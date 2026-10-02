"""IPv6, and the chain of extension headers that can follow its fixed header.

The fixed header is always forty bytes. Anything optional goes in extension
headers, each naming what comes after it with the same numbers IPv4 uses for
its protocol field, which is why they register in the same table.

References: RFC 8200, and RFC 2460 for the routing header.
"""

from pilotfish.core.dissect import (
    LINK_TYPE,
    Buffer,
    Context,
    Dissector,
    Field,
    FieldType,
    Handoff,
    Reader,
    Source,
    as_data,
    register,
)
from pilotfish.core.protocols.ethernet import ETHERTYPE, ETHERTYPE_IPV6
from pilotfish.core.protocols.ip import (
    IP_PROTO,
    IP_VERSION,
    LINKTYPE_IPV6,
    cut_short,
    reassemble,
)
from pilotfish.core.protocols.loopback import (
    AF_INET6_BSD,
    AF_INET6_DARWIN,
    AF_INET6_FREEBSD,
    NULL_FAMILY,
)

HEADER_SIZE = 40
VERSION = 6

PROTO_HOPOPTS = 0
PROTO_ROUTING = 43
PROTO_FRAGMENT = 44
PROTO_NO_NEXT_HEADER = 59
PROTO_DSTOPTS = 60

OPTION_PAD1 = 0
ROUTING_SOURCE_ROUTE = 0
"""The deprecated routing header that lists addresses to visit."""


def _option_fields() -> tuple[Field, ...]:
    """The options inside a hop-by-hop or destination options header."""
    return (
        Field("ipv6.opt.type", FieldType.UINT, "Type", hex=True),
        Field("ipv6.opt.type.action", FieldType.UINT, "Action"),
        Field("ipv6.opt.type.change", FieldType.BOOL, "May change"),
        Field("ipv6.opt.type.rest", FieldType.UINT, "Low-order bits", hex=True),
        Field("ipv6.opt.length", FieldType.UINT, "Length"),
    )


def _chain_fields(name: str) -> tuple[Field, ...]:
    """The fields every extension header starts with."""
    return (
        Field(f"{name}.nxt", FieldType.UINT, "Next Header"),
        Field(f"{name}.len", FieldType.UINT, "Length"),
        Field(f"{name}.len_oct", FieldType.UINT, "Length (octets)"),
    )


@register(ETHERTYPE, ETHERTYPE_IPV6)
@register(NULL_FAMILY, AF_INET6_BSD, AF_INET6_FREEBSD, AF_INET6_DARWIN)
@register(IP_VERSION, VERSION)
@register(LINK_TYPE, LINKTYPE_IPV6)
class IPv6(Dissector):
    name = "ipv6"
    title = "Internet Protocol Version 6"
    fields = (
        Field("ipv6.version", FieldType.UINT, "Version"),
        Field("ipv6.tclass", FieldType.UINT, "Traffic Class", hex=True, digits=2),
        Field("ipv6.tclass.dscp", FieldType.UINT, "Differentiated Services Codepoint"),
        Field("ipv6.tclass.ecn", FieldType.UINT, "Explicit Congestion Notification"),
        Field("ipv6.flow", FieldType.UINT, "Flow Label", hex=True, digits=5),
        Field("ipv6.plen", FieldType.UINT, "Payload Length"),
        Field("ipv6.nxt", FieldType.UINT, "Next Header"),
        Field("ipv6.hlim", FieldType.UINT, "Hop Limit"),
        Field("ipv6.src", FieldType.IPV6, "Source Address"),
        Field("ipv6.dst", FieldType.IPV6, "Destination Address"),
        Field(
            "ipv6.addr",
            FieldType.IPV6,
            "Source or Destination Address",
            either=("ipv6.src", "ipv6.dst"),
        ),
    )

    def dissect(self, reader: Reader, context: Context) -> Handoff | None:
        offset = reader.buffer.offset
        first = reader.buffer.uint(4, name="ipv6.version")
        traffic_class = (first >> 20) & 0xFF
        reader.add("ipv6.version", first >> 28, offset=offset, length=1)
        reader.add("ipv6.tclass", traffic_class, offset=offset, length=2)
        with reader.inside():
            reader.add("ipv6.tclass.dscp", traffic_class >> 2)
            reader.add("ipv6.tclass.ecn", traffic_class & 0x3)
        reader.add("ipv6.flow", first & 0xFFFFF, offset=offset + 1, length=3)

        payload_length = reader.uint16("ipv6.plen")
        next_header = reader.uint8("ipv6.nxt")
        reader.uint8("ipv6.hlim")
        source = reader.ipv6("ipv6.src")
        destination = reader.ipv6("ipv6.dst")

        context.source = source
        context.destination = destination
        context.describe(f"{source} → {destination}")
        reader.summarize(f"Internet Protocol Version 6, Src: {source}, Dst: {destination}")
        payload = reader.payload(payload_length)
        context.truncated = cut_short(payload, payload_length, context.packet)
        if next_header == PROTO_NO_NEXT_HEADER or not payload.remaining:
            return None
        return Handoff(IP_PROTO, next_header, payload)


class OptionsHeader(Dissector):
    """A hop-by-hop or destination options header: a chain link of options."""

    def dissect(self, reader: Reader, context: Context) -> Handoff | None:
        start = reader.buffer.offset
        next_header = reader.uint8(f"{self.name}.nxt")
        offset = reader.buffer.offset
        length = reader.buffer.uint(1, name=f"{self.name}.len")
        octets = (length + 1) * 8
        reader.add(f"{self.name}.len", length, offset=offset, length=1)
        reader.add(f"{self.name}.len_oct", octets, offset=offset, length=1)
        read_options(reader, start + octets)
        reader.summarize(self.title)
        payload = reader.payload()
        if next_header == PROTO_NO_NEXT_HEADER or not payload.remaining:
            return None
        return Handoff(IP_PROTO, next_header, payload)


@register(IP_PROTO, PROTO_HOPOPTS)
class HopByHop(OptionsHeader):
    name = "ipv6.hopopts"
    title = "IPv6 Hop-by-Hop Option"
    fields = (*_chain_fields("ipv6.hopopts"), *_option_fields())


@register(IP_PROTO, PROTO_DSTOPTS)
class DestinationOptions(OptionsHeader):
    name = "ipv6.dstopts"
    title = "IPv6 Destination Option"
    fields = (*_chain_fields("ipv6.dstopts"), *_option_fields())


@register(IP_PROTO, PROTO_ROUTING)
class Routing(Dissector):
    """The addresses a packet was told to travel through."""

    name = "ipv6.routing"
    title = "Routing Header for IPv6"
    fields = (
        *_chain_fields("ipv6.routing"),
        Field("ipv6.routing.type", FieldType.UINT, "Type"),
        Field("ipv6.routing.segleft", FieldType.UINT, "Segments Left"),
        Field("ipv6.routing.src.addr", FieldType.IPV6, "Address"),
    )

    def dissect(self, reader: Reader, context: Context) -> Handoff | None:
        start = reader.buffer.offset
        next_header = reader.uint8("ipv6.routing.nxt")
        offset = reader.buffer.offset
        length = reader.buffer.uint(1, name="ipv6.routing.len")
        octets = (length + 1) * 8
        reader.add("ipv6.routing.len", length, offset=offset, length=1)
        reader.add("ipv6.routing.len_oct", octets, offset=offset, length=1)
        kind = reader.uint8("ipv6.routing.type")
        reader.uint8("ipv6.routing.segleft")
        end = start + octets
        if kind == ROUTING_SOURCE_ROUTE:
            reader.skip(4, "ipv6.routing.src.reserved")
            while reader.buffer.offset + 16 <= end:
                # What follows is checksummed against the last of these
                # rather than the address in the fixed header.
                context.destination = reader.ipv6("ipv6.routing.src.addr")
        reader.skip(max(end - reader.buffer.offset, 0), "ipv6.routing")
        reader.summarize(self.title)
        payload = reader.payload()
        if next_header == PROTO_NO_NEXT_HEADER or not payload.remaining:
            return None
        return Handoff(IP_PROTO, next_header, payload)


@register(IP_PROTO, PROTO_FRAGMENT)
class Fragment(Dissector):
    """One piece of a datagram that was too big for the path it took."""

    name = "ipv6.fraghdr"
    title = "Fragment Header for IPv6"
    fields = (
        Field("ipv6.fraghdr.nxt", FieldType.UINT, "Next header"),
        Field("ipv6.fraghdr.reserved_octet", FieldType.UINT, "Reserved octet"),
        Field("ipv6.fraghdr.offset", FieldType.UINT, "Offset"),
        Field("ipv6.fraghdr.reserved_bits", FieldType.UINT, "Reserved bits"),
        Field("ipv6.fraghdr.more", FieldType.BOOL, "More Fragments"),
        Field("ipv6.fraghdr.ident", FieldType.UINT, "Identification", hex=True),
        Field("ipv6.fragment", FieldType.UINT, "IPv6 Fragment"),
        Field("ipv6.fragment.count", FieldType.UINT, "Fragment count"),
        Field("ipv6.fragment.overlap", FieldType.BOOL, "Fragment overlap"),
        Field(
            "ipv6.fragment.overlap.conflict",
            FieldType.BOOL,
            "Conflicting data in fragment overlap",
        ),
        Field("ipv6.reassembled.length", FieldType.UINT, "Reassembled IPv6 length"),
        Field("ipv6.reassembled.data", FieldType.BYTES, "Reassembled IPv6 data"),
    )

    def dissect(self, reader: Reader, context: Context) -> Handoff | None:
        next_header = reader.uint8("ipv6.fraghdr.nxt")
        reader.uint8("ipv6.fraghdr.reserved_octet")
        offset = reader.buffer.offset
        word = reader.buffer.uint(2, name="ipv6.fraghdr.offset")
        reader.add("ipv6.fraghdr.offset", word >> 3, offset=offset, length=2)
        reader.add("ipv6.fraghdr.reserved_bits", (word >> 1) & 0x3, offset=offset, length=2)
        reader.add("ipv6.fraghdr.more", bool(word & 1), offset=offset, length=2)
        identifier = reader.uint32("ipv6.fraghdr.ident")
        reader.summarize(self.title)
        payload = reader.payload()
        fragment_offset, more = (word >> 3) * 8, bool(word & 1)
        if not (fragment_offset or more):
            # A fragment header on a datagram that was never cut up.
            return Handoff(IP_PROTO, next_header, payload) if payload.remaining else None
        # Only the pieces after this header are put together. The headers
        # before it are repeated in every fragment.
        key = (context.source, context.destination, identifier)
        whole = reassemble(context, payload, key, fragment_offset, more)
        if whole is None:
            context.describe(
                f"IPv6 fragment (off={fragment_offset} more={'y' if more else 'n'} "
                f"ident=0x{identifier:08x} nxt={next_header})"
            )
            return as_data(payload) if payload.remaining else None
        for frame in whole.frames:
            reader.add("ipv6.fragment", frame)
        if whole.overlap:
            reader.add("ipv6.fragment.overlap", True)
        if whole.conflict:
            reader.add("ipv6.fragment.overlap.conflict", True)
        reader.add("ipv6.fragment.count", len(whole.frames))
        reader.add("ipv6.reassembled.length", len(whole.data))
        reader.add("ipv6.reassembled.data", whole.data)
        if not whole.data:
            return None
        return Handoff(
            IP_PROTO, next_header, Buffer(whole.data, 0, Source("Reassembled IPv6", whole.data))
        )


def read_options(reader: Reader, end: int) -> None:
    """The type-length-value options an extension header carries."""
    while reader.buffer.offset < end:
        offset = reader.buffer.offset
        kind = reader.buffer.uint(1, name="ipv6.opt.type")
        reader.add("ipv6.opt.type", kind, offset=offset, length=1)
        with reader.inside():
            reader.add("ipv6.opt.type.action", kind >> 6)
            reader.add("ipv6.opt.type.change", bool(kind & 0x20))
            reader.add("ipv6.opt.type.rest", kind & 0x1F)
        if kind == OPTION_PAD1:
            continue  # one byte of padding, with no length of its own
        length = reader.uint8("ipv6.opt.length")
        reader.skip(min(length, max(end - reader.buffer.offset, 0)), "ipv6.opt")
