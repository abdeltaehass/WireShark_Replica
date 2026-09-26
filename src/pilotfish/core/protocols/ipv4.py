"""IPv4: addresses, fragmentation, and a checksum over the header.

Reference: RFC 791.
"""

from pilotfish.core.dissect import (
    LINK_TYPE,
    Context,
    Dissector,
    Field,
    FieldType,
    Handoff,
    MalformedError,
    Reader,
    as_data,
    register,
)
from pilotfish.core.protocols.checksum import ChecksumStatus, verify
from pilotfish.core.protocols.ethernet import ETHERTYPE, ETHERTYPE_IPV4
from pilotfish.core.protocols.ip import IP_PROTO, IP_VERSION, LINKTYPE_IPV4
from pilotfish.core.protocols.loopback import AF_INET, NULL_FAMILY

HEADER_SIZE = 20
"""The header without options, which the header length field counts in words."""

VERSION = 4

FLAG_MORE_FRAGMENTS = 0x1
FLAG_DONT_FRAGMENT = 0x2

OPTION_END = 0
OPTION_NOP = 1


@register(ETHERTYPE, ETHERTYPE_IPV4)
@register(NULL_FAMILY, AF_INET)
@register(IP_VERSION, VERSION)
@register(LINK_TYPE, LINKTYPE_IPV4)
class IPv4(Dissector):
    name = "ip"
    title = "Internet Protocol Version 4"
    fields = (
        Field("ip.version", FieldType.UINT, "Version"),
        Field("ip.hdr_len", FieldType.UINT, "Header Length"),
        Field("ip.dsfield", FieldType.UINT, "Differentiated Services Field", hex=True),
        Field("ip.dsfield.dscp", FieldType.UINT, "Differentiated Services Codepoint"),
        Field("ip.dsfield.ecn", FieldType.UINT, "Explicit Congestion Notification"),
        Field("ip.len", FieldType.UINT, "Total Length"),
        Field("ip.id", FieldType.UINT, "Identification", hex=True),
        Field("ip.flags", FieldType.UINT, "Flags", hex=True),
        Field("ip.flags.rb", FieldType.BOOL, "Reserved bit"),
        Field("ip.flags.df", FieldType.BOOL, "Don't fragment"),
        Field("ip.flags.mf", FieldType.BOOL, "More fragments"),
        Field("ip.frag_offset", FieldType.UINT, "Fragment Offset"),
        Field("ip.ttl", FieldType.UINT, "Time to Live"),
        Field("ip.proto", FieldType.UINT, "Protocol"),
        Field("ip.checksum", FieldType.UINT, "Header Checksum", hex=True),
        Field("ip.checksum.status", FieldType.UINT, "Header checksum status"),
        Field("ip.src", FieldType.IPV4, "Source Address"),
        Field("ip.dst", FieldType.IPV4, "Destination Address"),
        Field("ip.opt.type", FieldType.UINT, "Type"),
        Field("ip.opt.type.copy", FieldType.BOOL, "Copy on fragmentation"),
        Field("ip.opt.type.class", FieldType.UINT, "Class"),
        Field("ip.opt.type.number", FieldType.UINT, "Number"),
        Field("ip.opt.len", FieldType.UINT, "Length"),
    )

    def dissect(self, reader: Reader, context: Context) -> Handoff | None:
        start = reader.buffer.offset
        first = reader.buffer.peek(1, "ip.version")[0]
        header_length = (first & 0xF) * 4
        if header_length < HEADER_SIZE:
            raise MalformedError(f"a header of {header_length} bytes is shorter than IPv4's 20")
        # The checksum covers the header, so it is taken before reading it
        # apart. A header cut short by a snapshot length can't be checked.
        status = (
            verify(reader.buffer.peek(header_length))
            if reader.buffer.remaining >= header_length
            else ChecksumStatus.UNVERIFIED
        )

        reader.buffer.skip(1)
        reader.add("ip.version", first >> 4, offset=start, length=1)
        reader.add("ip.hdr_len", header_length, offset=start, length=1)
        services = reader.uint8("ip.dsfield")
        with reader.inside():
            reader.add("ip.dsfield.dscp", services >> 2)
            reader.add("ip.dsfield.ecn", services & 0x3)
        total_length = reader.uint16("ip.len")
        identifier = reader.uint16("ip.id")

        offset = reader.buffer.offset
        fragmentation = reader.buffer.uint(2, name="ip.flags")
        flags = fragmentation >> 13
        fragment_offset = fragmentation & 0x1FFF
        reader.add("ip.flags", flags, offset=offset, length=2)
        with reader.inside():
            reader.add("ip.flags.rb", bool(flags & 0x4))
            reader.add("ip.flags.df", bool(flags & FLAG_DONT_FRAGMENT))
            reader.add("ip.flags.mf", bool(flags & FLAG_MORE_FRAGMENTS))
        # Wireshark reports the field as it stands, in eight-byte units.
        reader.add("ip.frag_offset", fragment_offset, offset=offset, length=2)

        reader.uint8("ip.ttl")
        protocol = reader.uint8("ip.proto")
        reader.uint16("ip.checksum")
        with reader.inside():
            reader.add("ip.checksum.status", int(status))
        source = reader.ipv4("ip.src")
        destination = reader.ipv4("ip.dst")
        if header_length > HEADER_SIZE:
            self._options(reader, header_length - HEADER_SIZE)

        context.source = source
        context.destination = destination
        context.describe(f"{source} → {destination}")
        reader.summarize(f"Internet Protocol Version 4, Src: {source}, Dst: {destination}")
        declared = max(total_length - header_length, 0)
        payload = reader.payload(declared)
        context.truncated = payload.remaining < declared
        if fragment_offset or flags & FLAG_MORE_FRAGMENTS:
            # Only the first fragment starts with the header of what follows,
            # and even that is only half a message. Reassembly comes later.
            context.describe(
                f"Fragmented IP protocol (proto={protocol}, "
                f"off={fragment_offset * 8}, ID={identifier:04x})"
            )
            return as_data(payload) if payload.remaining else None
        return Handoff(IP_PROTO, protocol, payload)

    def _options(self, reader: Reader, count: int) -> None:
        """The options after the fixed header, up to ``count`` bytes of them."""
        end = reader.buffer.offset + count
        while reader.buffer.offset < end:
            offset = reader.buffer.offset
            kind = reader.buffer.uint(1, name="ip.opt.type")
            reader.add("ip.opt.type", kind, offset=offset, length=1)
            with reader.inside():
                reader.add("ip.opt.type.copy", bool(kind & 0x80))
                reader.add("ip.opt.type.class", (kind >> 5) & 0x3)
                reader.add("ip.opt.type.number", kind & 0x1F)
            if kind == OPTION_END:
                break  # the rest of the header is padding
            if kind == OPTION_NOP:
                continue
            length = reader.uint8("ip.opt.len")
            if length < 2:
                raise MalformedError(f"option {kind} claims a length of {length}")
            reader.skip(min(length - 2, end - reader.buffer.offset), "ip.opt")
