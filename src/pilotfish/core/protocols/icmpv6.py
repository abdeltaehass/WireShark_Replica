"""ICMPv6, including the neighbour discovery a Mac runs all day.

IPv6 has no ARP: a host asks who holds an address with a Neighbor
Solicitation and is answered with a Neighbor Advertisement, both of them
ICMPv6 messages carrying options. Routers announce themselves the same way.

The checksum here covers a pseudo header of the IPv6 addresses as well as the
message, so a message delivered to the wrong address fails the check.

References: RFC 4443 for the messages, RFC 4861 for neighbour discovery.
"""

from pilotfish.core.dissect import (
    Context,
    Dissector,
    Field,
    FieldType,
    Handoff,
    Reader,
    as_data,
    register,
)
from pilotfish.core.protocols.checksum import ChecksumStatus, pseudo_header, verify
from pilotfish.core.protocols.ip import IP_PROTO, IP_VERSION, PROTO_ICMPV6

DESTINATION_UNREACHABLE = 1
PACKET_TOO_BIG = 2
TIME_EXCEEDED = 3
PARAMETER_PROBLEM = 4
ECHO_REQUEST = 128
ECHO_REPLY = 129
ROUTER_SOLICITATION = 133
ROUTER_ADVERTISEMENT = 134
NEIGHBOR_SOLICITATION = 135
NEIGHBOR_ADVERTISEMENT = 136
REDIRECT = 137

QUOTING_TYPES = frozenset(
    {DESTINATION_UNREACHABLE, PACKET_TOO_BIG, TIME_EXCEEDED, PARAMETER_PROBLEM}
)

OPTION_SOURCE_LINK_ADDRESS = 1
OPTION_TARGET_LINK_ADDRESS = 2
OPTION_PREFIX_INFORMATION = 3
OPTION_MTU = 5

_TYPES = {
    DESTINATION_UNREACHABLE: "Destination Unreachable",
    PACKET_TOO_BIG: "Packet Too Big",
    TIME_EXCEEDED: "Time Exceeded",
    PARAMETER_PROBLEM: "Parameter Problem",
    ECHO_REQUEST: "Echo (ping) request",
    ECHO_REPLY: "Echo (ping) reply",
    ROUTER_SOLICITATION: "Router Solicitation",
    ROUTER_ADVERTISEMENT: "Router Advertisement",
    NEIGHBOR_SOLICITATION: "Neighbor Solicitation",
    NEIGHBOR_ADVERTISEMENT: "Neighbor Advertisement",
    REDIRECT: "Redirect",
}

_UNREACHABLE_CODES = {
    0: "no route to destination",
    1: "Administratively prohibited",
    2: "Beyond scope of source address",
    3: "Address unreachable",
    4: "Port unreachable",
}


@register(IP_PROTO, PROTO_ICMPV6)
class Icmpv6(Dissector):
    name = "icmpv6"
    title = "Internet Control Message Protocol v6"
    fields = (
        Field("icmpv6.type", FieldType.UINT, "Type"),
        Field("icmpv6.code", FieldType.UINT, "Code"),
        Field("icmpv6.checksum", FieldType.UINT, "Checksum", hex=True),
        Field("icmpv6.checksum.status", FieldType.UINT, "Checksum status"),
        Field("icmpv6.reserved", FieldType.BYTES, "Reserved"),
        Field("icmpv6.echo.identifier", FieldType.UINT, "Identifier", hex=True),
        Field("icmpv6.echo.sequence_number", FieldType.UINT, "Sequence"),
        Field("icmpv6.nd.ns.target_address", FieldType.IPV6, "Target Address"),
        Field("icmpv6.nd.na.flag", FieldType.UINT, "Flags", hex=True),
        Field("icmpv6.nd.na.flag.r", FieldType.BOOL, "Router"),
        Field("icmpv6.nd.na.flag.s", FieldType.BOOL, "Solicited"),
        Field("icmpv6.nd.na.flag.o", FieldType.BOOL, "Override"),
        Field("icmpv6.nd.na.flag.rsv", FieldType.UINT, "Reserved"),
        Field("icmpv6.nd.na.target_address", FieldType.IPV6, "Target Address"),
        Field("icmpv6.nd.ra.cur_hop_limit", FieldType.UINT, "Cur hop limit"),
        Field("icmpv6.nd.ra.flag", FieldType.UINT, "Flags", hex=True),
        Field("icmpv6.nd.ra.flag.m", FieldType.BOOL, "Managed address configuration"),
        Field("icmpv6.nd.ra.flag.o", FieldType.BOOL, "Other configuration"),
        Field("icmpv6.nd.ra.router_lifetime", FieldType.UINT, "Router lifetime (s)"),
        Field("icmpv6.nd.ra.reachable_time", FieldType.UINT, "Reachable time (ms)"),
        Field("icmpv6.nd.ra.retrans_timer", FieldType.UINT, "Retrans timer (ms)"),
        Field("icmpv6.opt.type", FieldType.UINT, "Type"),
        Field("icmpv6.opt.length", FieldType.UINT, "Length"),
        Field("icmpv6.opt.linkaddr", FieldType.ETHERNET, "Link-layer address"),
        Field("icmpv6.opt.src_linkaddr", FieldType.ETHERNET, "Source Link-layer address"),
        Field("icmpv6.opt.target_linkaddr", FieldType.ETHERNET, "Target Link-layer address"),
        Field("icmpv6.opt.mtu", FieldType.UINT, "MTU"),
        Field("icmpv6.opt.prefix.length", FieldType.UINT, "Prefix Length"),
        Field("icmpv6.opt.prefix.valid_lifetime", FieldType.UINT, "Valid Lifetime"),
        Field("icmpv6.opt.prefix.preferred_lifetime", FieldType.UINT, "Preferred Lifetime"),
        Field("icmpv6.opt.prefix", FieldType.IPV6, "Prefix"),
    )

    def dissect(self, reader: Reader, context: Context) -> Handoff | None:
        message = reader.buffer.peek(reader.remaining)
        kind = reader.uint8("icmpv6.type")
        code = reader.uint8("icmpv6.code")
        reader.uint16("icmpv6.checksum")
        with reader.inside():
            reader.add("icmpv6.checksum.status", int(self._status(context, message)))
        reader.summarize(self.title)
        context.describe(_describe(kind, code))

        if kind in {ECHO_REQUEST, ECHO_REPLY}:
            identifier = reader.uint16("icmpv6.echo.identifier")
            sequence = reader.uint16("icmpv6.echo.sequence_number")
            context.describe(f"{_TYPES[kind]} id=0x{identifier:04x}, seq={sequence}")
            payload = reader.payload()
            return as_data(payload) if payload.remaining else None

        if kind == NEIGHBOR_SOLICITATION:
            reader.bytes("icmpv6.reserved", 4)
            target = reader.ipv6("icmpv6.nd.ns.target_address")
            context.describe(f"Neighbor Solicitation for {target}")
            self._options(reader, context)
            return None

        if kind == NEIGHBOR_ADVERTISEMENT:
            flags = self._advertisement_flags(reader)
            target = reader.ipv6("icmpv6.nd.na.target_address")
            context.describe(f"Neighbor Advertisement {target}{flags}")
            self._options(reader, context)
            return None

        if kind == ROUTER_SOLICITATION:
            reader.bytes("icmpv6.reserved", 4)
            self._options(reader, context)
            return None

        if kind == ROUTER_ADVERTISEMENT:
            reader.uint8("icmpv6.nd.ra.cur_hop_limit")
            offset = reader.buffer.offset
            configuration = reader.buffer.uint(1, name="icmpv6.nd.ra.flag")
            reader.add("icmpv6.nd.ra.flag", configuration, offset=offset, length=1)
            with reader.inside():
                reader.add("icmpv6.nd.ra.flag.m", bool(configuration & 0x80))
                reader.add("icmpv6.nd.ra.flag.o", bool(configuration & 0x40))
            reader.uint16("icmpv6.nd.ra.router_lifetime")
            reader.uint32("icmpv6.nd.ra.reachable_time")
            reader.uint32("icmpv6.nd.ra.retrans_timer")
            self._options(reader, context)
            return None

        if kind in QUOTING_TYPES:
            reader.bytes("icmpv6.reserved", 4)
            payload = reader.payload()
            # The start of the packet that caused the error, which describes
            # itself but not the packet it is quoted in.
            context.in_error = True
            return Handoff(IP_VERSION, 6, payload) if payload.remaining else None

        payload = reader.payload()
        return as_data(payload) if payload.remaining else None

    @staticmethod
    def _status(context: Context, message: bytes) -> ChecksumStatus:
        if context.truncated or context.in_error:
            return ChecksumStatus.UNVERIFIED
        if context.source is None or context.destination is None:
            return ChecksumStatus.UNVERIFIED
        pseudo = pseudo_header(context.source, context.destination, PROTO_ICMPV6, len(message))
        return verify(pseudo, message)

    @staticmethod
    def _advertisement_flags(reader: Reader) -> str:
        """The router, solicited and override flags, and how to name them."""
        offset = reader.buffer.offset
        flags = reader.buffer.uint(4, name="icmpv6.nd.na.flag")
        reader.add("icmpv6.nd.na.flag", flags, offset=offset, length=4)
        with reader.inside():
            reader.add("icmpv6.nd.na.flag.r", bool(flags & 0x80000000))
            reader.add("icmpv6.nd.na.flag.s", bool(flags & 0x40000000))
            reader.add("icmpv6.nd.na.flag.o", bool(flags & 0x20000000))
            reader.add("icmpv6.nd.na.flag.rsv", flags & 0x1FFFFFFF)
        named = [
            name
            for bit, name in ((0x80000000, "rtr"), (0x40000000, "sol"), (0x20000000, "ovr"))
            if flags & bit
        ]
        return f" ({', '.join(named)})" if named else ""

    def _options(self, reader: Reader, context: Context) -> None:
        """The options a neighbour discovery message ends with."""
        while reader.remaining >= 2:
            start = reader.buffer.offset
            kind = reader.uint8("icmpv6.opt.type")
            # The rest of the option hangs under its type, as Wireshark's does.
            with reader.inside():
                length = reader.uint8("icmpv6.opt.length") * 8
                if length == 0:
                    return  # a length of zero would never finish
                end = start + length
                if kind in {OPTION_SOURCE_LINK_ADDRESS, OPTION_TARGET_LINK_ADDRESS}:
                    address = reader.mac("icmpv6.opt.linkaddr")
                    named = (
                        "icmpv6.opt.src_linkaddr"
                        if kind == OPTION_SOURCE_LINK_ADDRESS
                        else "icmpv6.opt.target_linkaddr"
                    )
                    reader.add(named, address, offset=start + 2, length=6)
                    joiner = (
                        "is at" if context.info.startswith("Neighbor Advertisement") else "from"
                    )
                    context.describe(f"{context.info} {joiner} {address}")
                elif kind == OPTION_MTU:
                    reader.skip(2, "icmpv6.opt.reserved")
                    reader.uint32("icmpv6.opt.mtu")
                elif kind == OPTION_PREFIX_INFORMATION:
                    reader.uint8("icmpv6.opt.prefix.length")
                    reader.skip(1, "icmpv6.opt.prefix.flag")
                    reader.uint32("icmpv6.opt.prefix.valid_lifetime")
                    reader.uint32("icmpv6.opt.prefix.preferred_lifetime")
                    reader.skip(4, "icmpv6.opt.reserved")
                    reader.ipv6("icmpv6.opt.prefix")
                reader.skip(max(end - reader.buffer.offset, 0), "icmpv6.opt")


def _describe(kind: int, code: int) -> str:
    name = _TYPES.get(kind, f"Type {kind}")
    if kind == DESTINATION_UNREACHABLE and code in _UNREACHABLE_CODES:
        return f"{name} ({_UNREACHABLE_CODES[code]})"
    return name
