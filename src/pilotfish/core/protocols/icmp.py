"""ICMP: the errors and the pings of IPv4.

An error message quotes the packet that caused it, which pilotfish decodes as
the next layer. Wireshark nests it inside the ICMP layer instead; the fields
are the same either way.

Reference: RFC 792.
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
from pilotfish.core.protocols.checksum import ChecksumStatus, verify
from pilotfish.core.protocols.ip import IP_PROTO, IP_VERSION, PROTO_ICMP

ECHO_REPLY = 0
DESTINATION_UNREACHABLE = 3
SOURCE_QUENCH = 4
REDIRECT = 5
ECHO_REQUEST = 8
TIME_EXCEEDED = 11
PARAMETER_PROBLEM = 12

QUOTING_TYPES = frozenset(
    {DESTINATION_UNREACHABLE, SOURCE_QUENCH, REDIRECT, TIME_EXCEEDED, PARAMETER_PROBLEM}
)
"""The messages that carry the start of the packet that caused them."""

_TYPES = {
    ECHO_REPLY: "Echo (ping) reply",
    DESTINATION_UNREACHABLE: "Destination unreachable",
    SOURCE_QUENCH: "Source quench",
    REDIRECT: "Redirect",
    ECHO_REQUEST: "Echo (ping) request",
    9: "Router advertisement",
    10: "Router solicitation",
    TIME_EXCEEDED: "Time-to-live exceeded",
    PARAMETER_PROBLEM: "Parameter problem",
    13: "Timestamp request",
    14: "Timestamp reply",
}

_UNREACHABLE_CODES = {
    0: "Network unreachable",
    1: "Host unreachable",
    2: "Protocol unreachable",
    3: "Port unreachable",
    4: "Fragmentation needed",
    5: "Source route failed",
    9: "Network administratively prohibited",
    10: "Host administratively prohibited",
    13: "Communication administratively filtered",
}

_TIME_EXCEEDED_CODES = {
    0: "Time to live exceeded in transit",
    1: "Fragment reassembly time exceeded",
}


@register(IP_PROTO, PROTO_ICMP)
class Icmp(Dissector):
    name = "icmp"
    title = "Internet Control Message Protocol"
    fields = (
        Field("icmp.type", FieldType.UINT, "Type"),
        Field("icmp.code", FieldType.UINT, "Code"),
        Field("icmp.checksum", FieldType.UINT, "Checksum", hex=True),
        Field("icmp.checksum.status", FieldType.UINT, "Checksum status"),
        Field("icmp.ident", FieldType.UINT, "Identifier", hex=True),
        Field("icmp.seq", FieldType.UINT, "Sequence Number"),
        Field("icmp.data", FieldType.BYTES, "Data"),
        Field("icmp.unused", FieldType.BYTES, "Unused"),
        Field("icmp.redir_gw", FieldType.IPV4, "Gateway Address"),
    )

    def dissect(self, reader: Reader, context: Context) -> Handoff | None:
        message = reader.buffer.peek(reader.remaining)
        kind = reader.uint8("icmp.type")
        code = reader.uint8("icmp.code")
        reader.uint16("icmp.checksum")
        with reader.inside():
            status = ChecksumStatus.UNVERIFIED if context.truncated else verify(message)
            reader.add("icmp.checksum.status", int(status))
        reader.summarize(self.title)

        if kind in {ECHO_REQUEST, ECHO_REPLY}:
            identifier = reader.uint16("icmp.ident")
            sequence = reader.uint16("icmp.seq")
            context.describe(f"{_TYPES[kind]}  id=0x{identifier:04x}, seq={sequence}")
            if reader.remaining:
                reader.bytes("icmp.data", reader.remaining)
            return None

        if kind in QUOTING_TYPES:
            context.describe(_describe(kind, code))
            if kind == REDIRECT:
                reader.ipv4("icmp.redir_gw")
            else:
                reader.bytes("icmp.unused", 4)
            payload = reader.payload()
            # What follows is the start of the packet that caused the error,
            # which describes itself but not the packet it is quoted in.
            context.in_error = True
            return Handoff(IP_VERSION, 4, payload) if payload.remaining else None

        context.describe(_TYPES.get(kind, f"Type {kind}"))
        payload = reader.payload()
        return as_data(payload) if payload.remaining else None


def _describe(kind: int, code: int) -> str:
    """The Info column text, as Wireshark writes it: the type, then the code."""
    name = _TYPES.get(kind, f"Type {kind}")
    codes = {
        DESTINATION_UNREACHABLE: _UNREACHABLE_CODES,
        TIME_EXCEEDED: _TIME_EXCEEDED_CODES,
    }.get(kind, {})
    return f"{name} ({codes[code]})" if code in codes else name
