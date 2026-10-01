"""What IPv4 and IPv6 share: the table of what they carry, and raw IP links.

Both versions name what comes next with the same numbers, so they route
through one table: 1 is ICMP, 6 is TCP, 17 is UDP, 58 is ICMPv6. IPv6
extension headers take their numbers from the same list, which is why they
register there too.

Reference: the IANA protocol numbers registry.
"""

from collections.abc import Hashable

from pilotfish.core.dissect import (
    LINK_TYPE,
    Buffer,
    Context,
    Dissector,
    Handoff,
    MalformedError,
    Reader,
    register,
)
from pilotfish.core.packet import Packet
from pilotfish.core.reassembly import Fragments, Reassembled
from pilotfish.core.reassembly.fragments import MAX_DATAGRAM

IP_PROTO = "ip.proto"
"""The table keyed by protocol number, for what an IP packet carries."""

IP_VERSION = "ip.version"
"""The table keyed by 4 or 6, for a link that carries bare IP packets."""

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMPV6 = 58

LINKTYPE_RAW = 101
LINKTYPE_RAW_BSD = 12
"""What BSD numbered a raw IP link, which files captured on a Mac still carry.
libpcap writes 101 now, but tcpdump's registry keeps both."""
LINKTYPE_RAW_OPENBSD = 14
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229

FRAGMENTS = "ip.fragments"
"""Where a capture keeps the datagrams still waiting for fragments."""


@register(LINK_TYPE, LINKTYPE_RAW, LINKTYPE_RAW_BSD, LINKTYPE_RAW_OPENBSD)
class Raw(Dissector):
    """A link that carries a bare IP packet, with no header of its own.

    Tunnels are captured this way. Which version follows is in the first
    nibble of the packet itself.
    """

    name = "raw"
    title = "Raw packet data"

    def dissect(self, reader: Reader, context: Context) -> Handoff:
        version = reader.buffer.peek(1, "ip.version")[0] >> 4
        return Handoff(IP_VERSION, version, reader.payload())


def cut_short(payload: Buffer, declared: int, packet: Packet) -> bool:
    """Whether the capture holds less of a payload than the header says.

    A header claiming more than the frame is long is taken at the frame's
    word, as Wireshark takes it: the bytes that are there are all there ever
    were, so a checksum over them can still be checked. It is a snapshot
    length cutting a frame short that leaves bytes nobody can see.
    """
    return payload.remaining < min(declared, packet.original_length - payload.offset)


def reassemble(
    context: Context, payload: Buffer, key: Hashable, offset: int, more: bool
) -> Reassembled | None:
    """Add a fragment to its datagram, and return the datagram once complete.

    A fragment quoted inside an error message is not one of the capture's
    own, and one the capture cut short is missing bytes the datagram needs,
    so neither is counted.
    """
    if context.in_error or context.truncated:
        return None
    if offset + payload.remaining > MAX_DATAGRAM:
        # The trick behind the "ping of death": fragments that are each
        # legal, and add up to more than any datagram can be.
        raise MalformedError(
            f"a fragment reaching byte {offset + payload.remaining} "
            f"is past the {MAX_DATAGRAM} a datagram can hold"
        )
    fragments = context.session.store(FRAGMENTS, Fragments)
    whole = fragments.add(
        key,
        offset,
        payload.peek(payload.remaining),
        more=more,
        frame=context.number,
        time=context.packet.timestamp_ns,
    )
    if whole is not None:
        # The datagram is all here, whatever the last frame's own length says.
        context.truncated = False
    return whole
