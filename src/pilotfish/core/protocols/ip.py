"""What IPv4 and IPv6 share: the table of what they carry, and raw IP links.

Both versions name what comes next with the same numbers, so they route
through one table: 1 is ICMP, 6 is TCP, 17 is UDP, 58 is ICMPv6. IPv6
extension headers take their numbers from the same list, which is why they
register there too.

Reference: the IANA protocol numbers registry.
"""

from pilotfish.core.dissect import (
    LINK_TYPE,
    Context,
    Dissector,
    Handoff,
    Reader,
    register,
)

IP_PROTO = "ip.proto"
"""The table keyed by protocol number, for what an IP packet carries."""

IP_VERSION = "ip.version"
"""The table keyed by 4 or 6, for a link that carries bare IP packets."""

PROTO_ICMP = 1
PROTO_TCP = 6
PROTO_UDP = 17
PROTO_ICMPV6 = 58

LINKTYPE_RAW = 101
LINKTYPE_IPV4 = 228
LINKTYPE_IPV6 = 229


@register(LINK_TYPE, LINKTYPE_RAW)
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
