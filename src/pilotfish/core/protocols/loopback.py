"""BSD loopback, the link type of lo0 and the utun tunnels on a Mac.

There is no header: four bytes hold the address family the packet was sent
with, in the byte order of the machine that captured it, and the IP packet
follows. Each BSD picked a different number for IPv6, so the family says
which system wrote the capture as well as which protocol follows.

Reference: the LINKTYPE_NULL entry of the tcpdump link-layer header types.
"""

from pilotfish.core.dissect import (
    LINK_TYPE,
    Context,
    Dissector,
    Field,
    FieldType,
    Handoff,
    Reader,
    register,
)

NULL_FAMILY = "null.family"
"""The table keyed by address family, for what the loopback header carries."""

LINKTYPE_NULL = 0
LINKTYPE_LOOP = 108
"""OpenBSD's version of the same link, which always writes big-endian."""

AF_INET = 2
AF_INET6_BSD = 24
"""NetBSD, OpenBSD and BSD/OS."""
AF_INET6_FREEBSD = 28
AF_INET6_DARWIN = 30
"""macOS, which is what a capture on lo0 or a utun holds."""

_FAMILIES = frozenset({AF_INET, AF_INET6_BSD, AF_INET6_FREEBSD, AF_INET6_DARWIN})


@register(LINK_TYPE, LINKTYPE_NULL, LINKTYPE_LOOP)
class Loopback(Dissector):
    name = "null"
    title = "Null/Loopback"
    fields = (Field("null.family", FieldType.UINT, "Family"),)

    def dissect(self, reader: Reader, context: Context) -> Handoff:
        offset = reader.buffer.offset
        raw = bytes(reader.buffer.read(4, "null.family"))
        family = int.from_bytes(raw, "little")
        if family not in _FAMILIES and int.from_bytes(raw, "big") in _FAMILIES:
            # Written on a machine of the other byte order, or on OpenBSD,
            # which writes this field big-endian whatever the machine is.
            family = int.from_bytes(raw, "big")
        reader.add("null.family", family, offset=offset, length=4)
        reader.summarize("Null/Loopback")
        return Handoff(NULL_FAMILY, family, reader.payload())
