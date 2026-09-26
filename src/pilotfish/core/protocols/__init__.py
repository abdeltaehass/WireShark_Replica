"""The protocols pilotfish decodes.

Importing this package registers every dissector in it, which is how the
engine finds them: each module's ``@register`` decorators put it in the
tables that route by value. Anything that decodes packets imports this once.

The link and network layers are here now. Transport and application
protocols follow in the next phases.
"""

from pilotfish.core.protocols import (
    arp,
    ethernet,
    icmp,
    icmpv6,
    ip,
    ipv4,
    ipv6,
    loopback,
    tcp,
    udp,
)

__all__ = [
    "arp",
    "ethernet",
    "icmp",
    "icmpv6",
    "ip",
    "ipv4",
    "ipv6",
    "loopback",
    "tcp",
    "udp",
]
