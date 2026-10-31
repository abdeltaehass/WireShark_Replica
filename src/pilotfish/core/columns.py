"""The packet list's columns, worked out from a packet's protocol tree.

Both front ends show the same list: the command line prints it, and the
desktop app shows it in a table. What goes in each column is decided here,
once, so the two can't drift apart.
"""

from pilotfish.core.dissect import ProtocolTree, Value

# Where the addresses in the packet list come from, innermost first: the
# network layer when there is one, and the link layer otherwise, which is
# what Wireshark shows for ARP.
SOURCES = ("ipv6.src", "ip.src", "eth.src")
DESTINATIONS = ("ipv6.dst", "ip.dst", "eth.dst")
_ADDRESSES = frozenset({*SOURCES, *DESTINATIONS})

# Protocols whose column name isn't just their name in capitals.
_ABBREVIATIONS = {"ip": "IPv4", "ipv6": "IPv6", "icmpv6": "ICMPv6"}


def address(tree: ProtocolTree, names: tuple[str, ...]) -> str:
    """The address to show for a packet, from the outermost layer that has one."""
    for name in names:
        value = tree.get(name)
        if value is not None:
            return str(value)
    return ""


def addresses(tree: ProtocolTree) -> tuple[str, str]:
    """The Source and Destination columns, found in one walk of the tree.

    The same as :func:`address` for each, which would walk the whole tree
    once for every name a packet doesn't have.
    """
    first: dict[str, Value | None] = {}
    for node in tree.walk():
        if node.name in _ADDRESSES:
            first.setdefault(node.name, node.value)
    return _pick(first, SOURCES), _pick(first, DESTINATIONS)


def _pick(first: dict[str, Value | None], names: tuple[str, ...]) -> str:
    for name in names:
        value = first.get(name)
        if value is not None:
            return str(value)
    return ""


def summary(tree: ProtocolTree) -> str:
    """The Info column: what the packet is, and whether it made sense."""
    if tree.error is None:
        return tree.info
    return f"{tree.info} [Malformed Packet]".strip()


def protocol(tree: ProtocolTree) -> str:
    """The innermost protocol decoded, as the column shows it.

    Bytes nothing claimed aren't a protocol, so the column names the last
    one that was decoded, as Wireshark's does.
    """
    if not tree.protocol:
        return "DATA" if "data" in tree.protocols else ""
    # An extension header is part of IPv6 rather than a protocol of its own.
    name = tree.protocol.split(".")[0]
    return _ABBREVIATIONS.get(name, name.upper())
