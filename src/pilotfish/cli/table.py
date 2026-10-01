"""The packet list that ``pilotfish read`` and ``pilotfish capture`` print."""

from typing import Literal, TextIO

from pilotfish.core.dissect import ProtocolTree
from pilotfish.core.packet import Packet
from pilotfish.core.timestamps import format_epoch, format_utc

type TimeFormat = Literal["epoch", "utc"]

TIME_FORMATS: tuple[TimeFormat, ...] = ("epoch", "utc")

_TIME_WIDTH: dict[TimeFormat, int] = {"epoch": 20, "utc": 29}

_ADDRESS_WIDTH = 21
_PROTOCOL_WIDTH = 8

# Where the addresses in the packet list come from, innermost first: the
# network layer when there is one, and the link layer otherwise, which is
# what Wireshark shows for ARP.
_SOURCES = ("ipv6.src", "ip.src", "eth.src")
_DESTINATIONS = ("ipv6.dst", "ip.dst", "eth.dst")

# Protocols whose column name isn't just their name in capitals.
_ABBREVIATIONS = {"ip": "IPv4", "ipv6": "IPv6", "icmpv6": "ICMPv6"}


class PacketTable:
    """One line per packet: when it arrived, who sent it, and what it was."""

    def __init__(self, out: TextIO, time_format: TimeFormat) -> None:
        self._out = out
        self._format_time = format_utc if time_format == "utc" else format_epoch
        self._width = _TIME_WIDTH[time_format]

    def write_header(self) -> None:
        self._out.write(
            f"{'No.':>7}  {'Time':<{self._width}}  {'Source':<{_ADDRESS_WIDTH}}  "
            f"{'Destination':<{_ADDRESS_WIDTH}}  {'Protocol':<{_PROTOCOL_WIDTH}}  "
            f"{'Length':>6}  Info\n"
        )

    def write_row(self, number: int, packet: Packet, tree: ProtocolTree) -> None:
        ns = packet.timestamp_ns
        time = "-" if ns is None else self._format_time(ns)
        self._out.write(
            f"{number:>7}  {time:<{self._width}}  {address(tree, _SOURCES):<{_ADDRESS_WIDTH}}  "
            f"{address(tree, _DESTINATIONS):<{_ADDRESS_WIDTH}}  "
            f"{protocol(tree):<{_PROTOCOL_WIDTH}}  {packet.original_length:>6}  "
            f"{summary(tree)}\n".rstrip(" ")
        )


def address(tree: ProtocolTree, names: tuple[str, ...]) -> str:
    """The address to show for a packet, from the outermost layer that has one."""
    for name in names:
        value = tree.get(name)
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
