"""The packet list that ``pilotfish read`` and ``pilotfish capture`` print."""

from typing import Literal, TextIO

from pilotfish.core.columns import addresses, protocol, summary
from pilotfish.core.dissect import ProtocolTree
from pilotfish.core.packet import Packet
from pilotfish.core.timestamps import format_epoch, format_utc

type TimeFormat = Literal["epoch", "utc"]

TIME_FORMATS: tuple[TimeFormat, ...] = ("epoch", "utc")

_TIME_WIDTH: dict[TimeFormat, int] = {"epoch": 20, "utc": 29}

_ADDRESS_WIDTH = 21
_PROTOCOL_WIDTH = 8


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
        source, destination = addresses(tree)
        self._out.write(
            f"{number:>7}  {time:<{self._width}}  {source:<{_ADDRESS_WIDTH}}  "
            f"{destination:<{_ADDRESS_WIDTH}}  "
            f"{protocol(tree):<{_PROTOCOL_WIDTH}}  {packet.original_length:>6}  "
            f"{summary(tree)}\n".rstrip(" ")
        )
