"""The packet list that ``pilotfish read`` and ``pilotfish capture`` print."""

from typing import Literal, TextIO

from pilotfish.core.linktypes import link_type_name
from pilotfish.core.packet import Packet
from pilotfish.core.timestamps import format_epoch, format_utc

type TimeFormat = Literal["epoch", "utc"]

TIME_FORMATS: tuple[TimeFormat, ...] = ("epoch", "utc")

_TIME_WIDTH: dict[TimeFormat, int] = {"epoch": 20, "utc": 29}


class PacketTable:
    """A header line, then one line per packet: number, timestamp, lengths and link type."""

    def __init__(self, out: TextIO, time_format: TimeFormat) -> None:
        self._out = out
        self._format_time = format_utc if time_format == "utc" else format_epoch
        self._width = _TIME_WIDTH[time_format]

    def write_header(self) -> None:
        self._out.write(
            f"{'No.':>7}  {'Time':<{self._width}}  {'Length':>7}  {'Captured':>8}  Link type\n"
        )

    def write_row(self, number: int, packet: Packet) -> None:
        ns = packet.timestamp_ns
        time = "-" if ns is None else self._format_time(ns)
        self._out.write(
            f"{number:>7}  {time:<{self._width}}  {packet.original_length:>7}  "
            f"{packet.captured_length:>8}  {link_type_name(packet.link_type)}\n"
        )
