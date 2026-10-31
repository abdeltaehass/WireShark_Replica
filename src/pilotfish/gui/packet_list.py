"""The packet list: one row per packet, decoded as it scrolls into view.

A table view asks its model only for the rows it is about to paint, so the
model is where decoding happens lazily. The number, time and length come
straight from the file. The other columns need the packet decoded, and the
packets before it, so a row that isn't decoded yet is painted blank and
decoding catches up a slice at a time between repaints, never blocking the
window for longer than :data:`SLICE_SECONDS`.
"""

import time
from typing import override

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QObject,
    QPersistentModelIndex,
    Qt,
    QTimer,
    Signal,
)

from pilotfish.core.decoder import Decoder, Summary
from pilotfish.core.packet import Interface, Packet
from pilotfish.core.timestamps import NS_PER_SECOND

COLUMNS = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
NUMBER, TIME, SOURCE, DESTINATION, PROTOCOL, LENGTH, INFO = range(len(COLUMNS))

SLICE_SECONDS = 0.015
"""How long to decode for between repaints, to keep scrolling smooth."""

_NO_PARENT = QModelIndex()
_DISPLAY = Qt.ItemDataRole.DisplayRole


class PacketListModel(QAbstractTableModel):
    """The rows of a :class:`Decoder`'s capture, in the packet list's columns."""

    progress = Signal(int, int)
    """How many packets are decoded, and how many the rows shown need."""

    def __init__(self, decoder: Decoder, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.decoder = decoder
        self._start = _first_time(decoder)
        self._wanted = -1
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._decode_some)

    @property
    def busy(self) -> bool:
        """Whether rows already shown are still waiting to be decoded."""
        return self.decoder.decoded <= self._wanted

    @override
    def rowCount(self, parent: QModelIndex | QPersistentModelIndex = _NO_PARENT) -> int:
        return 0 if parent.isValid() else len(self.decoder)

    @override
    def columnCount(self, parent: QModelIndex | QPersistentModelIndex = _NO_PARENT) -> int:
        return 0 if parent.isValid() else len(COLUMNS)

    @override
    def headerData(self, section: int, orientation: Qt.Orientation, role: int = _DISPLAY) -> object:
        if orientation == Qt.Orientation.Horizontal and role == _DISPLAY:
            return COLUMNS[section]
        return None

    @override
    def data(self, index: QModelIndex | QPersistentModelIndex, role: int = _DISPLAY) -> object:
        if not index.isValid():
            return None
        row, column = index.row(), index.column()
        if role == Qt.ItemDataRole.TextAlignmentRole and column in {NUMBER, LENGTH}:
            return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        if role != _DISPLAY:
            return None
        if column == NUMBER:
            return str(row + 1)
        if column in {TIME, LENGTH}:
            packet = self.decoder.packet(row)
            return self._time(packet) if column == TIME else str(packet.original_length)
        summary = self.decoder.summary(row)
        if summary is None:
            self.decode_through(row)
            return ""
        return _column(summary, column)

    def _time(self, packet: Packet) -> str:
        """Seconds since the capture's first packet, Wireshark's default."""
        if packet.timestamp_ns is None or self._start is None:
            return ""
        return relative_time(packet.timestamp_ns - self._start, packet.interface)

    def decode_through(self, row: int) -> None:
        """Have the packets up to ``row`` decoded, a slice at a time, starting soon."""
        if row > self._wanted:
            self._wanted = row
            if not self._timer.isActive():
                self._timer.start(0)

    def _decode_some(self) -> None:
        before = self.decoder.decoded
        deadline = time.monotonic() + SLICE_SECONDS
        after = self.decoder.advance(self._wanted, deadline)
        if after > before:
            self.dataChanged.emit(
                self.index(before, SOURCE), self.index(after - 1, INFO), [_DISPLAY]
            )
        self.progress.emit(after, min(self._wanted + 1, len(self.decoder)))
        if self.busy:
            self._timer.start(0)


def relative_time(nanoseconds: int, interface: Interface | None) -> str:
    """A time since the first packet, to as many decimals as the file counts in."""
    places = _decimals(interface)
    sign = "-" if nanoseconds < 0 else ""
    seconds, fraction = divmod(abs(nanoseconds), NS_PER_SECOND)
    if not places:
        return f"{sign}{seconds}"
    return f"{sign}{seconds}.{fraction // 10 ** (9 - places):0{places}d}"


def _decimals(interface: Interface | None) -> int:
    """Microseconds unless the interface counts in finer steps, as Wireshark's
    automatic precision does. A resolution in powers of two gets nanoseconds."""
    units = 1_000_000 if interface is None else interface.units_per_second
    digits = str(units)
    if digits.startswith("1") and set(digits[1:]) <= {"0"}:
        return min(len(digits) - 1, 9)
    return 9


def _first_time(decoder: Decoder) -> int | None:
    """The time the capture starts at: its first packet that has one."""
    for packet in decoder.index:
        if packet.timestamp_ns is not None:
            return packet.timestamp_ns
    return None


def _column(summary: Summary, column: int) -> str:
    if column == SOURCE:
        return summary.source
    if column == DESTINATION:
        return summary.destination
    if column == PROTOCOL:
        return summary.protocol
    return summary.info
