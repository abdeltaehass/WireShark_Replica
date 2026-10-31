"""The packet list: one row per packet, decoded as it scrolls into view.

A table view asks its model only for the rows it is about to paint, so the
model is where decoding happens lazily. The number, time and length come
straight from the file. The other columns need the packet decoded, and the
packets before it, so a row that isn't decoded yet is painted blank and
decoding catches up a slice at a time between repaints, never blocking the
window for longer than :data:`SLICE_SECONDS`.

A display filter changes that. Whether a packet is shown depends on what it
decodes into, so every packet has to be decoded, in order, and the rows are
the packets that matched. Decoding then runs to the end of the capture
rather than to the rows on screen.

A live capture's packets keep arriving, and telling the view about each one
as it comes would have it lay itself out thousands of times a second. The
model tells it about new rows in batches instead, :data:`REFRESH_MS` apart.
"""

import bisect
import time
from array import array
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

from pilotfish.core.decoder import Decoder, Packets, Summary
from pilotfish.core.display import DisplayFilter
from pilotfish.core.dissect import ProtocolTree
from pilotfish.core.packet import Interface, Packet
from pilotfish.core.timestamps import NS_PER_SECOND

COLUMNS = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
NUMBER, TIME, SOURCE, DESTINATION, PROTOCOL, LENGTH, INFO = range(len(COLUMNS))

SLICE_SECONDS = 0.015
"""How long to decode for between repaints, to keep scrolling smooth."""
REFRESH_MS = 100
"""How often new rows are added to the view: about ten times a second."""

_NO_PARENT = QModelIndex()
_DISPLAY = Qt.ItemDataRole.DisplayRole


class PacketListModel(QAbstractTableModel):
    """The packets of a capture in the packet list's columns, all of them or
    those a display filter matches."""

    progress = Signal(int, int)
    """How many packets are decoded, and how many the rows shown need."""
    refreshed = Signal()
    """New packets may have arrived, been decoded or been matched."""

    def __init__(self, packets: Packets, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.packets = packets
        self.decoder = Decoder(packets)
        self.display: DisplayFilter | None = None
        self._matches = array("q")
        """With a filter, the packets it matched, in order."""
        self._shown = len(packets)
        """Rows the view has been told about."""
        self._start: int | None = None
        self._searched = 0
        """Packets looked through for the first time, which a live capture may not have yet."""
        self._wanted = -1
        self._decoding = QTimer(self)
        self._decoding.setSingleShot(True)
        self._decoding.timeout.connect(self._decode_some)
        self._refreshing = QTimer(self)
        self._refreshing.setInterval(REFRESH_MS)
        self._refreshing.timeout.connect(self.refresh)
        self._refreshing.start()

    @property
    def busy(self) -> bool:
        """Whether packets the rows need are still waiting to be decoded."""
        return self.decoder.decoded <= self._wanted

    @property
    def total(self) -> int:
        """Packets in the capture so far."""
        return len(self.packets)

    @property
    def displayed(self) -> int:
        """Packets shown: every one, or those the filter has matched so far."""
        return self._shown

    @property
    def filtering(self) -> bool:
        """Whether a filter is still deciding about packets that have arrived."""
        return self.display is not None and self.decoder.decoded < len(self.packets)

    def packet_row(self, row: int) -> int:
        """Which packet a row shows, counting from 0."""
        return row if self.display is None else self._matches[row]

    def row_of(self, packet_row: int) -> int | None:
        """The row showing a packet, if one does."""
        if self.display is None:
            return packet_row if packet_row < self._shown else None
        row = bisect.bisect_left(self._matches, packet_row, 0, self._shown)
        found = row < self._shown and self._matches[row] == packet_row
        return row if found else None

    def set_filter(self, display: DisplayFilter | None) -> None:
        """Show only the packets ``display`` matches, or every packet."""
        self.beginResetModel()
        self._matches = array("q")
        self._wanted = -1
        if display is not None:
            # Packets already decoded weren't asked about, so start again.
            self.decoder = Decoder(self.packets, visit=self._match)
        else:
            self.decoder.visit = None
        self.display = display
        self._shown = len(self.packets) if display is None else 0
        self.endResetModel()
        self.refresh()

    def refresh(self) -> None:
        """Tell the view about rows that have appeared since it was last told."""
        target = len(self.packets) if self.display is None else len(self._matches)
        if target > self._shown:
            self.beginInsertRows(_NO_PARENT, self._shown, target - 1)
            self._shown = target
            self.endInsertRows()
        if self.display is not None and self.decoder.decoded < len(self.packets):
            self.decode_through(len(self.packets) - 1)
        self.refreshed.emit()

    def stop(self) -> None:
        """Stop the timers, as the capture closes."""
        self._refreshing.stop()
        self._decoding.stop()

    @override
    def rowCount(self, parent: QModelIndex | QPersistentModelIndex = _NO_PARENT) -> int:
        return 0 if parent.isValid() else self._shown

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
        column = index.column()
        if role == Qt.ItemDataRole.TextAlignmentRole and column in {NUMBER, LENGTH}:
            return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
        if role != _DISPLAY:
            return None
        row = self.packet_row(index.row())
        if column == NUMBER:
            return str(row + 1)
        if column in {TIME, LENGTH}:
            packet = self.packets[row]
            return self._time(packet) if column == TIME else str(packet.original_length)
        summary = self.decoder.summary(row)
        if summary is None:
            self.decode_through(row)
            return ""
        return _column(summary, column)

    def decode_through(self, row: int) -> None:
        """Have the packets up to ``row`` decoded, a slice at a time, starting soon."""
        if row > self._wanted:
            self._wanted = row
            if not self._decoding.isActive():
                self._decoding.start(0)

    def _time(self, packet: Packet) -> str:
        """Seconds since the capture's first packet, Wireshark's default."""
        if self._start is None:
            self._start, self._searched = _first_time(self.packets, self._searched)
        if packet.timestamp_ns is None or self._start is None:
            return ""
        return relative_time(packet.timestamp_ns - self._start, packet.interface)

    def _match(self, row: int, tree: ProtocolTree) -> None:
        display = self.display
        if display is not None and display.matches(tree, self.packets[row].data):
            self._matches.append(row)

    def _decode_some(self) -> None:
        before = self.decoder.decoded
        deadline = time.monotonic() + SLICE_SECONDS
        after = self.decoder.advance(self._wanted, deadline)
        if after > before and self.display is None:
            last = min(after, self._shown) - 1
            if last >= before:
                self.dataChanged.emit(
                    self.index(before, SOURCE), self.index(last, INFO), [_DISPLAY]
                )
        self.progress.emit(after, min(self._wanted + 1, len(self.packets)))
        if self.busy:
            self._decoding.start(0)


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


def _first_time(packets: Packets, start: int) -> tuple[int | None, int]:
    """The time the capture starts at, its first packet that has one, looking
    from ``start`` on. Also says how far it looked."""
    for row in range(start, len(packets)):
        time_ns = packets[row].timestamp_ns
        if time_ns is not None:
            return time_ns, row
    return None, len(packets)


def _column(summary: Summary, column: int) -> str:
    if column == SOURCE:
        return summary.source
    if column == DESTINATION:
        return summary.destination
    if column == PROTOCOL:
        return summary.protocol
    return summary.info
