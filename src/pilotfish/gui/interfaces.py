"""The interface picker: what to capture on, and how busy each one is.

Each interface has a small graph of its traffic over the last minute, so the
one carrying traffic is easy to spot, as on Wireshark's welcome page. The
graphs come from the kernel's packet counters, read once a second, which
needs no permission to capture.
"""

from collections import deque
from collections.abc import Callable
from typing import override

from PySide6.QtCore import QModelIndex, QPersistentModelIndex, QPointF, QRect, Qt, QTimer, Signal
from PySide6.QtGui import QPainter, QPen, QPolygonF
from PySide6.QtWidgets import (
    QAbstractItemView,
    QLabel,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from pilotfish.core.capture import CaptureError, Device, list_devices
from pilotfish.core.capture.counters import Counters, interface_counters
from pilotfish.gui.filter_bar import FilterEdit, capture_filter_problem

HISTORY = 60
"""Seconds of traffic each graph shows."""
POLL_MS = 1000

NAME, TRAFFIC, ADDRESSES = range(3)
_RATES = Qt.ItemDataRole.UserRole
_NAME = Qt.ItemDataRole.UserRole + 1


class Sparkline(QStyledItemDelegate):
    """Draws a row's packets a second as a line, scaled to its own busiest second."""

    @override
    def paint(
        self,
        painter: QPainter,
        option: QStyleOptionViewItem,
        index: QModelIndex | QPersistentModelIndex,
    ) -> None:
        super().paint(painter, option, index)
        rates = index.data(_RATES)
        if not isinstance(rates, list) or len(rates) < 2:
            return
        area: QRect = option.rect.adjusted(4, 4, -4, -4)
        top = max(max(rates), 1)
        step = area.width() / (HISTORY - 1)
        start = area.left() + area.width() - step * (len(rates) - 1)
        line = QPolygonF(
            [
                QPointF(start + step * n, area.bottom() - area.height() * rate / top)
                for n, rate in enumerate(rates)
            ]
        )
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        selected = option.state & QStyle.StateFlag.State_Selected
        palette = option.palette
        # On a selected row the line would vanish into the selection colour.
        colour = (palette.highlightedText() if selected else palette.highlight()).color()
        painter.setPen(QPen(colour, 1.5))
        painter.drawPolyline(line)
        painter.restore()


class InterfacePicker(QWidget):
    """Every interface, its traffic, and the capture filter to start with."""

    start_requested = Signal(str)
    """An interface was double-clicked, or Return pressed on it."""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        devices: Callable[[], list[Device]] = list_devices,
        counters: Callable[[], dict[str, Counters]] = interface_counters,
    ) -> None:
        super().__init__(parent)
        self._devices = devices
        self._counters = counters
        self._last: dict[str, int] = {}
        self.rates: dict[str, deque[int]] = {}
        """Packets a second for each interface, the newest last."""

        title = QLabel("Capture")
        title.setStyleSheet("font-size: 18px; font-weight: 600;")
        self.filter = FilterEdit(capture_filter_problem, "Enter a capture filter …")
        self.list = QTreeWidget()
        self.list.setHeaderLabels(["Interface", "Traffic", "Addresses"])
        self.list.setRootIsDecorated(False)
        self.list.setUniformRowHeights(True)
        self.list.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.list.setItemDelegateForColumn(TRAFFIC, Sparkline(self.list))
        self.list.setColumnWidth(NAME, 280)
        self.list.setColumnWidth(TRAFFIC, 160)
        self.list.itemActivated.connect(self._activated)
        self.message = QLabel(
            "Double-click an interface to capture on it, or open a capture file with ⌘O."
        )
        self.message.setWordWrap(True)

        layout = QVBoxLayout(self)
        layout.addWidget(title)
        layout.addWidget(self.filter)
        layout.addWidget(self.list, 1)
        layout.addWidget(self.message)

        self._poll = QTimer(self)
        self._poll.setInterval(POLL_MS)
        self._poll.timeout.connect(self.sample)
        self.reload()
        self._poll.start()

    def reload(self) -> None:
        """List the interfaces again, keeping the one selected."""
        chosen = self.selected()
        self.list.clear()
        try:
            devices = self._devices()
        except CaptureError as error:
            self.message.setText(f"The interfaces can't be listed: {error}")
            return
        for device in devices:
            label = device.name + (f" ({device.description})" if device.description else "")
            item = QTreeWidgetItem([label, "", ", ".join(device.addresses)])
            item.setData(NAME, _NAME, device.name)
            item.setToolTip(NAME, device.status)
            if device.status in {"down", "not running", "disconnected"}:
                item.setForeground(NAME, self.palette().placeholderText())
            self.list.addTopLevelItem(item)
            if device.name == chosen:
                self.list.setCurrentItem(item)
        if self.list.currentItem() is None and devices:
            first = next((n for n, d in enumerate(devices) if d.is_usable), 0)
            default = self.list.topLevelItem(first)
            if default is not None:
                self.list.setCurrentItem(default)
        self.sample()

    def selected(self) -> str | None:
        item = self.list.currentItem()
        name = None if item is None else item.data(NAME, _NAME)
        return name if isinstance(name, str) else None

    def select(self, name: str) -> None:
        for row in range(self.list.topLevelItemCount()):
            item = self.list.topLevelItem(row)
            if item is not None and item.data(NAME, _NAME) == name:
                self.list.setCurrentItem(item)

    def capture_filter(self) -> str | None:
        text = self.filter.text().strip()
        return text or None

    def sample(self) -> None:
        """Read the counters and add a second to every graph."""
        try:
            counters = self._counters()
        except OSError:
            return
        for name, counted in counters.items():
            previous = self._last.get(name)
            self._last[name] = counted.packets
            if previous is not None:
                history = self.rates.setdefault(name, deque(maxlen=HISTORY))
                history.append(max(counted.packets - previous, 0))
        for row in range(self.list.topLevelItemCount()):
            item = self.list.topLevelItem(row)
            if item is None:
                continue
            rates = self.rates.get(str(item.data(NAME, _NAME)))
            if rates:
                item.setData(TRAFFIC, _RATES, list(rates))
                item.setToolTip(TRAFFIC, f"{rates[-1]:,} packets in the last second")

    def _activated(self, item: QTreeWidgetItem, _column: int) -> None:
        name = item.data(NAME, _NAME)
        if isinstance(name, str) and self.filter.validity != "invalid":
            self.start_requested.emit(name)
