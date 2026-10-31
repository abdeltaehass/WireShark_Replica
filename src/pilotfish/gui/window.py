"""The main window: Wireshark's three panes, one above the other.

The packet list is on top, the protocol tree of the packet selected in it
below, and that packet's bytes at the bottom. The three share one
:class:`Decoder`, which reads packets from the file through a
:class:`PacketIndex` rather than holding them.
"""

import os
from pathlib import Path
from typing import override

from PySide6.QtCore import QModelIndex, QPersistentModelIndex, Qt
from PySide6.QtGui import QAction, QCloseEvent, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMessageBox,
    QSplitter,
    QTableView,
    QWidget,
)

import pilotfish.core.protocols  # noqa: F401  (registers the dissectors)
from pilotfish.core.decoder import Decoder
from pilotfish.core.formats import CaptureFileError, PacketIndex
from pilotfish.gui.bytes_view import BytesPane
from pilotfish.gui.detail import ProtocolTreeView
from pilotfish.gui.packet_list import PacketListModel

APP_NAME = "pilotfish"
CAPTURE_FILES = "Capture files (*.pcap *.pcapng *.cap *.ntar);;All files (*)"

# Starting widths, in characters of the list's font. Info takes the rest.
_COLUMN_WIDTHS = (7, 12, 22, 22, 9, 7)


class MainWindow(QMainWindow):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWindowTitle(APP_NAME)
        self.index: PacketIndex | None = None
        self.model: PacketListModel | None = None
        self._waiting_for: int | None = None
        """The row selected before decoding reached it, if one was."""

        self.packet_list = QTableView()
        self._set_up_list(self.packet_list)
        self.tree = ProtocolTreeView()
        self.bytes = BytesPane()
        self.tree.field_selected.connect(self.bytes.show_field)
        self.bytes.byte_clicked.connect(self.tree.select_byte)

        panes = QSplitter(Qt.Orientation.Vertical)
        for pane in (self.packet_list, self.tree, self.bytes):
            panes.addWidget(pane)
        panes.setSizes([400, 260, 200])
        self.setCentralWidget(panes)

        self.file_label = QLabel()
        self.progress_label = QLabel()
        self.statusBar().addWidget(self.file_label, 1)
        self.statusBar().addPermanentWidget(self.progress_label)
        self._add_menus()
        self.resize(1200, 860)

    def open_file(self, path: str | os.PathLike[str]) -> None:
        """Open a capture file in place of the one open now.

        Raises :class:`CaptureFileError` or :class:`OSError` if it can't be
        read at all, leaving the open file as it was. A file damaged partway
        opens with the packets before the damage, and the status bar says
        what was wrong.
        """
        index = PacketIndex.open(path)
        self.close_file()
        self.index = index
        self.model = PacketListModel(Decoder(index), self)
        self.model.progress.connect(self._show_progress)
        self.packet_list.setModel(self.model)
        self.packet_list.selectionModel().currentRowChanged.connect(self._select)
        for column, width in enumerate(self._widths):
            self.packet_list.setColumnWidth(column, width)
        name = Path(path).name
        self.setWindowTitle(f"{name} — {APP_NAME}")
        count = len(index)
        status = f"{name}: {count:,} packet{'' if count == 1 else 's'}"
        if index.error is not None:
            status += f". The file is damaged after that: {index.error}"
        self.file_label.setText(status)

    def close_file(self) -> None:
        self._waiting_for = None
        self.packet_list.setModel(None)
        self.tree.clear()
        self.bytes.clear()
        if self.model is not None:
            self.model.deleteLater()
            self.model = None
        if self.index is not None:
            self.index.close()
            self.index = None
        self.setWindowTitle(APP_NAME)
        self.file_label.clear()
        self.progress_label.clear()

    def choose_file(self) -> None:
        """Ask which file to open, and say so if it can't be."""
        path, _ = QFileDialog.getOpenFileName(self, "Open Capture File", "", CAPTURE_FILES)
        if path:
            self.try_to_open(path)

    def try_to_open(self, path: str | os.PathLike[str]) -> bool:
        try:
            self.open_file(path)
        except (CaptureFileError, OSError) as error:
            reason = error.strerror if isinstance(error, OSError) and error.strerror else error
            QMessageBox.warning(self, APP_NAME, f"{Path(path).name} can't be opened: {reason}")
            return False
        return True

    @override
    def closeEvent(self, event: QCloseEvent) -> None:
        self.close_file()
        super().closeEvent(event)

    def _select(self, current: QModelIndex | QPersistentModelIndex, _previous: QModelIndex) -> None:
        self._waiting_for = None
        if self.model is None or not current.isValid():
            self.tree.clear()
            self.bytes.clear()
            return
        row = current.row()
        if row >= self.model.decoder.decoded:
            # Its tree needs the packets before it decoded first. Rather than
            # hold the window up for them, show the bytes now and the tree
            # once the list's decoding gets there.
            self._waiting_for = row
            self.tree.show_waiting(f"Decoding the packets before packet {row + 1:,}…")
            self.bytes.show_bytes(bytes(self.model.decoder.packet(row).data), [])
            self.model.decode_through(row)
            return
        self._show_packet(self.model.decoder, row)

    def _show_packet(self, decoder: Decoder, row: int) -> None:
        tree = decoder.tree(row)
        self.tree.show_tree(tree)
        self.bytes.show_bytes(bytes(decoder.packet(row).data), tree.sources)

    def _show_progress(self, decoded: int, wanted: int) -> None:
        if decoded >= wanted:
            self.progress_label.clear()
        else:
            self.progress_label.setText(f"Decoding: {decoded:,} of {wanted:,}")
        waiting = self._waiting_for
        if self.model is not None and waiting is not None and decoded > waiting:
            self._waiting_for = None
            self._show_packet(self.model.decoder, waiting)

    def _set_up_list(self, view: QTableView) -> None:
        view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        view.setShowGrid(False)
        view.setWordWrap(False)
        view.setAlternatingRowColors(True)
        view.setCornerButtonEnabled(False)
        rows = view.verticalHeader()
        rows.hide()
        # Every row the same height, so the view never measures rows it
        # isn't showing, and so never asks for them.
        rows.setSectionResizeMode(QHeaderView.ResizeMode.Fixed)
        rows.setDefaultSectionSize(view.fontMetrics().height() + 6)
        columns = view.horizontalHeader()
        columns.setHighlightSections(False)
        columns.setStretchLastSection(True)
        columns.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        self._widths = [view.fontMetrics().averageCharWidth() * chars for chars in _COLUMN_WIDTHS]

    def _add_menus(self) -> None:
        menu = self.menuBar().addMenu("&File")
        for text, keys, slot in (
            ("&Open…", QKeySequence.StandardKey.Open, self.choose_file),
            ("&Close", QKeySequence.StandardKey.Close, self.close_file),
            ("&Quit", QKeySequence.StandardKey.Quit, self.close),
        ):
            action = QAction(text, self)
            action.setShortcut(keys)
            action.triggered.connect(slot)
            menu.addAction(action)
