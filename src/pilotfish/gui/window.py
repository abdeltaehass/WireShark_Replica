"""The main window: Wireshark's three panes, one above the other.

The packet list is on top, the protocol tree of the packet selected in it
below, and that packet's bytes at the bottom, with the display filter bar
above them all. Packets come from a file, through a :class:`PacketIndex`, or
from a live capture, through the :class:`PcapngStream` its helper fills, and
the panes don't need to know which.

With nothing open, the window shows the interfaces to capture on instead.
"""

import os
import shlex
import subprocess
import sys
from collections.abc import Callable, Sequence
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
    QStackedWidget,
    QStyle,
    QTableView,
    QVBoxLayout,
    QWidget,
)

import pilotfish.core.protocols  # noqa: F401  (registers the dissectors)
from pilotfish.core.capture import access
from pilotfish.core.decoder import Decoder, Packets
from pilotfish.core.display import DisplayFilter
from pilotfish.core.formats import CaptureFileError, PacketIndex
from pilotfish.gui.bytes_view import BytesPane
from pilotfish.gui.detail import ProtocolTreeView
from pilotfish.gui.filter_bar import DisplayFilterBar
from pilotfish.gui.interfaces import InterfacePicker
from pilotfish.gui.live import HELPER, CaptureSession
from pilotfish.gui.packet_list import PacketListModel

APP_NAME = "pilotfish"
CAPTURE_FILES = "Capture files (*.pcap *.pcapng *.cap *.ntar);;All files (*)"

# Starting widths, in characters of the list's font. Info takes the rest.
_COLUMN_WIDTHS = (7, 12, 22, 22, 9, 7)

type Runner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


class MainWindow(QMainWindow):
    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        picker: InterfacePicker | None = None,
        helper: Sequence[str] = HELPER,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle(APP_NAME)
        self.index: PacketIndex | None = None
        self.session: CaptureSession | None = None
        self.model: PacketListModel | None = None
        self.helper = tuple(helper)
        """The command that starts the capture helper."""
        self.run_command: Runner = access.run_command
        self._waiting_for: int | None = None
        """The packet selected before decoding reached it, if one was."""
        self._following = True
        """Whether the list keeps the newest packet in view during a capture."""

        self.picker = picker or InterfacePicker()
        self.picker.start_requested.connect(self.start_capture)
        self.filter_bar = DisplayFilterBar()
        self.filter_bar.applied.connect(self._apply_filter)
        self.filter_bar.edit.checked.connect(self._show_filter_problem)
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
        packets = QWidget()
        column = QVBoxLayout(packets)
        column.setContentsMargins(0, 0, 0, 0)
        column.setSpacing(0)
        column.addWidget(self.filter_bar)
        column.addWidget(panes, 1)
        self.pages = QStackedWidget()
        self.pages.addWidget(self.picker)
        self.pages.addWidget(packets)
        self._packets_page = packets
        self.setCentralWidget(self.pages)

        self.file_label = QLabel()
        self.counts_label = QLabel()
        self.progress_label = QLabel()
        self.statusBar().addWidget(self.file_label, 1)
        self.statusBar().addPermanentWidget(self.counts_label)
        self.statusBar().addPermanentWidget(self.progress_label)
        self._add_actions()
        self._update_actions()
        self.resize(1200, 860)

    # Files

    def open_file(self, path: str | os.PathLike[str]) -> None:
        """Open a capture file in place of whatever is open now.

        Raises :class:`CaptureFileError` or :class:`OSError` if it can't be
        read at all, leaving what is open as it was. A file damaged partway
        opens with the packets before the damage, and the status bar says
        what was wrong.
        """
        index = PacketIndex.open(path)
        self.close_file()
        self.index = index
        self._show_packets(index)
        name = Path(path).name
        self.setWindowTitle(f"{name} — {APP_NAME}")
        count = len(index)
        status = f"{name}: {count:,} packet{'' if count == 1 else 's'}"
        if index.error is not None:
            status += f". The file is damaged after that: {index.error}"
        self.file_label.setText(status)

    def close_file(self) -> None:
        """Close the file or capture, and go back to the interfaces."""
        self._waiting_for = None
        self.packet_list.setModel(None)
        self.tree.clear()
        self.bytes.clear()
        if self.model is not None:
            self.model.stop()
            self.model.deleteLater()
            self.model = None
        if self.session is not None:
            self.session.close()
            self.session.deleteLater()
            self.session = None
        if self.index is not None:
            self.index.close()
            self.index = None
        self.setWindowTitle(APP_NAME)
        for label in (self.file_label, self.counts_label, self.progress_label):
            label.clear()
        self.pages.setCurrentWidget(self.picker)
        self._update_actions()

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
            self.warn(f"{Path(path).name} can't be opened: {reason}")
            return False
        return True

    # Live capture

    def start_capture(
        self, interface: str | None = None, capture_filter: str | None = None
    ) -> bool:
        """Capture from ``interface``, or the one chosen in the picker."""
        name = interface or self.picker.selected()
        if name is None:
            self.warn("Choose an interface to capture on.")
            return False
        if interface is None and self.picker.filter.validity == "invalid":
            self.warn(f"The capture filter doesn't compile: {self.picker.filter.problem}")
            return False
        wanted_filter = capture_filter if interface is not None else self.picker.capture_filter()
        self.close_file()
        session = CaptureSession(name, wanted_filter, self, helper=self.helper)
        session.failed.connect(self._capture_failed)
        session.finished.connect(self._capture_finished)
        session.statistics.connect(self._update_counts)
        self.session = session
        self._show_packets(session.stream)
        self._following = True
        self.setWindowTitle(f"Capturing from {name} — {APP_NAME}")
        filtering = f" (filter: {wanted_filter})" if wanted_filter else ""
        self.file_label.setText(f"Capturing from {name}{filtering}")
        session.start()
        self._update_actions()
        return True

    def stop_capture(self) -> None:
        if self.session is not None:
            self.session.stop()

    def restart_capture(self) -> None:
        """Throw away what was captured and start again, as Wireshark's restart does."""
        if self.session is not None:
            self.start_capture(self.session.interface, self.session.capture_filter)

    def _capture_finished(self) -> None:
        session = self.session
        if session is None:
            return
        if self.model is not None:
            self.model.refresh()
        if session.error is None:
            self.setWindowTitle(f"{session.interface} — {APP_NAME}")
            self.file_label.setText(f"Captured from {session.interface}")
        self._update_counts()
        self._update_actions()

    def _capture_failed(self, kind: str, message: str) -> None:
        self.file_label.setText(f"Capture failed: {message}")
        if kind == "permission":
            self.offer_access(message)
        else:
            self.warn(f"The capture failed: {message}")

    def offer_access(self, message: str) -> None:
        """Explain why capture needs permission, and offer to install the launch daemon."""
        state = access.check()
        reasons = state.explain() or [message]
        if not (state.daemon or state.wireshark_daemon) or not state.member:
            if self.ask_to_install("\n\n".join(reasons)):
                self.install_access()
        else:
            self.warn("\n\n".join(reasons))

    def install_access(self) -> bool:
        """Run ``pilotfish bpf-access install`` as an administrator.

        macOS asks for the password itself, through osascript, the way an
        installer would, so the app never sees it.
        """
        command = shlex.join(
            [
                sys.executable,
                "-m",
                "pilotfish",
                "bpf-access",
                "install",
                "--user",
                access.current_user(),
            ]
        )
        script = f'do shell script "{_applescript_string(command)}" with administrator privileges'
        result = self.run_command(["osascript", "-e", script])
        if result.returncode != 0:
            reason = result.stderr.strip() or f"exit status {result.returncode}"
            self.warn(f"Capture access wasn't installed: {reason}")
            return False
        state = access.check()
        if state.readable:
            self.restart_capture()
        else:
            self.warn(
                "Installed. You are in the access_bpf group from your next login: "
                "log out and back in, then capture."
            )
        return True

    # What the user is asked or told; tests answer these themselves.

    def warn(self, text: str) -> None:
        QMessageBox.warning(self, APP_NAME, text)

    def ask_to_install(self, text: str) -> bool:
        box = QMessageBox(QMessageBox.Icon.Question, APP_NAME, text, parent=self)
        install = box.addButton("Install…", QMessageBox.ButtonRole.AcceptRole)
        box.addButton(QMessageBox.StandardButton.Cancel)
        box.exec()
        return box.clickedButton() is install

    # The panes

    def _show_packets(self, packets: Packets) -> None:
        model = PacketListModel(packets, self)
        model.progress.connect(self._show_progress)
        model.refreshed.connect(self._update_counts)
        model.rowsAboutToBeInserted.connect(self._note_position)
        model.rowsInserted.connect(self._follow)
        self.model = model
        self.packet_list.setModel(model)
        self.packet_list.selectionModel().currentRowChanged.connect(self._select)
        for column, width in enumerate(self._widths):
            self.packet_list.setColumnWidth(column, width)
        if self.filter_bar.active is not None:
            model.set_filter(self.filter_bar.active)
        self.pages.setCurrentWidget(self._packets_page)
        self._update_counts()

    def _apply_filter(self, display: DisplayFilter | None) -> None:
        if self.model is not None:
            self._waiting_for = None
            self.model.set_filter(display)
            self._update_counts()

    def _show_filter_problem(self, problem: str) -> None:
        if problem:
            self.statusBar().showMessage(f"Display filter: {problem}")
        else:
            self.statusBar().clearMessage()

    def _note_position(self) -> None:
        bar = self.packet_list.verticalScrollBar()
        self._following = bar.value() >= bar.maximum() - 1

    def _follow(self) -> None:
        # During a capture, the newest packets stay in view unless the list
        # has been scrolled up to look at something.
        if self.session is not None and self.session.running and self._following:
            self.packet_list.scrollToBottom()

    def _select(self, current: QModelIndex | QPersistentModelIndex, _previous: QModelIndex) -> None:
        self._waiting_for = None
        if self.model is None or not current.isValid():
            self.tree.clear()
            self.bytes.clear()
            return
        row = self.model.packet_row(current.row())
        if row >= self.model.decoder.decoded:
            # Its tree needs the packets before it decoded first. Rather than
            # hold the window up for them, show the bytes now and the tree
            # once the list's decoding gets there.
            self._waiting_for = row
            self.tree.show_waiting(f"Decoding the packets before packet {row + 1:,}…")
            self.bytes.show_bytes(bytes(self.model.packets[row].data), [])
            self.model.decode_through(row)
            return
        self._show_packet(self.model.decoder, row)

    def _show_packet(self, decoder: Decoder, row: int) -> None:
        tree = decoder.tree(row)
        self.tree.show_tree(tree)
        self.bytes.show_bytes(bytes(decoder.index[row].data), tree.sources)

    def _show_progress(self, decoded: int, wanted: int) -> None:
        if decoded >= wanted:
            self.progress_label.clear()
        else:
            self.progress_label.setText(f"Decoding: {decoded:,} of {wanted:,}")
        waiting = self._waiting_for
        if self.model is not None and waiting is not None and decoded > waiting:
            self._waiting_for = None
            self._show_packet(self.model.decoder, waiting)

    def _update_counts(self) -> None:
        """Packets captured, displayed and dropped, as Wireshark's status bar has them."""
        model = self.model
        if model is None:
            self.counts_label.clear()
            return
        total = model.total
        parts = [f"Packets: {total:,}"]
        if model.display is not None:
            share = 100 * model.displayed / total if total else 0
            parts.append(f"Displayed: {model.displayed:,} ({share:.1f}%)")
        if self.session is not None:
            dropped = self.session.dropped
            seen = total + dropped
            share = 100 * dropped / seen if seen else 0
            parts.append(f"Dropped: {dropped:,} ({share:.1f}%)")
        self.counts_label.setText(" · ".join(parts))

    def _update_actions(self) -> None:
        running = self.session is not None and self.session.running
        self.start_action.setEnabled(not running)
        self.stop_action.setEnabled(running)
        self.restart_action.setEnabled(self.session is not None)

    @override
    def closeEvent(self, event: QCloseEvent) -> None:
        self.close_file()
        super().closeEvent(event)

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

    def _add_actions(self) -> None:
        style = self.style()
        icons = QStyle.StandardPixmap

        def action(
            text: str, keys: QKeySequence | QKeySequence.StandardKey, slot: Callable[[], object]
        ) -> QAction:
            made = QAction(text, self)
            made.setShortcut(keys)
            made.triggered.connect(slot)
            return made

        self.open_action = action("&Open…", QKeySequence.StandardKey.Open, self.choose_file)
        close = action("&Close", QKeySequence.StandardKey.Close, self.close_file)
        quit_app = action("&Quit", QKeySequence.StandardKey.Quit, self.close)
        self.start_action = action("&Start", QKeySequence("Ctrl+E"), self.start_capture)
        self.stop_action = action("S&top", QKeySequence("Ctrl+E"), self.stop_capture)
        self.restart_action = action("&Restart", QKeySequence("Ctrl+R"), self.restart_capture)
        focus_filter = action(
            "Display &Filter", QKeySequence("Ctrl+/"), self.filter_bar.edit.setFocus
        )
        self.start_action.setIcon(style.standardIcon(icons.SP_MediaPlay))
        self.stop_action.setIcon(style.standardIcon(icons.SP_MediaStop))
        self.restart_action.setIcon(style.standardIcon(icons.SP_BrowserReload))
        self.open_action.setIcon(style.standardIcon(icons.SP_DialogOpenButton))

        files = self.menuBar().addMenu("&File")
        for each in (self.open_action, close, quit_app):
            files.addAction(each)
        capture = self.menuBar().addMenu("&Capture")
        for each in (self.start_action, self.stop_action, self.restart_action):
            capture.addAction(each)
        view = self.menuBar().addMenu("&View")
        view.addAction(focus_filter)
        toolbar = self.addToolBar("Main")
        toolbar.setMovable(False)
        for each in (self.start_action, self.stop_action, self.restart_action, self.open_action):
            toolbar.addAction(each)


def _applescript_string(text: str) -> str:
    """Text to go between double quotes in AppleScript."""
    return text.replace("\\", "\\\\").replace('"', '\\"')
