"""A live capture: the helper process, and the packets it sends back.

The window starts ``python -m pilotfish.helper`` with :class:`QProcess`,
which hands over what the helper writes whenever the event loop gets round
to it, so reading never blocks the window. What comes on standard output is
pcapng, fed to a :class:`PcapngStream` that spools it to a temporary file;
what comes on standard error is the helper's reports, a JSON object a line.
"""

import json
import os
import sys
import tempfile
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from PySide6.QtCore import QObject, QProcess, QTimer, Signal

from pilotfish.core.formats import CaptureFileError, PcapngStream

HELPER = (sys.executable, "-m", "pilotfish.helper")

READ_SIZE = 1024 * 1024
"""The most of the helper's output taken in one turn of the event loop."""


class CaptureSession(QObject):
    """One run of the capture helper on one interface."""

    started = Signal()
    statistics = Signal()
    """New counts arrived from the helper."""
    failed = Signal(str, str)
    """The helper couldn't capture: what kind of problem, and what it said."""
    finished = Signal()

    def __init__(
        self,
        interface: str,
        capture_filter: str | None = None,
        parent: QObject | None = None,
        *,
        helper: Sequence[str] = HELPER,
        spool_dir: str | os.PathLike[str] | None = None,
    ) -> None:
        super().__init__(parent)
        self.interface = interface
        self.capture_filter = capture_filter
        stamp = datetime.now().strftime("%Y%m%d%H%M%S")
        handle, spool = tempfile.mkstemp(
            prefix=f"pilotfish_{interface}_{stamp}_", suffix=".pcapng", dir=spool_dir
        )
        os.close(handle)
        self.stream = PcapngStream(spool)
        self.counts: dict[str, Any] = {}
        """The helper's latest counts: captured, dropped and the rest."""
        self.error: tuple[str, str] | None = None
        self._events = bytearray()
        self._unexplained = ""
        """What the helper printed that wasn't a report, such as a traceback."""
        self._stopping = False
        self._draining = False
        """Whether the helper has finished, so whatever is left is read at once."""
        self.process = QProcess(self)
        self.process.readyReadStandardOutput.connect(self._read_output)
        self.process.readyReadStandardError.connect(self._read_events)
        self.process.finished.connect(self._finished)
        arguments = [*helper[1:], "-i", interface]
        if capture_filter:
            arguments += ["-f", capture_filter]
        self._program = (helper[0], arguments)

    @property
    def running(self) -> bool:
        return self.process.state() != QProcess.ProcessState.NotRunning

    @property
    def dropped(self) -> int:
        dropped = self.counts.get("dropped", 0)
        return dropped if isinstance(dropped, int) else 0

    def start(self) -> None:
        program, arguments = self._program
        self.process.start(program, arguments)

    def stop(self) -> None:
        """Ask the helper to stop. It finishes writing what it captured first."""
        if self.running:
            self._stopping = True
            self.process.terminate()

    def close(self, *, keep: bool = False) -> None:
        """Stop for good, and remove the spool unless ``keep``."""
        if self.running:
            self.stop()
            if not self.process.waitForFinished(3000):
                self.process.kill()
                self.process.waitForFinished(1000)
        self.stream.close()
        if not keep:
            self.stream.path.unlink(missing_ok=True)

    def _read_output(self) -> None:
        if self._draining:
            data = bytes(self.process.readAllStandardOutput().data())
        else:
            # A burst can leave megabytes waiting. Taking a bounded piece
            # each turn of the event loop keeps every turn short, so the
            # window can repaint while the rest is read.
            data = bytes(self.process.read(READ_SIZE).data())
            if self.process.bytesAvailable():
                QTimer.singleShot(0, self._read_output)
        if not data or self.error is not None:
            return
        try:
            self.stream.feed(data)
        except CaptureFileError as error:
            self._fail("stream", f"the helper's output isn't a capture: {error}")
            self.stop()

    def _read_events(self) -> None:
        self._events += bytes(self.process.readAllStandardError().data())
        while b"\n" in self._events:
            line, _, rest = bytes(self._events).partition(b"\n")
            self._events = bytearray(rest)
            self._handle(line.decode("utf-8", errors="replace"))

    def _handle(self, line: str) -> None:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            # Kept in case the helper then fails without saying why.
            self._unexplained += line + "\n"
            return
        if not isinstance(event, dict):
            return
        kind = event.get("event")
        if kind == "started":
            self.started.emit()
        elif kind in {"stats", "stopped"}:
            self.counts = event
            self.statistics.emit()
        elif kind == "error":
            self._fail(str(event.get("kind", "capture")), str(event.get("message", "")))

    def _finished(self, status: int, _exit: QProcess.ExitStatus) -> None:
        self._draining = True
        self._read_output()
        self._read_events()
        if self.error is None and status != 0 and not self._stopping:
            said = self._unexplained.strip()
            self._fail("capture", said or f"the capture helper stopped with status {status}")
        self.finished.emit()

    def _fail(self, kind: str, message: str) -> None:
        if self.error is None:
            self.error = (kind, message)
            self.failed.emit(kind, message)
