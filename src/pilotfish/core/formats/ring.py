"""Writing a long capture across a ring of files.

A capture left running for days would fill the disk as one file. A ring
buffer starts a new file whenever the current one reaches a size or an age,
and keeps only the newest few, deleting the oldest as each new one starts:
a recording of the last hour, say, that is always there when something goes
wrong.

The files are named the way dumpcap names them, from the name given with a
number and the time each one starts::

    capture.pcapng  ->  capture_00001_20261005143012.pcapng
                        capture_00002_20261005144512.pcapng

The time is the first packet's, in UTC, so a file split from a saved capture
is named for when its packets were captured rather than for when it was split.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import BinaryIO

from pilotfish.core.formats.reader import FileFormat
from pilotfish.core.formats.writer import CaptureWriter, open_writer
from pilotfish.core.packet import Packet
from pilotfish.core.timestamps import NS_PER_SECOND

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class RingLimits:
    """When to start a new file, and how many to keep."""

    max_bytes: int | None = None
    """Start a new file once the current one holds this many bytes."""
    max_seconds: int | None = None
    """Start a new file once a packet comes this long after the current
    file's first one."""
    max_files: int | None = None
    """Keep only this many of the newest files, deleting older ones."""

    def __post_init__(self) -> None:
        if self.max_bytes is None and self.max_seconds is None:
            raise ValueError("a ring buffer needs a size or a duration to start new files at")


class RingBuffer:
    """A capture writer that spreads its packets over a series of files.

    Each file is a whole capture file of its own, with its own header and
    interface descriptions, so any one of them can be opened alone. A new
    file is only started when a packet arrives for it, so a quiet hour makes
    no empty files.
    """

    def __init__(
        self,
        path: Path,
        file_format: FileFormat,
        limits: RingLimits,
        *,
        link_type: int | None = None,
    ) -> None:
        self._path = path
        self._format = file_format
        self._limits = limits
        self._link_type = link_type
        self._suffix = path.suffix or f".{file_format}"
        self.files: list[Path] = []
        """Every file started, oldest first, including those since deleted."""
        self._stream: BinaryIO | None = None
        self._writer: CaptureWriter | None = None
        self._started_ns = 0

    def write(self, packet: Packet) -> None:
        if self._writer is None or self._full(packet):
            self._next_file(packet)
        assert self._writer is not None
        self._writer.write(packet)

    def flush(self) -> None:
        if self._writer is not None:
            self._writer.flush()

    def close(self) -> None:
        self._close_file()

    def _full(self, packet: Packet) -> bool:
        limits = self._limits
        assert self._stream is not None
        if limits.max_bytes is not None and self._stream.tell() >= limits.max_bytes:
            return True
        if limits.max_seconds is None or packet.timestamp_ns is None:
            return False
        return packet.timestamp_ns - self._started_ns >= limits.max_seconds * NS_PER_SECOND

    def _next_file(self, packet: Packet) -> None:
        self._close_file()
        self._started_ns = packet.timestamp_ns or 0
        when = _EPOCH + timedelta(microseconds=self._started_ns // 1_000)
        name = f"{self._path.stem}_{len(self.files) + 1:05d}_{when:%Y%m%d%H%M%S}{self._suffix}"
        path = self._path.with_name(name)
        self._stream = path.open("wb")
        self.files.append(path)
        self._writer = open_writer(self._stream, self._format, link_type=self._link_type)
        keep = self._limits.max_files
        if keep is not None and len(self.files) > keep:
            self.files[-keep - 1].unlink(missing_ok=True)

    def _close_file(self) -> None:
        if self._writer is not None:
            self._writer.close()
        if self._stream is not None:
            self._stream.close()
        self._writer = None
        self._stream = None
