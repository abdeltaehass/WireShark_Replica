"""A pcapng capture arriving a piece at a time, as a live capture writes it.

The desktop app captures through a helper process that writes pcapng to a
pipe, the way Wireshark's capture helper does. Pipe reads stop wherever
they happen to, often partway through a block, so :class:`PcapngStream`
keeps the unfinished end of what has arrived until the rest comes.

Each finished block goes into a spool file on disk, and only where each
packet starts is kept in memory, as :class:`PacketIndex` does for a file.
So a capture left running holds eight bytes a packet in memory however long
it runs, and the spool is a pcapng file of everything captured so far.
"""

import os
from array import array
from collections.abc import Iterator
from pathlib import Path
from types import TracebackType
from typing import Self

from pilotfish.core.formats.errors import CaptureFileError
from pilotfish.core.formats.pcapng import SECTION_HEADER_MAGIC, PcapngBlocks
from pilotfish.core.packet import Packet

_FRAMING = 12
"""A block's type, its length, and its length again at the end."""


class PcapngStream:
    """The packets of a pcapng stream, kept in ``spool`` as they arrive."""

    def __init__(self, spool: str | os.PathLike[str]) -> None:
        self.path = Path(spool)
        # Unbuffered, so what has been written can be read straight back.
        self._file = self.path.open("w+b", buffering=0)
        self._blocks = PcapngBlocks()
        self._offsets = array("q")
        self._pending = bytearray()
        self._spooled = 0
        """Bytes in the spool so far, which is where ``_pending`` starts."""

    def feed(self, data: bytes) -> int:
        """Take the next piece of the stream, and say how many packets it finished.

        Raises :class:`CaptureFileError` if the stream isn't pcapng, or a
        block in it is damaged.
        """
        self._pending += data
        starting = not self._spooled and len(self._pending) >= 4
        if starting and bytes(self._pending[:4]) != SECTION_HEADER_MAGIC:
            raise CaptureFileError("the stream isn't pcapng (no Section Header Block first)")
        found = 0
        while complete := self._complete():
            found += self._spool(complete)
        return found

    def finish(self) -> None:
        """Say the stream has ended, which it may only do between blocks."""
        if self._pending:
            raise CaptureFileError(
                f"the stream ended partway through a block, {len(self._pending)} bytes in"
            )

    def _spool(self, complete: int) -> int:
        """Read the whole blocks at the front of what is waiting, and keep them."""
        chunk = memoryview(bytes(self._pending[:complete]))
        del self._pending[:complete]
        found = 0
        offset = 0
        try:
            while offset < complete:
                _, length = self._blocks.frame(chunk, offset, self._spooled)
                if self._blocks.read(chunk, offset, self._spooled) is not None:
                    self._offsets.append(self._spooled + offset)
                    found += 1
                offset += length
        finally:
            # Whatever was read keeps its place in the spool, damage or not.
            self._file.write(chunk[:offset])
            self._spooled += offset
        return found

    @property
    def waiting(self) -> int:
        """Bytes of a block that hasn't finished arriving."""
        return len(self._pending)

    def __len__(self) -> int:
        return len(self._offsets)

    def __getitem__(self, row: int) -> Packet:
        """The packet in this row, counting from 0, read back from the spool."""
        if not 0 <= row < len(self._offsets):
            raise IndexError(f"there is no packet {row + 1}; the stream has {len(self)}")
        offset = self._offsets[row]
        order = self._blocks.section_at(offset).byte_order
        header = os.pread(self._file.fileno(), _FRAMING, offset)
        length = int.from_bytes(header[4:8], "little" if order == "<" else "big")
        block = os.pread(self._file.fileno(), length, offset)
        return self._blocks.packet(memoryview(block), 0, offset)

    def __iter__(self) -> Iterator[Packet]:
        return (self[row] for row in range(len(self)))

    def close(self) -> None:
        self._file.close()

    def _complete(self) -> int:
        """How many bytes at the front of what is waiting are whole blocks."""
        pending = self._pending
        order = self._blocks.byte_order
        offset = 0
        while len(pending) - offset >= _FRAMING:
            header = bytes(pending[offset : offset + _FRAMING])
            if header[:4] == SECTION_HEADER_MAGIC:
                # A new section can change the byte order of what follows.
                magic = header[8:12]
                order = "<" if magic == b"\x4d\x3c\x2b\x1a" else ">"
            length = int.from_bytes(header[4:8], "little" if order == "<" else "big")
            if length < _FRAMING or length % 4:
                # Not a length a block can have. The blocks before it are
                # kept first, then reading it says what is wrong with it.
                return offset or _FRAMING
            if len(pending) - offset < length:
                break
            offset += length
        return offset

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
