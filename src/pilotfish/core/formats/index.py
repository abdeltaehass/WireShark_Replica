"""Where each packet of a capture file is, so any one can be read again.

A capture can hold millions of packets. Holding them all would cost their
bytes again on top of the file, so the index keeps only where each one
starts: eight bytes a packet, in an array. Reading packet 40,000 is then a
lookup and one record read from the memory-mapped file, however large the
file is, which is how the desktop app's packet list can jump anywhere.
"""

import os
from array import array
from collections.abc import Iterator
from types import TracebackType
from typing import Self

from pilotfish.core.formats.errors import CaptureFileError
from pilotfish.core.formats.reader import CaptureFile
from pilotfish.core.packet import Packet


class PacketIndex:
    """The packets of a capture file, read from the file when asked for.

    Building the index reads the file once from end to end, checking each
    record as the readers always do. A file that turns out to be damaged
    partway keeps the packets before the damage, and :attr:`error` says
    what was wrong, as the command line prints what came first and then
    fails.
    """

    def __init__(self, capture: CaptureFile) -> None:
        self.capture = capture
        self._offsets = array("q")
        self.error: CaptureFileError | None = None
        """Why the file couldn't be read to its end, if it couldn't."""
        try:
            for offset, _ in capture.records():
                self._offsets.append(offset)
        except CaptureFileError as error:
            self.error = error

    @classmethod
    def open(cls, path: str | os.PathLike[str]) -> "PacketIndex":
        """Open a capture file and index it."""
        return cls(CaptureFile(path))

    def __len__(self) -> int:
        return len(self._offsets)

    def __getitem__(self, row: int) -> Packet:
        """The packet in this row, counting from 0: frame ``row + 1``."""
        if not 0 <= row < len(self._offsets):
            raise IndexError(f"there is no packet {row + 1}; the file has {len(self)}")
        return self.capture.packet_at(self._offsets[row])

    def __iter__(self) -> Iterator[Packet]:
        return (self[row] for row in range(len(self)))

    def close(self) -> None:
        self.capture.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
