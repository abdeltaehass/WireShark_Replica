"""Open a capture file and choose its reader from the first bytes."""

import contextlib
import mmap
import os
from collections.abc import Buffer, Iterator
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import Self

from pilotfish.core.formats.errors import CaptureFileError
from pilotfish.core.formats.pcap import PcapReader, is_pcap_magic
from pilotfish.core.formats.pcapng import SECTION_HEADER_MAGIC, PcapngReader
from pilotfish.core.packet import Packet

_GZIP_MAGIC = b"\x1f\x8b"


class FileFormat(StrEnum):
    PCAP = "pcap"
    PCAPNG = "pcapng"


def reader_for(data: Buffer) -> PcapReader | PcapngReader:
    """Return a reader for capture data held in memory, chosen by its magic number."""
    view = memoryview(data)
    if len(view) < 4:
        raise CaptureFileError(f"file is too short to be a capture file ({len(view)} bytes)")
    head = bytes(view[:4])
    if head == SECTION_HEADER_MAGIC:
        return PcapngReader(view)
    if is_pcap_magic(head):
        return PcapReader(view)
    if head.startswith(_GZIP_MAGIC):
        raise CaptureFileError("file is gzip-compressed; decompress it first with gunzip")
    raise CaptureFileError("not a pcap or pcapng file")


class CaptureFile:
    """A capture file opened for reading. Iterate over it for its packets.

    The file is memory-mapped, so opening a large file reads nothing up front,
    and each packet's data is a view into the mapping rather than a copy.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        with self.path.open("rb") as file:
            if os.fstat(file.fileno()).st_size == 0:
                raise CaptureFileError("file is empty")
            # The mapping keeps its own reference to the file, so the file
            # object can be closed straight away.
            self._mmap = mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            self._reader = reader_for(self._mmap)
        except CaptureFileError:
            self._close_mapping()
            raise
        self.format = (
            FileFormat.PCAPNG if isinstance(self._reader, PcapngReader) else FileFormat.PCAP
        )

    def __iter__(self) -> Iterator[Packet]:
        return iter(self._reader)

    def close(self) -> None:
        self._reader.close()
        self._close_mapping()

    def _close_mapping(self) -> None:
        # Packets still in use hold views into the mapping, and mmap refuses to
        # close while they exist. The mapping is then freed with the last of them.
        with contextlib.suppress(BufferError):
            self._mmap.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
