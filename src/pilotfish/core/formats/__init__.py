"""Reading and writing pcap and pcapng capture files."""

from pilotfish.core.formats.errors import CaptureFileError
from pilotfish.core.formats.pcap import PcapHeader, PcapReader
from pilotfish.core.formats.pcapng import Interface, PcapngReader
from pilotfish.core.formats.reader import CaptureFile, FileFormat, reader_for
from pilotfish.core.formats.writer import (
    CaptureWriter,
    PcapngWriter,
    PcapWriter,
    WriteError,
    open_writer,
)

__all__ = [
    "CaptureFile",
    "CaptureFileError",
    "CaptureWriter",
    "FileFormat",
    "Interface",
    "PcapHeader",
    "PcapReader",
    "PcapWriter",
    "PcapngReader",
    "PcapngWriter",
    "WriteError",
    "open_writer",
    "reader_for",
]
