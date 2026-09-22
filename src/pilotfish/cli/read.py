"""``pilotfish read``: list the packets in a capture file."""

import sys
from pathlib import Path
from typing import TextIO

from pilotfish.cli.table import PacketTable, TimeFormat
from pilotfish.core.formats import CaptureFile, CaptureFileError


def run(path: Path, time_format: TimeFormat, out: TextIO | None = None) -> int:
    """Print one line per packet: number, timestamp, lengths and link type."""
    out = out or sys.stdout
    try:
        capture = CaptureFile(path)
    except (OSError, CaptureFileError) as error:
        return _fail(path, error)

    table = PacketTable(out, time_format)
    with capture:
        table.write_header()
        try:
            for number, packet in enumerate(capture, start=1):
                table.write_row(number, packet)
        except CaptureFileError as error:
            out.flush()
            return _fail(path, error)
    return 0


def _fail(path: Path, error: OSError | CaptureFileError) -> int:
    reason = error.strerror if isinstance(error, OSError) and error.strerror else str(error)
    print(f"pilotfish: {path}: {reason}", file=sys.stderr)
    return 1
