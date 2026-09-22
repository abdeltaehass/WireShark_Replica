"""``pilotfish read``: list the packets in a capture file."""

import sys
from pathlib import Path
from typing import Literal, TextIO

from pilotfish.core.formats import CaptureFile, CaptureFileError
from pilotfish.core.linktypes import link_type_name
from pilotfish.core.timestamps import format_epoch, format_utc

type TimeFormat = Literal["epoch", "utc"]

TIME_FORMATS: tuple[TimeFormat, ...] = ("epoch", "utc")

_TIME_WIDTH: dict[TimeFormat, int] = {"epoch": 20, "utc": 29}


def run(path: Path, time_format: TimeFormat, out: TextIO | None = None) -> int:
    """Print one line per packet: number, timestamp, lengths and link type."""
    out = out or sys.stdout
    try:
        capture = CaptureFile(path)
    except (OSError, CaptureFileError) as error:
        return _fail(path, error)

    format_time = format_utc if time_format == "utc" else format_epoch
    width = _TIME_WIDTH[time_format]
    with capture:
        out.write(f"{'No.':>7}  {'Time':<{width}}  {'Length':>7}  {'Captured':>8}  Link type\n")
        try:
            for number, packet in enumerate(capture, start=1):
                ns = packet.timestamp_ns
                time = "-" if ns is None else format_time(ns)
                out.write(
                    f"{number:>7}  {time:<{width}}  {packet.original_length:>7}  "
                    f"{packet.captured_length:>8}  {link_type_name(packet.link_type)}\n"
                )
        except CaptureFileError as error:
            out.flush()
            return _fail(path, error)
    return 0


def _fail(path: Path, error: OSError | CaptureFileError) -> int:
    reason = error.strerror if isinstance(error, OSError) and error.strerror else str(error)
    print(f"pilotfish: {path}: {reason}", file=sys.stderr)
    return 1
