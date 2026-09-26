"""``pilotfish read``: list the packets in a capture file."""

import sys
from itertools import chain
from pathlib import Path
from typing import TextIO

from pilotfish.cli.table import PacketTable, TimeFormat
from pilotfish.core.capture import MAX_SNAPLEN, compile_filter
from pilotfish.core.filters import FilterError, Program, machine
from pilotfish.core.formats import CaptureFile, CaptureFileError
from pilotfish.core.linktypes import dlt_from_link_type
from pilotfish.core.packet import Packet


def run(
    path: Path,
    time_format: TimeFormat,
    *,
    filter_text: str | None = None,
    out: TextIO | None = None,
) -> int:
    """Print one line per packet: number, timestamp, lengths and link type.

    With a capture filter, packets it doesn't match are left out. They keep
    their numbers in the file, as tshark's do.
    """
    out = out or sys.stdout
    try:
        capture = CaptureFile(path)
    except (OSError, CaptureFileError) as error:
        return _fail(path, error)

    table = PacketTable(out, time_format)
    # A pcapng file can hold interfaces with different link types, and a
    # filter has to be compiled for each of them.
    programs: dict[int, Program] = {}
    with capture:
        packets = enumerate(capture, start=1)
        try:
            # Compiling the filter needs a link type, so it waits for the
            # first packet, and a filter that won't compile says so before any
            # of the listing is printed.
            first = next(packets, None)
            if first is not None and filter_text is not None:
                _program_for(first[1].link_type, filter_text, programs)
            table.write_header()
            rest = packets if first is None else chain([first], packets)
            for number, packet in rest:
                if filter_text is not None and not _matches(packet, filter_text, programs):
                    continue
                table.write_row(number, packet)
        except CaptureFileError as error:
            out.flush()
            return _fail(path, error)
        except FilterError as error:
            out.flush()
            print(f"pilotfish: {error}", file=sys.stderr)
            return 1
    return 0


def _matches(packet: Packet, filter_text: str, programs: dict[int, Program]) -> bool:
    """Run the filter over one packet, the way the kernel would for live capture."""
    program = _program_for(packet.link_type, filter_text, programs)
    return machine.matches(program, packet.data, packet.original_length)


def _program_for(link_type: int, filter_text: str, programs: dict[int, Program]) -> Program:
    program = programs.get(link_type)
    if program is None:
        program = compile_filter(filter_text, dlt_from_link_type(link_type), MAX_SNAPLEN)
        programs[link_type] = program
    return program


def _fail(path: Path, error: OSError | CaptureFileError) -> int:
    reason = error.strerror if isinstance(error, OSError) and error.strerror else str(error)
    print(f"pilotfish: {path}: {reason}", file=sys.stderr)
    return 1
