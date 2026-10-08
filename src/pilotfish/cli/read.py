"""Reading a capture file: ``pilotfish -r FILE``, or ``pilotfish read FILE``."""

import sys
from itertools import chain
from typing import TextIO

from pilotfish.cli.pipeline import Pipeline
from pilotfish.cli.status import CommandError, Exit
from pilotfish.core.capture import MAX_SNAPLEN, compile_filter
from pilotfish.core.filters import FilterError, Program, machine
from pilotfish.core.formats import CaptureFile, CaptureFileError
from pilotfish.core.linktypes import dlt_from_link_type
from pilotfish.core.packet import Packet

STANDARD_INPUT = "-"


def open_capture(path: str) -> CaptureFile:
    """The capture file to read.

    ``-`` is standard input, so a capture can be piped in. It is read to its
    end before the first packet is decoded.
    """
    name = "standard input" if path == STANDARD_INPUT else path
    try:
        if path == STANDARD_INPUT:
            return CaptureFile.from_bytes(sys.stdin.buffer.read(), name)
        return CaptureFile(path)
    except OSError as error:
        raise CommandError(Exit.INVALID_FILE, f"{name}: {error.strerror or error}") from None
    except CaptureFileError as error:
        raise CommandError(Exit.INVALID_FILE, f"{name}: {error}") from None


def run(
    capture: CaptureFile,
    pipeline: Pipeline,
    *,
    filter_text: str | None = None,
    count: int | None = None,
    print_filter: bool = False,
    out: TextIO | None = None,
) -> Exit:
    """Hand every packet of the file to ``pipeline``, numbered from 1.

    A capture filter leaves out the packets it doesn't match before they are
    decoded. They keep their numbers in the file, as tshark's do. ``count``
    stops after that many packets have been read, matched or not, which is
    what tshark's -c does too.

    A file that turns out to be cut short ends the output cleanly, after
    the packets before the damage, and then fails.
    """
    out = out or sys.stdout
    name = str(capture.path)
    # A pcapng file can hold interfaces with different link types, and a
    # filter has to be compiled for each of them.
    programs: dict[int, Program] = {}
    with capture:
        packets = enumerate(capture, start=1)
        try:
            # Compiling the filter needs a link type, so it waits for the
            # first packet, and a filter that won't compile says so before any
            # of the output is printed.
            first = next(packets, None)
        except CaptureFileError as error:
            raise CommandError(Exit.READ_ERROR, f"{name}: {error}") from None
        if filter_text is not None:
            link_type = 1 if first is None else first[1].link_type
            program = _program_for(link_type, filter_text, programs)
            if print_filter:
                for line in program.disassemble():
                    out.write(f"{line}\n")
                return Exit.OK
        pipeline.begin()
        try:
            for number, packet in packets if first is None else chain([first], packets):
                if count is not None and number > count:
                    break
                if filter_text is not None and not _matches(packet, filter_text, programs):
                    continue
                pipeline.packet(number, packet)
        except CaptureFileError as error:
            raise CommandError(Exit.READ_ERROR, f"{name}: {error}") from None
        finally:
            pipeline.end()
    return Exit.OK


def _matches(packet: Packet, filter_text: str, programs: dict[int, Program]) -> bool:
    """Run the filter over one packet, the way the kernel would for live capture."""
    program = _program_for(packet.link_type, filter_text, programs)
    return machine.matches(program, packet.data, packet.original_length)


def _program_for(link_type: int, filter_text: str, programs: dict[int, Program]) -> Program:
    program = programs.get(link_type)
    if program is None:
        try:
            program = compile_filter(filter_text, dlt_from_link_type(link_type), MAX_SNAPLEN)
        except FilterError as error:
            raise CommandError(Exit.INVALID_FILTER, str(error)) from None
        programs[link_type] = program
    return program
