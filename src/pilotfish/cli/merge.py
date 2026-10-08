"""``pilotfish merge``: several capture files as one, in time order, as mergecap does."""

from collections.abc import Iterator
from contextlib import ExitStack
from itertools import chain

from pilotfish.cli import read
from pilotfish.cli.pipeline import open_output, write_errors
from pilotfish.cli.status import CommandError, Exit
from pilotfish.core.formats import CaptureFile, CaptureFileError, FileFormat, merge, open_writer
from pilotfish.core.packet import MICROSECONDS, Packet


def run(paths: list[str], output: str, file_format: FileFormat, *, concatenate: bool) -> Exit:
    """Write the packets of every file to ``output``, earliest first.

    With ``concatenate``, the files go one after another instead, as they
    were given. Every interface keeps its description and every packet its
    comments, and interfaces that describe themselves the same way in
    several files become one.
    """
    with ExitStack() as stack:
        captures = [stack.enter_context(read.open_capture(path)) for path in paths]
        packets = [_labelled(capture) for capture in captures]
        firsts = [next(each, None) for each in packets]
        sources = [
            chain([] if first is None else [first], each)
            for first, each in zip(firsts, packets, strict=True)
        ]
        stream, name = open_output(output)
        if name != "standard output":
            stack.enter_context(stream)
        # A pcap file has one resolution for every packet, so it counts in
        # nanoseconds unless every file starts out counting in microseconds.
        nanoseconds = any(
            first.interface is not None and first.interface.units_per_second != MICROSECONDS
            for first in firsts
            if first is not None
        )
        writer = open_writer(stream, file_format, nanoseconds=nanoseconds)
        ordered = chain(*sources) if concatenate else merge(sources)
        with write_errors(name):
            for packet in ordered:
                writer.write(packet)
            writer.close()
    return Exit.OK


def _labelled(capture: CaptureFile) -> Iterator[Packet]:
    """The capture's packets, with a read error saying which file it was in."""
    try:
        yield from capture
    except CaptureFileError as error:
        raise CommandError(Exit.READ_ERROR, f"{capture.path}: {error}") from None
