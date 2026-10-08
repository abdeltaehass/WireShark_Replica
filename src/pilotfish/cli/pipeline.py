"""What happens to each packet, wherever it came from.

Reading a file and capturing live differ only in where packets come from.
From there on both hand each one to a :class:`Pipeline`, which decodes it,
asks the display filter about it, and passes the ones that match to the
printer and to the capture file being written.
"""

import sys
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from typing import BinaryIO, Protocol, TextIO

from pilotfish.cli.detail import write_tree
from pilotfish.cli.hexdump import write_hex
from pilotfish.cli.status import CommandError, Exit
from pilotfish.cli.table import PacketTable, TimeFormat
from pilotfish.core.display import DisplayFilter
from pilotfish.core.dissect import ProtocolTree, Session, dissect
from pilotfish.core.formats import CaptureWriter, WriteError
from pilotfish.core.packet import Packet


class Printer(Protocol):
    """One way of printing packets: the packet list, JSON, fields."""

    def begin(self) -> None:
        """Called before the first packet, even if none come."""
        ...

    def packet(self, number: int, packet: Packet, tree: ProtocolTree) -> None: ...

    def end(self) -> None:
        """Called after the last packet, however the run ended."""
        ...


class TextPrinter:
    """The text output: the packet list, or each packet's protocol tree with
    ``-V``, its bytes in hexadecimal with ``-x``, or both."""

    def __init__(
        self,
        out: TextIO,
        time_format: TimeFormat = "epoch",
        *,
        tree: bool = False,
        hex_dump: bool = False,
    ) -> None:
        self._out = out
        self._table = PacketTable(out, time_format)
        self._tree = tree
        self._hex = hex_dump

    @property
    def _listing(self) -> bool:
        return not (self._tree or self._hex)

    def begin(self) -> None:
        if self._listing:
            self._table.write_header()

    def packet(self, number: int, packet: Packet, tree: ProtocolTree) -> None:
        if self._listing:
            self._table.write_row(number, packet, tree)
            return
        # A blank line after a tree and after a dump, which is where tshark
        # puts them, so the two print the same.
        if self._tree:
            write_tree(tree, self._out)
            self._out.write("\n")
        if self._hex:
            write_hex(tree, packet.data, self._out)
            self._out.write("\n")

    def end(self) -> None:
        pass


class Pipeline:
    """Decodes packets, filters them, and prints and writes the ones that pass.

    One session holds what earlier packets said, so the packets passed over
    still count towards what later ones mean: a retransmission is one
    whether or not the display filter lets the original through. A packet
    is only decoded at all if something needs its tree, so writing a capture
    straight to a file costs no decoding.
    """

    def __init__(
        self,
        out: TextIO,
        *,
        display: DisplayFilter | None = None,
        printer: Printer | None = None,
        writer: CaptureWriter | None = None,
        writing_to: str = "",
        flush_each: bool = False,
    ) -> None:
        self._out = out
        self._display = display
        self._printer = printer
        self._writer = writer
        self._writing_to = writing_to
        self._flush_each = flush_each
        self._session = Session()
        self._decode = display is not None or printer is not None

    def begin(self) -> None:
        if self._printer is not None:
            self._printer.begin()

    def packet(self, number: int, packet: Packet) -> bool:
        """Handle one packet, and say whether it passed the display filter."""
        tree = ProtocolTree()
        if self._decode:
            tree = dissect(packet, number, session=self._session)
            if self._display is not None and not self._display.matches(tree, packet.data):
                return False
        if self._writer is not None:
            with self._writing():
                self._writer.write(packet)
        if self._printer is not None:
            self._printer.packet(number, packet, tree)
        if self._flush_each:
            self.flush()
        return True

    def flush(self) -> None:
        """Send on what has been printed and written so far."""
        self._out.flush()
        if self._writer is not None:
            with self._writing():
                self._writer.flush()

    def end(self) -> None:
        """Finish the output, so that it is whole even when the input wasn't."""
        if self._printer is not None:
            self._printer.end()
        if self._writer is not None:
            with self._writing():
                self._writer.close()
        self._out.flush()

    def _writing(self) -> AbstractContextManager[None]:
        return write_errors(self._writing_to)


@contextmanager
def write_errors(name: str) -> Iterator[None]:
    """Turn a failure to write the capture file into the exit status for one.

    A reader at the other end of a pipe going away is something else, and
    is left for the caller to deal with.
    """
    try:
        yield
    except BrokenPipeError:
        raise
    except OSError as error:
        raise CommandError(Exit.WRITE_ERROR, f"{name}: {error.strerror or error}") from error
    except WriteError as error:
        raise CommandError(Exit.WRITE_ERROR, f"{name}: {error}") from error


def open_output(path: str) -> tuple[BinaryIO, str]:
    """The stream to write a capture file to, and what to call it in messages.

    ``-`` is standard output, so a capture can be piped into another program.
    """
    if path == "-":
        return sys.stdout.buffer, "standard output"
    try:
        # The caller closes it.
        return open(path, "wb"), path
    except OSError as error:
        raise CommandError(Exit.OPEN_ERROR, f"{path}: {error.strerror or error}") from None
