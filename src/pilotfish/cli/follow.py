"""``pilotfish follow``: print one TCP connection as the conversation it was."""

import sys
from pathlib import Path
from typing import BinaryIO, Literal, TextIO

from pilotfish.core.follow import Chunk, FollowedStream, follow_tcp_stream
from pilotfish.core.formats import CaptureFile, CaptureFileError
from pilotfish.core.protocols.conversations import Endpoint

type Side = Literal["client", "server"]

SIDES: tuple[Side, ...] = ("client", "server")

_PRINTABLE = frozenset(range(0x20, 0x7F)) | {0x09, 0x0A, 0x0D}


def run(
    path: Path,
    index: int,
    *,
    raw: Side | None = None,
    out: TextIO | None = None,
    binary: BinaryIO | None = None,
) -> int:
    """Print a stream's conversation, each end's turns marked.

    With ``raw``, write one end's bytes exactly as they were sent and nothing
    else, so the output can be saved or hashed.
    """
    try:
        with CaptureFile(path) as capture:
            stream = follow_tcp_stream(capture, index)
    except (OSError, CaptureFileError) as error:
        reason = error.strerror if isinstance(error, OSError) and error.strerror else str(error)
        print(f"pilotfish: {path}: {reason}", file=sys.stderr)
        return 1
    except LookupError as error:
        print(f"pilotfish: {path}: {error}", file=sys.stderr)
        return 1
    if raw is not None:
        binary = binary or sys.stdout.buffer
        binary.write(stream.from_client if raw == "client" else stream.from_server)
        binary.flush()
        return 0
    write_conversation(stream, out or sys.stdout)
    return 0


def write_conversation(stream: FollowedStream, out: TextIO) -> None:
    """The conversation as text, with a line saying who is speaking each time."""
    out.write(f"TCP stream {stream.index}\n")
    out.write(f"client  {endpoint(stream.client)}\n")
    out.write(f"server  {endpoint(stream.server)}\n")
    for chunk in stream.chunks:
        out.write(f"\n{_heading(chunk)}\n")
        text = as_text(chunk.data)
        out.write(text if text.endswith("\n") else f"{text}\n")


def _heading(chunk: Chunk) -> str:
    who = "client > server" if chunk.from_client else "server > client"
    heading = f"{who}, {len(chunk.data)} bytes"
    if chunk.missed:
        heading += f", after {chunk.missed} bytes missing from the capture"
    return heading


def endpoint(end: Endpoint) -> str:
    """An address and port, with an IPv6 address in brackets so the colons
    can't be mistaken for the one before the port."""
    address, port = end
    text = str(address)
    return f"[{text}]:{port}" if ":" in text else f"{text}:{port}"


def as_text(data: bytes) -> str:
    """Bytes as Wireshark shows them in its text view: what is printable as
    itself, and a dot for everything else."""
    return "".join(chr(byte) if byte in _PRINTABLE else "." for byte in data).replace("\r\n", "\n")
