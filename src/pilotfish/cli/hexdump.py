"""The hex dump ``-x`` prints, laid out as tshark lays it out: each line an
offset, sixteen bytes in hexadecimal, and the same bytes as text."""

from collections.abc import Buffer
from typing import TextIO

from pilotfish.core.dissect import ProtocolTree

BYTES_PER_LINE = 16


def hex_dump(data: Buffer) -> str:
    """Sixteen bytes a line: the offset, the bytes in hexadecimal, and the
    bytes again as text, with a dot for anything that doesn't print."""
    view = bytes(data)
    # Four digits of offset, or as many as the last offset needs.
    width = max(4, len(f"{max(len(view) - 1, 0):x}"))
    lines = []
    for offset in range(0, len(view), BYTES_PER_LINE):
        line = view[offset : offset + BYTES_PER_LINE]
        hexadecimal = " ".join(f"{byte:02x}" for byte in line)
        text = "".join(chr(byte) if 0x20 <= byte < 0x7F else "." for byte in line)
        lines.append(f"{offset:0{width}x}  {hexadecimal:<{BYTES_PER_LINE * 3 - 1}}   {text}\n")
    return "".join(lines)


def write_hex(tree: ProtocolTree, data: Buffer, out: TextIO) -> None:
    """The packet's bytes, then any bytes it was reassembled into.

    A message put together from several packets is in none of them, so its
    bytes are dumped after the packet's own, each under a heading.
    """
    if not tree.sources:
        out.write(hex_dump(data))
        return
    out.write(f"Packet ({len(bytes(data))} bytes):\n")
    out.write(hex_dump(data))
    for source in tree.sources:
        out.write(f"{source.name} ({len(source.data)} bytes):\n")
        out.write(hex_dump(source.data))
