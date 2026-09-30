"""The packet detail view: one protocol tree, printed like Wireshark's."""

from typing import TextIO

from pilotfish.core.dissect import FieldType, Node, ProtocolTree, Value
from pilotfish.core.timestamps import format_epoch

INDENT = "    "
_BYTES_SHOWN = 32
"""How many bytes of a long field to print before cutting it short."""


def write_tree(tree: ProtocolTree, out: TextIO) -> None:
    """Print every layer, with its fields indented under it."""
    for layer in tree.layers:
        out.write(f"{layer.summary or layer.label}\n")
        for node in layer.children:
            _write_node(node, out, depth=1)
    if tree.error is not None:
        out.write(f"[Malformed packet: {tree.error}]\n")


def _write_node(node: Node, out: TextIO, depth: int) -> None:
    shown = format_value(node.type, node.value, node.hex, node.digits or node.length * 2)
    out.write(f"{INDENT * depth}{node.label}: {shown}\n")
    for child in node.children:
        _write_node(child, out, depth + 1)


def format_value(
    field_type: FieldType, value: Value | None, in_hex: bool = False, digits: int = 0
) -> str:
    """A field's value as the detail view shows it."""
    if value is None:
        return ""
    if field_type is FieldType.TIME and isinstance(value, int):
        return format_epoch(value)
    if in_hex and isinstance(value, int):
        # As wide as the bytes the field was read from, as Wireshark shows it,
        # falling back to what the value itself needs.
        needed = max(2, -(-value.bit_length() // 8) * 2)
        return f"0x{value:0{max(digits, needed)}x}"
    if field_type is FieldType.BOOL:
        return "Set" if value else "Not set"
    if isinstance(value, bytes):
        shown = value[:_BYTES_SHOWN].hex(":")
        return shown if len(value) <= _BYTES_SHOWN else f"{shown}… ({len(value)} bytes)"
    return str(value)
