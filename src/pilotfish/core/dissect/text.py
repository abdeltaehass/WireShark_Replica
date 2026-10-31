"""A protocol tree's rows as text, the way Wireshark's detail pane words them.

The command line prints these lines and the desktop app shows them in its
tree, so a field reads the same in both.
"""

from pilotfish.core.dissect.fields import FieldType, Value
from pilotfish.core.dissect.tree import Node
from pilotfish.core.timestamps import format_epoch

_BYTES_SHOWN = 32
"""How many bytes of a long field to show before cutting it short."""

# How the tree writes characters that would otherwise break its line, as
# Wireshark's detail pane and tshark -V write them: an HTTP header shows
# the \r\n that ends it rather than ending the row.
_ESCAPES = {
    "\a": "\\a",
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
    "\v": "\\v",
}


def node_text(node: Node) -> str:
    """One row of the tree: a layer's summary, or a field's label and value."""
    if node.type is FieldType.PROTOCOL:
        return node.summary or node.label
    shown = format_value(node.type, node.value, node.hex, node.digits or node.length * 2)
    if node.type is FieldType.STRING:
        shown = escaped(shown)
    return f"{node.label}: {shown}"


def escaped(text: str) -> str:
    """Text with its control characters written out, so it stays on one line."""
    if text.isprintable():
        return text
    return "".join(_ESCAPES.get(char) or _escape(char) for char in text)


def _escape(char: str) -> str:
    if char.isprintable():
        return char
    code = ord(char)
    return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"


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
