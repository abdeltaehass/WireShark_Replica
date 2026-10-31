"""The packet detail view: one protocol tree, printed like Wireshark's."""

from typing import TextIO

from pilotfish.core.dissect import Node, ProtocolTree
from pilotfish.core.dissect.text import node_text

INDENT = "    "


def write_tree(tree: ProtocolTree, out: TextIO) -> None:
    """Print every layer, with its fields indented under it."""
    for layer in tree.layers:
        out.write(f"{layer.summary or layer.label}\n")
        for node in layer.children:
            _write_node(node, out, depth=1)
    if tree.error is not None:
        out.write(f"[Malformed packet: {tree.error}]\n")


def _write_node(node: Node, out: TextIO, depth: int) -> None:
    out.write(f"{INDENT * depth}{node_text(node)}\n")
    for child in node.children:
        _write_node(child, out, depth + 1)
