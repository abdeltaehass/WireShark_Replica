"""Packets as data for other programs: ``-T json`` and ``-T fields``.

Both follow tshark's layout, so what was written to read tshark's output
reads pilotfish's. JSON is an array with one object per packet, its layers
under ``_source.layers``, each field's value as text, and the fields inside a
field under ``<name>_tree``. Fields output is one line per packet with a
column for each ``-e``.

tshark writes a field that appears twice in a packet as two keys of the same
name, which most JSON readers keep only the last of. pilotfish writes the
values as a list instead, as tshark does when asked with
``--no-duplicate-keys``.
"""

import json
import textwrap
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, TextIO

from pilotfish.cli.detail import format_value
from pilotfish.cli.status import CommandError, Exit
from pilotfish.cli.table import DESTINATIONS, SOURCES, TimeFormat, address, protocol, summary
from pilotfish.core.dissect import FieldRegistry, FieldType, Node, ProtocolTree
from pilotfish.core.packet import Packet
from pilotfish.core.timestamps import NS_PER_SECOND, format_epoch, format_utc

type Column = Callable[[int, Packet, ProtocolTree], str]

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def tree_text(node: Node) -> str:
    """A field's value as the JSON tree writes it: flags as 1 or 0, bytes
    as hexadecimal with colons between them."""
    if node.type is FieldType.BOOL:
        return "1" if node.value else "0"
    if isinstance(node.value, bytes):
        return node.value.hex(":")
    return field_text(node)


def field_text(node: Node) -> str:
    """A field's value as ``-T fields`` writes it: flags as True or False,
    bytes as hexadecimal run together, and a protocol as its summary."""
    value = node.value
    if value is None:
        return node.summary or node.label
    if node.type is FieldType.BOOL:
        return str(bool(value))
    if isinstance(value, bytes):
        return value.hex()
    return format_value(node.type, value, node.hex, node.digits or node.length * 2)


def layers(tree: ProtocolTree) -> dict[str, Any]:
    """Every layer of the tree as JSON, by protocol name."""
    found: dict[str, Any] = {}
    for layer in tree.layers:
        _add(found, layer.name, _members(layer.children))
    return found


def _members(nodes: Sequence[Node]) -> dict[str, Any]:
    found: dict[str, Any] = {}
    for node in nodes:
        _add(found, node.name, tree_text(node))
        if node.children:
            _add(found, f"{node.name}_tree", _members(node.children))
    return found


def _add(found: dict[str, Any], name: str, value: Any) -> None:
    """Add a value under ``name``, turning the entry into a list the second time."""
    if name not in found:
        found[name] = value
    elif isinstance(found[name], list):
        found[name].append(value)
    else:
        found[name] = [found[name], value]


def _time(time_format: TimeFormat) -> Column:
    format_time = format_utc if time_format == "utc" else format_epoch

    def column(number: int, packet: Packet, tree: ProtocolTree) -> str:
        return "" if packet.timestamp_ns is None else format_time(packet.timestamp_ns)

    return column


def _columns(time_format: TimeFormat) -> dict[str, Column]:
    """The packet list's columns, under the names tshark gives them."""
    return {
        "_ws.col.number": lambda number, packet, tree: str(number),
        "_ws.col.cls_time": _time(time_format),
        "_ws.col.def_src": lambda number, packet, tree: address(tree, SOURCES),
        "_ws.col.def_dst": lambda number, packet, tree: address(tree, DESTINATIONS),
        "_ws.col.protocol": lambda number, packet, tree: protocol(tree),
        "_ws.col.packet_length": lambda number, packet, tree: str(packet.original_length),
        "_ws.col.info": lambda number, packet, tree: summary(tree),
    }


class FieldPicker:
    """The values of the fields ``-e`` names, packet by packet.

    A name can be a field, a protocol, a field that stands for two such as
    ``ip.addr``, or one of the packet list's columns, such as
    ``_ws.col.info``.
    """

    def __init__(
        self, names: Sequence[str], fields: FieldRegistry, time_format: TimeFormat = "epoch"
    ) -> None:
        columns = _columns(time_format)
        unknown = [name for name in names if name not in fields and name.lower() not in columns]
        if unknown:
            raise CommandError(Exit.INVALID_OPTION, "some fields aren't valid:", tuple(unknown))
        self.names = tuple(names)
        self._wanted: dict[str, list[int]] = {}
        """Which of the requested names each node name supplies values for."""
        self._columns: dict[int, Column] = {}
        for index, name in enumerate(names):
            if name.lower() in columns:
                self._columns[index] = columns[name.lower()]
                continue
            for each in fields.found_as(name):
                self._wanted.setdefault(each, []).append(index)

    def pick(self, number: int, packet: Packet, tree: ProtocolTree) -> list[list[str]]:
        """Every value of each requested field, in the order they are in the tree."""
        values: list[list[str]] = [[] for _ in self.names]
        for node in tree.walk():
            for index in self._wanted.get(node.name, ()):
                values[index].append(field_text(node))
        for index, column in self._columns.items():
            values[index] = [column(number, packet, tree)]
        return values


class JsonPrinter:
    """``-T json``: an array of packets, written as they come.

    The array is closed when the output ends, however it ends, so what has
    been written is valid JSON even after a capture is stopped with Ctrl+C.
    """

    def __init__(self, out: TextIO, picker: FieldPicker | None = None) -> None:
        self._out = out
        self._picker = picker
        self._written = 0

    def begin(self) -> None:
        self._out.write("[")

    def packet(self, number: int, packet: Packet, tree: ProtocolTree) -> None:
        if self._picker is None:
            found = layers(tree)
        else:
            picked = self._picker.pick(number, packet, tree)
            found = {
                name: values
                for name, values in zip(self._picker.names, picked, strict=True)
                if values
            }
        entry = {"_index": index_name(packet), "_score": None, "_source": {"layers": found}}
        text = json.dumps(entry, indent=2, ensure_ascii=False)
        self._out.write(("," if self._written else "") + "\n" + textwrap.indent(text, "  "))
        self._written += 1

    def end(self) -> None:
        self._out.write("\n]\n" if self._written else "]\n")


def index_name(packet: Packet) -> str:
    """The ``_index`` tshark gives a packet: the day it was captured on."""
    seconds = (packet.timestamp_ns or 0) // NS_PER_SECOND
    try:
        day = _EPOCH + timedelta(seconds=seconds)
    except OverflowError:
        day = _EPOCH
    return f"packets-{day:%Y-%m-%d}"


@dataclass(slots=True)
class FieldsFormat:
    """How ``-T fields`` lays its values out, set with ``-E``."""

    header: bool = False
    """Whether the first line names the fields."""
    separator: str = "\t"
    """What goes between one field and the next."""
    occurrence: str = "a"
    """Which value of a field that appears more than once: the first, the
    last, or all of them."""
    aggregator: str = ","
    """What goes between the values of a field when all of them are printed."""
    quote: str = ""
    """What goes around each value, if anything."""

    def set(self, option: str) -> None:
        """Apply one ``-E name=value``, as tshark spells them."""
        name, equals, value = option.partition("=")
        if not equals:
            raise _bad_option(option)
        match name, value:
            case "header", "y" | "n":
                self.header = value == "y"
            case "separator" | "aggregator", _ if value:
                character = {"/t": "\t", "/s": " "}.get(value, value)
                setattr(self, name, character)
            case "occurrence", "f" | "l" | "a":
                self.occurrence = value
            case "quote", "d" | "s" | "n":
                self.quote = {"d": '"', "s": "'", "n": ""}[value]
            case _:
                raise _bad_option(option)


def _bad_option(option: str) -> CommandError:
    return CommandError(
        Exit.INVALID_OPTION,
        f'"{option}" isn\'t a -E option; they are header=y|n, separator=/t|/s|CHARACTER, '
        "occurrence=f|l|a, aggregator=,|/s|CHARACTER and quote=d|s|n",
    )


class FieldsPrinter:
    """``-T fields``: one line per packet, a column for each ``-e``."""

    def __init__(self, out: TextIO, picker: FieldPicker, layout: FieldsFormat) -> None:
        self._out = out
        self._picker = picker
        self._layout = layout

    def begin(self) -> None:
        if self._layout.header:
            self._out.write(self._layout.separator.join(self._picker.names) + "\n")

    def packet(self, number: int, packet: Packet, tree: ProtocolTree) -> None:
        layout = self._layout
        cells = []
        for values in self._picker.pick(number, packet, tree):
            if layout.occurrence == "f":
                values = values[:1]
            elif layout.occurrence == "l":
                values = values[-1:]
            cell = layout.aggregator.join(values)
            cells.append(f"{layout.quote}{cell}{layout.quote}" if values else "")
        self._out.write(layout.separator.join(cells) + "\n")

    def end(self) -> None:
        pass
