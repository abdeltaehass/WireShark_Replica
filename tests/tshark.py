"""tshark's own decoding of a capture, as the answer key for the dissectors.

``scripts/update_answer_keys.py`` records ``tshark -T json`` for each sample
as ``<capture>.tshark.json.gz``, so the tests don't need Wireshark installed.
Where a capture has no key recorded, tshark runs here if it's on the machine,
and the test is skipped if it isn't.

tshark reports every field as text, so a comparison turns pilotfish's values
into the same text rather than the other way round.
"""

import gzip
import json
import shutil
import subprocess
from collections.abc import Container
from datetime import UTC, datetime
from functools import cache
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path
from typing import Any

import pytest

from pilotfish.core.dissect import REGISTRY, Field, FieldType, ProtocolTree, Value

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
CAPTURE_SUFFIXES = frozenset({".cap", ".ntar", ".pcap", ".pcapng"})

# For some link types Wireshark moves a fixed-size pseudo-header out of the
# packet and into metadata, so its frame.len and frame.cap_len leave it out.
# pilotfish reports the lengths stored in the file, as libpcap and tcpdump do.
WIRESHARK_PSEUDO_HEADER_BYTES = {144: 16}  # LINKTYPE_LINUX_IRDA

# tshark lists pcapng Custom Blocks as frames even though they aren't packets.
TSHARK_FILTER = "not frame.cb_pen"

type Fields = dict[str, list[str]]
"""One packet's fields, by name. A field can appear more than once."""


def answer_key(capture: Path) -> Path:
    return capture.with_name(f"{capture.name}.tshark.json.gz")


def captures_with_keys() -> list[Path]:
    """Every sample whose tshark decoding has been recorded."""
    return sorted(
        key.with_name(key.name.removesuffix(".tshark.json.gz"))
        for key in SAMPLES_DIR.rglob("*.tshark.json.gz")
    )


@cache
def packets(capture: Path) -> tuple[Fields, ...]:
    """Every packet's fields, as tshark decodes them."""
    key = answer_key(capture)
    if key.exists():
        recorded = gzip.decompress(key.read_bytes()).decode()
    elif shutil.which("tshark"):
        recorded = run_tshark(capture)
    else:
        pytest.skip(f"{key.name} hasn't been recorded and tshark isn't installed")
    return tuple(fields_of(entry) for entry in json.loads(recorded, object_pairs_hook=_merge))


def _merge(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Keep every value of a repeated field.

    tshark writes a field that appears more than once in a packet as repeated
    keys of the same JSON object, which a plain parse would collapse to the
    last one, losing every option but the last of its kind.
    """
    merged: dict[str, Any] = {}
    for key, value in pairs:
        if key not in merged:
            merged[key] = value
        elif isinstance(merged[key], list):
            merged[key].append(value)
        else:
            merged[key] = [merged[key], value]
    return merged


def run_tshark(capture: Path) -> str:
    result = subprocess.run(
        # The same preferences scripts/update_answer_keys.py records with.
        [
            *["tshark", "-n", "-r", capture.name, "-Y", TSHARK_FILTER, "-T", "json"],
            *["-o", "ip.check_checksum:TRUE"],
            *["-o", "udp.check_checksum:TRUE"],
            *["-o", "tcp.check_checksum:TRUE"],
        ],
        cwd=capture.parent,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        pytest.fail(f"tshark failed on {capture.name}:\n{result.stderr}")
    return result.stdout


def fields_of(entry: dict[str, Any]) -> Fields:
    """Flatten one packet's layers and subtrees into fields by name."""
    fields: Fields = {}

    def walk(node: dict[str, Any]) -> None:
        for name, value in node.items():
            match value:
                case dict():
                    walk(value)
                case list():
                    for each in value:
                        walk(each) if isinstance(each, dict) else add(name, each)
                case _:
                    add(name, value)

    def add(name: str, value: object) -> None:
        fields.setdefault(name, []).append(str(value))

    walk(entry["_source"]["layers"])
    return fields


def parse_time(text: str) -> int | None:
    """Nanoseconds since the epoch, from either form tshark prints a time in.

    The fields output gives decimal seconds, ``1112172466.496046000``. The
    JSON output gives UTC, ``2005-03-30T08:47:46.496046000Z``.
    """
    if text in {"", "n/a"}:
        return None
    if "T" in text:
        stamp, _, fraction = text.rstrip("Z").partition(".")
        moment = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC)
        return int(moment.timestamp()) * 1_000_000_000 + int(fraction.ljust(9, "0"))
    sign = -1 if text.startswith("-") else 1
    seconds, _, fraction = text.removeprefix("-").partition(".")
    return sign * (int(seconds) * 1_000_000_000 + int(fraction.ljust(9, "0")))


def as_value(field: Field, text: str) -> Value:
    """tshark's text for a field, turned into the value pilotfish holds.

    tshark prints everything as text, and numbers in whichever base the field
    is usually read in, so the comparison happens on values rather than on
    two different spellings of the same number.
    """
    match field.type:
        case FieldType.INT:
            return int(text)
        case FieldType.UINT:
            return int(text, 0) if text.lower().startswith("0x") else int(text)
        case FieldType.BOOL:
            # Wireshark writes a flag as an item with nothing in it, so its
            # being there at all is what says the flag is set.
            return True if text == "" else bool(int(text, 0))
        case FieldType.IPV4:
            return IPv4Address(text)
        case FieldType.IPV6:
            return IPv6Address(text)
        case FieldType.BYTES:
            return bytes.fromhex(text.replace(":", ""))
        case FieldType.TIME:
            return parse_time(text) or 0
        case _:
            return text


def compare(tree: ProtocolTree, expected: Fields, skip: Container[str] = ()) -> None:
    """Check every field pilotfish decoded that tshark decoded as well.

    Fields tshark reports and pilotfish doesn't are left alone: they belong to
    protocols of a later phase, or are values Wireshark works out rather than
    reads. Anything pilotfish claims, though, has to agree.
    """
    names = {
        node.name
        for node in tree.walk()
        if node.value is not None and node.name in expected and node.name not in skip
    }
    ours: dict[str, object] = {}
    theirs: dict[str, object] = {}
    for name in names:
        values = [
            node.value for node in tree.walk() if node.name == name and node.value is not None
        ]
        texts = expected[name]
        if all(text == "" for text in texts):
            # Wireshark can write the same flag twice for one packet, once in
            # its analysis tree and once as expert information, so for these
            # it is whether the flag is there that is compared.
            ours[name], theirs[name] = set(values), {True}
            continue
        # tshark writes a field that repeats as repeated keys of one JSON
        # object, and merging those gathers them all where the first one was,
        # which loses the order they came in. So for these it is the values
        # and how many of each that are compared, not the order.
        ours[name] = sorted(values, key=repr)
        theirs[name] = sorted((as_value(REGISTRY.fields[name], text) for text in texts), key=repr)
    assert ours == theirs
