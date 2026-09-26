"""Compare what pilotfish decodes with what tshark decodes, packet by packet.

Only the frame layer exists so far, so that is all this compares. The
protocols of the next phases plug into the same harness: every field tshark
reports is in the answer key already.
"""

from pathlib import Path

import pytest

import tshark
from pilotfish.core.dissect import dissect
from pilotfish.core.formats import CaptureFile

CAPTURES = tshark.captures_with_keys()
DNS = tshark.SAMPLES_DIR / "wireshark-wiki" / "dns.cap"


def sample_id(capture: Path) -> str:
    return str(capture.relative_to(tshark.SAMPLES_DIR))


def test_the_samples_have_answer_keys() -> None:
    assert len(CAPTURES) >= 10


class TestTheHarness:
    """The answer key has to be read right before it can be compared against."""

    def test_fields_come_out_by_name(self) -> None:
        first = tshark.packets(DNS)[0]
        assert first["frame.number"] == ["1"]
        assert first["ip.src"] == ["192.168.170.8"]
        assert first["dns.qry.name"] == ["google.com"]

    def test_fields_inside_a_subtree_are_found_too(self) -> None:
        # tshark nests eth.dst.oui under an eth.dst_tree object.
        assert tshark.packets(DNS)[0]["eth.dst.oui"] == ["49311"]

    def test_a_field_can_appear_more_than_once(self) -> None:
        # A frame has two Ethernet addresses, both reported as eth.addr.
        assert tshark.packets(DNS)[1]["eth.addr"] == [
            "00:e0:18:b1:0c:ad",
            "00:c0:9f:32:41:8c",
        ]

    @pytest.mark.parametrize(
        ("text", "nanoseconds"),
        [
            ("2005-03-30T08:47:46.496046000Z", 1112172466496046000),
            ("1112172466.496046000", 1112172466496046000),
            ("-0.500000000", -500000000),
            ("", None),
        ],
    )
    def test_times_parse_from_either_form(self, text: str, nanoseconds: int | None) -> None:
        assert tshark.parse_time(text) == nanoseconds


@pytest.mark.parametrize("capture", CAPTURES, ids=sample_id)
def test_frame_fields_match_tshark(capture: Path) -> None:
    expected = tshark.packets(capture)
    with CaptureFile(capture) as file:
        packets = list(file)
        trees = [dissect(packet, number) for number, packet in enumerate(packets, start=1)]
    assert len(trees) == len(expected)
    for packet, tree, fields in zip(packets, trees, expected, strict=True):
        hidden = tshark.WIRESHARK_PSEUDO_HEADER_BYTES.get(packet.link_type, 0)
        assert tree.get("frame.number") == int(fields["frame.number"][0])
        assert tree.get("frame.len") == int(fields["frame.len"][0]) + hidden
        assert tree.get("frame.cap_len") == int(fields["frame.cap_len"][0]) + hidden
        assert tree.get("frame.time_epoch") == tshark.parse_time(fields["frame.time_epoch"][0])


# The frame lengths have a test of their own above, which allows for the
# pseudo-headers Wireshark moves out of the packet for some link types.
# Data is whatever a dissector couldn't decode, so it means different things
# to each tool wherever tshark decodes a link type pilotfish doesn't.
SKIPPED = ("frame.len", "frame.cap_len", "data.data", "data.len")


@pytest.mark.parametrize("capture", CAPTURES, ids=sample_id)
def test_every_field_matches_tshark(capture: Path) -> None:
    expected = tshark.packets(capture)
    with CaptureFile(capture) as file:
        for number, (packet, fields) in enumerate(zip(file, expected, strict=True), start=1):
            tree = dissect(packet, number)
            assert tree.error is None, f"packet {number} of {capture.name}"
            tshark.compare(tree, fields, skip=SKIPPED)


@pytest.mark.parametrize("capture", CAPTURES, ids=sample_id)
def test_the_layers_match_tshark_as_far_as_they_go(capture: Path) -> None:
    """Every layer pilotfish decodes is the one tshark decoded there too.

    tshark goes deeper, into protocols of later phases, so what pilotfish
    found has to be the start of what tshark found rather than all of it.
    """
    expected = tshark.packets(capture)
    with CaptureFile(capture) as file:
        for number, (packet, fields) in enumerate(zip(file, expected, strict=True), start=1):
            theirs = [
                name
                for name in fields["frame.protocols"][0].split(":")
                # A pseudo-layer for the value that chose the next protocol.
                if name not in {"ethertype", "data"}
            ]
            ours = [name for name in dissect(packet, number).protocols if name != "data"][1:]
            assert ours == theirs[: len(ours)], f"packet {number} of {capture.name}"
