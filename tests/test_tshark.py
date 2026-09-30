"""Compare what pilotfish decodes with what tshark decodes, packet by packet.

Only the frame layer exists so far, so that is all this compares. The
protocols of the next phases plug into the same harness: every field tshark
reports is in the answer key already.
"""

from pathlib import Path

import pytest

import pilotfish.core.protocols  # noqa: F401  (registers the dissectors)
import tshark
from pilotfish.core.dissect import REGISTRY, FieldType, ProtocolTree, Session, dissect
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
    session = Session()
    with CaptureFile(capture) as file:
        for number, (packet, fields) in enumerate(zip(file, expected, strict=True), start=1):
            tree = dissect(packet, number, session=session)
            assert tree.error is None, f"packet {number} of {capture.name}"
            tshark.compare(tree, fields, skip=SKIPPED)


# What a TCP connection's history says about a segment, rather than what the
# segment says about itself.
ANALYSIS_FLAGS = tuple(
    field.name
    for field in REGISTRY.fields
    if field.name.startswith("tcp.analysis.") and field.type is FieldType.BOOL
)


def analysis_flags(fields: tshark.Fields | object) -> set[str]:
    return {name for name in ANALYSIS_FLAGS if name in fields}  # type: ignore[operator]


def test_the_samples_raise_every_analysis_flag() -> None:
    """The comparison below is only worth having if the samples exercise it."""
    raised = {
        name
        for capture in CAPTURES
        for fields in tshark.packets(capture)
        for name in analysis_flags(fields)
    }
    assert raised == set(ANALYSIS_FLAGS)


@pytest.mark.parametrize("capture", CAPTURES, ids=sample_id)
def test_the_tcp_analysis_matches_tshark(capture: Path) -> None:
    """Every judgement about a TCP connection agrees with Wireshark's.

    These aren't read out of a packet: they come from what the connection has
    done so far, so a flag pilotfish failed to raise matters as much as one it
    raised wrongly. The comparison above only sees the fields pilotfish
    decoded, so here the whole set is compared, packet for packet.
    """
    expected = tshark.packets(capture)
    session = Session()
    with CaptureFile(capture) as file:
        for number, (packet, fields) in enumerate(zip(file, expected, strict=True), start=1):
            tree = dissect(packet, number, session=session)
            where = f"packet {number} of {capture.name}"
            assert analysis_flags(tree) == analysis_flags(fields), where
            for name in ("tcp.analysis.duplicate_ack_num", "tcp.analysis.duplicate_ack_frame"):
                theirs = fields.get(name)
                assert tree.get(name) == (int(theirs[0]) if theirs else None), f"{name}, {where}"


@pytest.mark.parametrize("capture", CAPTURES, ids=sample_id)
def test_the_layers_match_tshark_as_far_as_they_go(capture: Path) -> None:
    """Every layer pilotfish decodes is the one tshark decoded there too.

    Neither list has to reach as far as the other. tshark goes deeper, into
    protocols of later phases. It can also stop short: a message split across
    several packets is put back together and reported against the packet that
    completes it, so the packet that starts one is left as plain TCP, while
    pilotfish decodes the part it holds where it holds it. Reassembly is the
    next phase, and it moves pilotfish's answer to the same packet as
    Wireshark's. What neither of them may do is disagree about a layer.
    """
    expected = tshark.packets(capture)
    session = Session()
    with CaptureFile(capture) as file:
        for number, (packet, fields) in enumerate(zip(file, expected, strict=True), start=1):
            theirs = [
                name
                for name in fields["frame.protocols"][0].split(":")
                # A pseudo-layer for the value that chose the next protocol.
                if name not in {"ethertype", "data"}
            ]
            decoded = dissect(packet, number, session=session)
            ours = [name for name in decoded.protocols if name != "data"][1:]
            shared = min(len(ours), len(theirs))
            assert ours[:shared] == theirs[:shared], f"packet {number} of {capture.name}"


# What a DNS answer can hold, by the field the value lands in.
ANSWERS = (
    "dns.a",
    "dns.aaaa",
    "dns.cname",
    "dns.ns",
    "dns.ptr.domain_name",
    "dns.mx.mail_exchange",
    "dns.srv.target",
    "dns.txt",
)

SERVER_NAME = "tls.handshake.extensions_server_name"


def asked_and_answered(fields: tshark.Fields | ProtocolTree) -> tuple[list[str], list[str]]:
    """Every name asked about in a packet, and everything it was told."""
    if isinstance(fields, ProtocolTree):
        questions = [str(value) for value in fields.values("dns.qry.name")]
        answers = [str(value) for name in ANSWERS for value in fields.values(name)]
        return questions, answers
    questions = list(fields.get("dns.qry.name", []))
    return questions, [value for name in ANSWERS for value in fields.get(name, [])]


@pytest.mark.parametrize("capture", CAPTURES, ids=sample_id)
def test_every_dns_answer_and_tls_server_name_matches_tshark(capture: Path) -> None:
    """The phase's own measure: what was asked, what came back, and who was asked for.

    Every DNS question in a capture, with the answers it was given, and every
    server name a TLS client asked for, packet by packet and in both
    directions: a query pilotfish missed fails this as surely as one it read
    wrongly.
    """
    expected = tshark.packets(capture)
    session = Session()
    with CaptureFile(capture) as file:
        for number, (packet, fields) in enumerate(zip(file, expected, strict=True), start=1):
            tree = dissect(packet, number, session=session)
            where = f"packet {number} of {capture.name}"
            assert asked_and_answered(tree) == asked_and_answered(fields), where
            names = [str(value) for value in tree.values(SERVER_NAME)]
            assert names == list(fields.get(SERVER_NAME, [])), f"{SERVER_NAME}, {where}"


def test_the_samples_hold_dns_answers_and_tls_server_names() -> None:
    """The comparison above is only worth having if the samples exercise it."""
    questions = answers = names = 0
    for capture in CAPTURES:
        for fields in tshark.packets(capture):
            asked, told = asked_and_answered(fields)
            questions += len(asked)
            answers += len(told)
            names += len(fields.get(SERVER_NAME, []))
    assert questions >= 40
    assert answers >= 30
    assert names >= 6
