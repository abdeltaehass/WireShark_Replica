"""Following a TCP stream, and the test this phase is measured by.

A file fetched over HTTP arrives as a run of segments. Following the stream
has to give that file back exactly, byte for byte, however the segments
arrived. A SHA-256 over the result is what says it did.
"""

import io
import re
import subprocess
import sys
from hashlib import sha256
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from packets import ethernet, ipv4, ipv6, tcp
from pilotfish.cli import follow as follow_command
from pilotfish.cli.main import main
from pilotfish.core.dissect import ProtocolTree, Session, dissect
from pilotfish.core.follow import Chunk, follow_tcp_stream
from pilotfish.core.formats import CaptureFile
from pilotfish.core.packet import Packet
from streams import ACK, CLIENT, PUSH, SERVER, Talk, captured, decode

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
DOWNLOAD = SAMPLES / "made" / "http-download.pcap"

DOWNLOAD_SHA256 = "4cfd36429b493d7232195a49be8270f51031a8bcc0878052b4c753eff45b9b85"
"""The digest scripts/make_test_captures.py prints for the file it puts in
the download capture."""

REQUEST = b"GET /file HTTP/1.1\r\nHost: example.com\r\n\r\n"


def the_file() -> bytes:
    """The file the download capture carries, built the way the script that
    made the capture builds it."""
    return b"".join(sha256(number.to_bytes(4, "big")).digest() for number in range(625))


def body_of(answer: bytes) -> bytes:
    """The body of the first HTTP response in a server's side of a stream."""
    head, _, rest = answer.partition(b"\r\n\r\n")
    length = re.search(rb"Content-Length: (\d+)", head)
    assert length is not None
    return rest[: int(length[1])]


def download_trees() -> list[ProtocolTree]:
    """Every packet of the download capture, decoded in order."""
    session = Session()
    with CaptureFile(DOWNLOAD) as capture:
        return [
            dissect(packet, number, session=session)
            for number, packet in enumerate(capture, start=1)
        ]


def answer_to(file: bytes) -> bytes:
    return b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(file) + file


class TestTheDownload:
    """The capture in samples/made: a 20,000-byte file, whose fourth segment
    overtakes its third and whose last is sent twice."""

    def test_following_the_stream_rebuilds_the_exact_file(self) -> None:
        with CaptureFile(DOWNLOAD) as capture:
            stream = follow_tcp_stream(capture, 0)
        rebuilt = body_of(stream.from_server)
        assert len(rebuilt) == 20000
        assert sha256(rebuilt).hexdigest() == DOWNLOAD_SHA256

    def test_the_digest_is_the_files_own(self) -> None:
        # Otherwise the test above would only prove the capture agrees with
        # a number written beside it.
        assert sha256(the_file()).hexdigest() == DOWNLOAD_SHA256

    def test_the_segments_did_not_arrive_in_order(self) -> None:
        # The file only comes back right if the reordering was undone, so
        # the capture has to hold some.
        trees = download_trees()
        assert any("tcp.analysis.lost_segment" in tree for tree in trees)
        assert any("tcp.analysis.spurious_retransmission" in tree for tree in trees)
        raw = b"".join(
            bytes(payload)  # type: ignore[arg-type]
            for tree in trees
            if tree.get("tcp.stream") == 0
            and tree.get("tcp.srcport") == 80
            and (payload := tree.get("tcp.payload")) is not None
        )
        assert sha256(body_of(raw)).hexdigest() != DOWNLOAD_SHA256

    def test_the_dissector_decodes_the_same_file(self) -> None:
        trees = download_trees()
        [download, notes, old] = [tree for tree in trees if "http.file_data" in tree]
        file = download.get("http.file_data")
        assert isinstance(file, bytes)
        assert sha256(file).hexdigest() == DOWNLOAD_SHA256
        assert download.get("frame.number") == 19
        # The compressed, chunked body, and the one that ran until the
        # server hung up.
        text = notes.get("http.file_data")
        assert isinstance(text, bytes)
        assert text.startswith(b"Line 001 of the notes.\n")
        assert text.count(b"\n") == 120
        assert old.get("frame.number") == 38

    def test_each_end_of_the_conversation_is_marked(self) -> None:
        with CaptureFile(DOWNLOAD) as capture:
            stream = follow_tcp_stream(capture, 0)
        assert stream.client == (IPv4Address("192.0.2.1"), 50010)
        assert stream.server == (IPv4Address("192.0.2.2"), 80)
        assert [chunk.from_client for chunk in stream.chunks] == [True, False, True, False]
        assert stream.chunks[0].data.startswith(b"GET /pilotfish.bin HTTP/1.1\r\n")
        assert stream.chunks[2].data.startswith(b"GET /notes.txt HTTP/1.1\r\n")
        assert all(chunk.missed == 0 for chunk in stream.chunks)

    def test_streams_are_numbered_as_the_tcp_dissector_numbers_them(self) -> None:
        with CaptureFile(DOWNLOAD) as capture:
            stream = follow_tcp_stream(capture, 1)
        assert stream.client == (IPv4Address("192.0.2.1"), 50011)
        assert stream.from_client.startswith(b"GET /old.txt HTTP/1.0\r\n")
        assert stream.from_server.endswith(b"line 40 and says nothing of how many follow.\n")

    def test_a_stream_the_capture_does_not_have(self) -> None:
        with CaptureFile(DOWNLOAD) as capture, pytest.raises(LookupError, match="no TCP stream 7"):
            follow_tcp_stream(capture, 7)


class TestSegmentsThatArriveAnyhow:
    @given(
        file=st.binary(min_size=1, max_size=12000),
        size=st.integers(50, 1460),
        order=st.randoms(use_true_random=False),
        repeats=st.integers(0, 6),
        overlaps=st.lists(st.tuples(st.integers(0, 12000), st.integers(1, 2000)), max_size=6),
    )
    def test_the_file_comes_back_exactly(
        self,
        file: bytes,
        size: int,
        order: object,
        repeats: int,
        overlaps: list[tuple[int, int]],
    ) -> None:
        # Every segment of a download, shuffled, with some sent twice and
        # some sent again cut at different places, as a sender that
        # repackages what it resends cuts them.
        talk = Talk()
        frames = [*talk.handshake(), *talk.send(REQUEST, from_client=True)]
        answer = answer_to(file)
        start = talk.next[False]
        arriving = talk.send(answer, from_client=False, size=size)
        arriving += arriving[:repeats]
        arriving += [
            talk.segment(answer[at : at + length], from_client=False, seq=start + at)
            for at, length in overlaps
            if at < len(answer)
        ]
        order.shuffle(arriving)  # type: ignore[attr-defined]
        frames += [*arriving, talk.acknowledge(from_client=True)]

        stream = follow_tcp_stream(captured(frames), 0)
        assert stream.from_client == REQUEST
        assert sha256(body_of(stream.from_server)).digest() == sha256(file).digest()

        # The dissector, reading the same stream, decodes the same file.
        [decoded] = [tree for tree in decode(frames) if "http.file_data" in tree]
        assert decoded.get("http.file_data") == file


class TestWhoIsTheClient:
    def test_the_end_that_sent_the_syn(self) -> None:
        talk = Talk()
        frames = [*talk.handshake(), talk.segment(b"hello", from_client=True)]
        stream = follow_tcp_stream(captured(frames), 0)
        assert stream.client == (IPv4Address(CLIENT), 50000)
        assert stream.chunks == (Chunk(True, b"hello"),)

    def test_a_capture_that_begins_with_the_answer_to_the_syn(self) -> None:
        talk = Talk()
        _, syn_ack, ack = talk.handshake()
        frames = [syn_ack, ack, talk.segment(b"hello", from_client=True)]
        stream = follow_tcp_stream(captured(frames), 0)
        assert stream.client == (IPv4Address(CLIENT), 50000)
        assert stream.server == (IPv4Address(SERVER), 80)
        assert stream.chunks == (Chunk(True, b"hello"),)

    def test_with_no_syn_it_is_whoever_spoke_first(self) -> None:
        talk = Talk()
        frames = [
            talk.segment(b"the server, mid-sentence", from_client=False),
            talk.segment(b"the client", from_client=True),
        ]
        stream = follow_tcp_stream(captured(frames), 0)
        assert stream.client == (IPv4Address(SERVER), 80)
        assert [chunk.from_client for chunk in stream.chunks] == [True, False]


class TestWhatAFollowedStreamHolds:
    def test_turns_are_joined_until_the_other_end_speaks(self) -> None:
        talk = Talk()
        frames = [
            *talk.handshake(),
            talk.segment(b"one ", from_client=True),
            talk.segment(b"two", from_client=True),
            talk.segment(b"three", from_client=False),
            talk.segment(b"four", from_client=True),
        ]
        stream = follow_tcp_stream(captured(frames), 0)
        assert stream.chunks == (
            Chunk(True, b"one two"),
            Chunk(False, b"three"),
            Chunk(True, b"four"),
        )
        assert stream.from_client == b"one twofour"

    def test_bytes_the_capture_never_saw_are_counted(self) -> None:
        talk = Talk()
        handshake = talk.handshake()
        first = talk.segment(b"a" * 100, from_client=False)
        # Sent and acknowledged, and missing from the capture.
        talk.segment(b"b" * 250, from_client=False)
        third = talk.segment(b"c" * 100, from_client=False)
        acknowledged = talk.acknowledge(from_client=True)
        stream = follow_tcp_stream(captured([*handshake, first, third, acknowledged]), 0)
        assert stream.chunks == (Chunk(False, b"a" * 100), Chunk(False, b"c" * 100, missed=250))

    def test_a_segment_sent_twice_is_heard_once(self) -> None:
        talk = Talk()
        handshake = talk.handshake()
        segment = talk.segment(b"once", from_client=True)
        stream = follow_tcp_stream(captured([*handshake, segment, segment, segment]), 0)
        assert stream.from_client == b"once"

    def test_only_the_stream_asked_for_is_followed(self) -> None:
        first, second = Talk(50000), Talk(50001)
        frames = [
            *first.handshake(),
            *second.handshake(),
            first.segment(b"first", from_client=True),
            second.segment(b"second", from_client=True),
        ]
        assert follow_tcp_stream(captured(frames), 0).from_client == b"first"
        assert follow_tcp_stream(captured(frames), 1).from_client == b"second"

    def test_a_connection_with_nothing_said(self) -> None:
        stream = follow_tcp_stream(captured(Talk().handshake()), 0)
        assert stream.chunks == ()
        assert stream.from_client == stream.from_server == b""

    def test_a_segment_that_was_itself_fragmented(self) -> None:
        # IP cut the segment in two, so the fragments are put together
        # first and the stream is followed through the result.
        said = bytes(range(256)) * 10
        segment = tcp(50000, 80, said, seq=1, flags=ACK | PUSH, source=CLIENT, destination=SERVER)
        frames = [
            ethernet(ipv4(segment[at : at + 1480], 6, at // 8, flags=int(at + 1480 < len(segment))))
            for at in range(0, len(segment), 1480)
        ]
        assert len(frames) == 2
        assert follow_tcp_stream(captured(frames), 0).from_client == said

    def test_a_stream_over_ipv6(self) -> None:
        segment = tcp(
            50000,
            80,
            b"over six",
            seq=1,
            flags=ACK | PUSH,
            source="2001:db8::1",
            destination="2001:db8::2",
        )
        frame = ethernet(ipv6(segment, 6), 0x86DD)
        stream = follow_tcp_stream([Packet(0, len(frame), 1, frame)], 0)
        assert stream.client == (IPv6Address("2001:db8::1"), 50000)
        assert stream.from_client == b"over six"


class TestTheCommand:
    def test_the_conversation_as_text(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["follow", str(DOWNLOAD), "1"]) == 0
        lines = capsys.readouterr().out.splitlines()
        assert lines[:9] == [
            "TCP stream 1",
            "client  192.0.2.1:50011",
            "server  192.0.2.2:80",
            "",
            "client > server, 44 bytes",
            "GET /old.txt HTTP/1.0",
            "Host: example.com",
            "",
            "",
        ]
        assert lines[9] == "server > client, 2725 bytes"
        assert lines[10] == "HTTP/1.0 200 OK"

    def test_one_end_raw_is_the_bytes_and_nothing_else(self) -> None:
        out = io.BytesIO()
        assert follow_command.run(DOWNLOAD, 0, raw="server", binary=out) == 0
        assert sha256(body_of(out.getvalue())).hexdigest() == DOWNLOAD_SHA256

    def test_raw_output_can_be_piped(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "pilotfish", "follow", str(DOWNLOAD), "0", "--raw", "client"],
            capture_output=True,
            check=True,
        )
        assert result.stdout.startswith(b"GET /pilotfish.bin HTTP/1.1\r\n")
        assert result.stdout.count(b"\r\n\r\n") == 2

    def test_bytes_that_are_not_text_are_shown_as_dots(self) -> None:
        assert follow_command.as_text(b"ok\x00\xff\r\nnext\ttab") == "ok..\nnext\ttab"

    def test_an_ipv6_address_is_bracketed(self) -> None:
        assert follow_command.endpoint((IPv6Address("2001:db8::1"), 443)) == "[2001:db8::1]:443"

    def test_missing_bytes_are_said_in_the_heading(self) -> None:
        out = io.StringIO()
        talk = Talk()
        handshake = talk.handshake()
        talk.segment(b"lost", from_client=False)
        after = talk.segment(b"kept\n", from_client=False)
        stream = follow_tcp_stream(
            captured([*handshake, after, talk.acknowledge(from_client=True)]), 0
        )
        follow_command.write_conversation(stream, out)
        assert "server > client, 5 bytes, after 4 bytes missing from the capture\nkept\n" in (
            out.getvalue()
        )

    def test_a_stream_that_is_not_there(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert main(["follow", str(DOWNLOAD), "9"]) == 1
        assert "the capture has no TCP stream 9" in capsys.readouterr().err

    def test_a_file_that_is_not_there(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["follow", str(tmp_path / "missing.pcap"), "0"]) == 1
        assert "No such file or directory" in capsys.readouterr().err

    def test_a_stream_number_below_zero_is_refused(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with pytest.raises(SystemExit):
            main(["follow", str(DOWNLOAD), "-1"])
        assert "must be 0 or more" in capsys.readouterr().err
