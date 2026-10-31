"""Reading pcapng as it arrives over a pipe, a piece at a time."""

import io
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from builders import enhanced_packet, interface_description, section_header
from pilotfish.core.formats import CaptureFile, CaptureFileError, PcapngStream, PcapngWriter
from pilotfish.core.packet import Interface, Packet

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
PCAPNG = sorted(SAMPLES_DIR.rglob("*.pcapng"))


def described(packet: Packet) -> tuple[object, ...]:
    return (packet, bytes(packet.data), packet.interface, packet.comments)


def whole(capture: Path) -> tuple[list[Packet], str | None]:
    packets: list[Packet] = []
    with CaptureFile(capture) as file:
        try:
            packets.extend(file)
        except CaptureFileError as error:
            return packets, str(error)
    return packets, None


def pieces(data: bytes, sizes: list[int]) -> list[bytes]:
    """``data`` cut into pieces of these sizes, over and over, then the rest."""
    cut: list[bytes] = []
    offset = 0
    while offset < len(data):
        for size in sizes:
            cut.append(data[offset : offset + size])
            offset += size
    return [piece for piece in cut if piece]


@pytest.mark.parametrize("capture", PCAPNG, ids=lambda capture: capture.name)
@settings(max_examples=12)
@given(sizes=st.lists(st.integers(1, 2000), min_size=1, max_size=8))
def test_a_file_fed_in_pieces_reads_as_the_file(
    capture: Path, sizes: list[int], tmp_path_factory: pytest.TempPathFactory
) -> None:
    expected, error = whole(capture)
    data = capture.read_bytes()
    spool = tmp_path_factory.mktemp("spool") / "live.pcapng"
    stream = PcapngStream(spool)
    failed = None
    try:
        for piece in pieces(data, sizes):
            stream.feed(piece)
        stream.finish()
    except CaptureFileError as raised:
        failed = str(raised)
    with stream:
        assert [described(packet) for packet in stream] == [described(p) for p in expected]
        if error is None:
            assert failed is None
            # The spool is the file, block for block.
            assert spool.read_bytes() == data
        else:
            assert failed is not None


def test_what_a_writer_writes_is_read_as_it_comes(tmp_path: Path) -> None:
    interface = Interface(1, 65535, 1_000_000_000, name="en0")
    packets = [
        Packet(1_700_000_000_000_000_000 + n, 60 + n, 1, bytes([n]) * (60 + n), interface=interface)
        for n in range(20)
    ]
    out = io.BytesIO()
    writer = PcapngWriter(out)
    with PcapngStream(tmp_path / "live.pcapng") as stream:
        fed = 0
        for number, packet in enumerate(packets, start=1):
            writer.write(packet)
            # What has been written since, a byte at a time.
            for byte in out.getvalue()[fed:]:
                stream.feed(bytes([byte]))
            fed = len(out.getvalue())
            # Each packet can be read as soon as its block is complete.
            assert len(stream) == number
        assert [described(p) for p in stream] == [described(p) for p in packets]
        assert stream.waiting == 0


def test_something_else_is_refused(tmp_path: Path) -> None:
    with (
        PcapngStream(tmp_path / "live.pcapng") as stream,
        pytest.raises(CaptureFileError, match="the stream isn't pcapng"),
    ):
        stream.feed(b"\xd4\xc3\xb2\xa1" + bytes(20))


def test_a_damaged_block_is_reported_once_the_good_ones_are_kept(tmp_path: Path) -> None:
    good = section_header() + interface_description() + enhanced_packet("<", 0, 1, b"good")
    bad = (6).to_bytes(4, "little") + (13).to_bytes(4, "little") + bytes(8)
    with PcapngStream(tmp_path / "live.pcapng") as stream:
        with pytest.raises(CaptureFileError, match="isn't a multiple of 4"):
            stream.feed(good + bad)
        assert [bytes(packet.data) for packet in stream] == [b"good"]


def test_a_stream_may_only_end_between_blocks(tmp_path: Path) -> None:
    data = section_header() + interface_description() + enhanced_packet("<", 0, 1, b"x")
    with PcapngStream(tmp_path / "live.pcapng") as stream:
        stream.feed(data[:-3])
        assert len(stream) == 0
        assert stream.waiting > 0
        with pytest.raises(CaptureFileError, match="ended partway through a block"):
            stream.finish()
        stream.feed(data[-3:])
        stream.finish()
        assert len(stream) == 1
        with pytest.raises(IndexError, match="there is no packet 2; the stream has 1"):
            stream[1]
