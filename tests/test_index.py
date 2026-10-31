"""The packet index: where each packet is, so any one can be read again."""

from pathlib import Path

import pytest

from builders import (
    enhanced_packet,
    interface_description,
    pcap_header,
    pcap_record,
    section_header,
    simple_packet,
)
from pilotfish.core.formats import CaptureFile, CaptureFileError, PacketIndex
from pilotfish.core.packet import Packet

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
CAPTURES = sorted(
    capture
    for capture in SAMPLES_DIR.rglob("*")
    if capture.suffix in {".cap", ".ntar", ".pcap", ".pcapng"}
)


def described(packet: Packet) -> tuple[object, ...]:
    """Everything a packet says, including what isn't part of its equality."""
    return (packet, bytes(packet.data), packet.interface, packet.comments)


def read_through(capture: Path) -> tuple[list[Packet], str | None]:
    """The packets reading the file from end to end gives, and why it stopped early."""
    packets: list[Packet] = []
    with CaptureFile(capture) as file:
        try:
            packets.extend(file)
        except CaptureFileError as error:
            return packets, str(error)
    return packets, None


def opens(capture: Path) -> bool:
    try:
        CaptureFile(capture).close()
    except CaptureFileError:
        return False
    return True


@pytest.mark.parametrize(
    "capture",
    [capture for capture in CAPTURES if opens(capture)],
    ids=lambda capture: str(capture.relative_to(SAMPLES_DIR)),
)
def test_every_packet_reads_again_as_it_was(capture: Path) -> None:
    expected, error = read_through(capture)
    with PacketIndex.open(capture) as index:
        assert len(index) == len(expected)
        # Out of order, as a packet list scrolled about reads them.
        for row in [*range(len(index) - 1, -1, -2), *range(0, len(index), 2)]:
            assert described(index[row]) == described(expected[row])
        assert (None if index.error is None else str(index.error)) == error


def write(path: Path, data: bytes) -> Path:
    path.write_bytes(data)
    return path


def test_packets_are_read_with_their_own_section(tmp_path: Path) -> None:
    # Two sections in opposite byte orders, each with its own interfaces.
    capture = write(
        tmp_path / "two.pcapng",
        section_header("<")
        + interface_description("<", link_type=1, name="en0")
        + enhanced_packet("<", 0, 1_000_000, b"first")
        + section_header(">")
        + interface_description(">", link_type=101, tsresol=9, name="utun0")
        + enhanced_packet(">", 0, 2_000_000_000, b"second")
        + simple_packet(">", b"third"),
    )
    with PacketIndex.open(capture) as index:
        assert [bytes(packet.data) for packet in index] == [b"first", b"second", b"third"]
        second = index[1]
        assert second.link_type == 101
        assert second.timestamp_ns == 2_000_000_000
        assert second.interface is not None
        assert second.interface.name == "utun0"
        assert index[2].timestamp_ns is None


def test_a_file_cut_short_keeps_the_packets_before(tmp_path: Path) -> None:
    capture = write(
        tmp_path / "cut.pcap",
        pcap_header() + pcap_record("<", 1, 0, b"whole") + pcap_record("<", 2, 0, b"cut")[:-1],
    )
    with PacketIndex.open(capture) as index:
        assert len(index) == 1
        assert bytes(index[0].data) == b"whole"
        assert str(index.error) == "packet at offset 45 is cut short: 2 of 3 bytes"


def test_there_is_no_packet_past_the_end(tmp_path: Path) -> None:
    capture = write(tmp_path / "one.pcap", pcap_header() + pcap_record("<", 1, 0, b"only"))
    with PacketIndex.open(capture) as index:
        with pytest.raises(IndexError, match="there is no packet 2; the file has 1"):
            index[1]
        with pytest.raises(IndexError):
            index[-1]


def test_only_a_packet_block_holds_a_packet(tmp_path: Path) -> None:
    capture = write(
        tmp_path / "one.pcapng",
        section_header() + interface_description() + enhanced_packet("<", 0, 0, b"x"),
    )
    with CaptureFile(capture) as file:
        [(offset, _)] = list(file.records())
        assert bytes(file.packet_at(offset).data) == b"x"
        with pytest.raises(CaptureFileError, match="the block at offset 0 doesn't hold a packet"):
            file.packet_at(0)
