"""Writing pcap and pcapng files.

Whatever is written has to read back as the packets that went in, which the
reader's own tests already hold to tshark. Where tshark is installed, it reads
the written files too.
"""

import io
import shutil
import struct
import subprocess
from pathlib import Path

import pytest

from pilotfish.core.formats import (
    CaptureFile,
    FileFormat,
    PcapngWriter,
    PcapWriter,
    WriteError,
    open_writer,
)
from pilotfish.core.formats.pcap import MAGIC_NANOSECONDS
from pilotfish.core.packet import Packet

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
REPOSITORY_SAMPLES = sorted(
    capture
    for capture in SAMPLES_DIR.rglob("*")
    if capture.suffix in {".cap", ".ntar", ".pcap", ".pcapng"}
    and capture.relative_to(SAMPLES_DIR).parts[0] != "private"
)

type Record = tuple[int | None, int, int, bytes]


def records(packets: list[Packet]) -> list[Record]:
    """What a packet is, as far as a capture file can say."""
    return [
        (packet.timestamp_ns, packet.original_length, packet.link_type, bytes(packet.data))
        for packet in packets
    ]


def written(packets: list[Packet], file_format: FileFormat, **options: object) -> bytes:
    stream = io.BytesIO()
    writer = open_writer(stream, file_format, **options)  # type: ignore[arg-type]
    for packet in packets:
        writer.write(packet)
    writer.close()
    return stream.getvalue()


def read_back(data: bytes) -> list[Packet]:
    with CaptureFile.from_bytes(data) as capture:
        return list(capture)


def packet(
    number: int, *, link_type: int = 1, data: bytes = b"\x00\x01\x02", **more: int
) -> Packet:
    return Packet(
        timestamp_ns=more.get("timestamp_ns", 1_700_000_000_123_456_789 + number),
        original_length=more.get("original_length", len(data)),
        link_type=link_type,
        data=data,
        interface_id=more.get("interface_id", 0),
    )


def block_types(data: bytes) -> list[int]:
    """The type of each pcapng block in ``data``, in order."""
    types = []
    offset = 0
    while offset < len(data):
        block_type, length = struct.unpack_from("<II", data, offset)
        types.append(block_type)
        offset += length
    return types


def sample_id(capture: Path) -> str:
    return str(capture.relative_to(SAMPLES_DIR))


@pytest.mark.parametrize("capture", REPOSITORY_SAMPLES, ids=sample_id)
@pytest.mark.parametrize("file_format", list(FileFormat))
def test_every_sample_reads_back_as_it_was(capture: Path, file_format: FileFormat) -> None:
    with CaptureFile(capture) as original:
        packets = list(original)
    if file_format is FileFormat.PCAP and len({each.link_type for each in packets}) > 1:
        # pcap has one link type for the whole file, so these can't be written as one.
        with pytest.raises(WriteError):
            written(packets, file_format)
        return
    again = read_back(written(packets, file_format))
    # A packet with no time is given 0, since both formats give every packet one.
    expected = [(time or 0, *rest) for time, *rest in records(packets)]
    assert records(again) == expected


def test_timestamps_keep_every_nanosecond() -> None:
    times = [0, 1, 999_999_999, 1_700_000_000_123_456_789, 2**63 - 1]
    packets = [packet(0, timestamp_ns=time) for time in times]
    for file_format in FileFormat:
        if file_format is FileFormat.PCAP:
            # pcap's seconds are 32 bits, so its times end in 2106.
            packets = packets[:-1]
        assert [each.timestamp_ns for each in read_back(written(packets, file_format))] == [
            each.timestamp_ns for each in packets
        ]


def test_a_packet_cut_short_keeps_its_length_on_the_wire() -> None:
    cut = packet(1, data=b"\xaa" * 10, original_length=1514)
    for file_format in FileFormat:
        (again,) = read_back(written([cut], file_format))
        assert (again.captured_length, again.original_length) == (10, 1514)


class TestPcap:
    def test_the_header_says_nanoseconds_and_the_link_type(self) -> None:
        data = written([packet(1, link_type=228)], FileFormat.PCAP)
        magic, major, minor, zone, sigfigs, snaplen, link_type = struct.unpack_from(
            "<IHHiIII", data
        )
        assert (magic, major, minor, zone, sigfigs) == (MAGIC_NANOSECONDS, 2, 4, 0, 0)
        assert (snaplen, link_type) == (262_144, 228)

    def test_an_empty_file_is_still_a_capture_file(self) -> None:
        stream = io.BytesIO()
        PcapWriter(stream, link_type=113).close()
        assert len(stream.getvalue()) == 24
        assert read_back(stream.getvalue()) == []
        with CaptureFile.from_bytes(stream.getvalue()) as capture:
            assert capture.format is FileFormat.PCAP
        # With no link type to go on, Ethernet.
        stream = io.BytesIO()
        PcapWriter(stream).close()
        assert struct.unpack_from("<I", stream.getvalue(), 20) == (1,)

    def test_one_link_type_per_file(self) -> None:
        writer = PcapWriter(io.BytesIO())
        writer.write(packet(1, link_type=1))
        with pytest.raises(WriteError, match="one link type"):
            writer.write(packet(2, link_type=113))

    def test_a_link_type_given_up_front_is_kept_to(self) -> None:
        writer = PcapWriter(io.BytesIO(), link_type=0)
        with pytest.raises(WriteError):
            writer.write(packet(1, link_type=1))


class TestPcapng:
    def test_the_section_says_who_wrote_it(self) -> None:
        data = written([], FileFormat.PCAPNG)
        block_type, length, magic, major, minor = struct.unpack_from("<IIIHH", data)
        assert (block_type, magic, major, minor) == (0x0A0D0D0A, 0x1A2B3C4D, 1, 0)
        assert length == len(data)
        assert b"pilotfish " in data
        assert read_back(data) == []

    def test_each_interface_is_described_once_before_its_first_packet(self) -> None:
        packets = [
            packet(1, link_type=1, interface_id=0),
            packet(2, link_type=113, interface_id=1),
            packet(3, link_type=1, interface_id=0),
            packet(4, link_type=113, interface_id=1),
        ]
        data = written(packets, FileFormat.PCAPNG)
        assert block_types(data) == [0x0A0D0D0A, 1, 6, 1, 6, 6, 6]
        again = read_back(data)
        assert records(again) == records(packets)
        assert [each.interface_id for each in again] == [0, 1, 0, 1]

    def test_interfaces_are_numbered_as_they_are_met(self) -> None:
        packets = [packet(1, interface_id=3), packet(2, interface_id=0)]
        assert [each.interface_id for each in read_back(written(packets, FileFormat.PCAPNG))] == [
            0,
            1,
        ]

    def test_an_interface_can_be_named(self) -> None:
        data = written([packet(1)], FileFormat.PCAPNG, interface_names={0: "en0"})
        assert b"en0\x00" in data

    def test_padding_keeps_blocks_on_four_byte_boundaries(self) -> None:
        for size in range(9):
            stream = io.BytesIO()
            writer = PcapngWriter(stream)
            writer.write(packet(1, data=bytes(range(size))))
            assert len(stream.getvalue()) % 4 == 0
            assert bytes(read_back(stream.getvalue())[0].data) == bytes(range(size))


@pytest.mark.skipif(shutil.which("tshark") is None, reason="needs tshark")
@pytest.mark.parametrize("file_format", list(FileFormat))
def test_tshark_reads_what_was_written(tmp_path: Path, file_format: FileFormat) -> None:
    with CaptureFile(SAMPLES_DIR / "wireshark-wiki" / "http.cap") as capture:
        packets = list(capture)
    path = tmp_path / f"http.{file_format}"
    path.write_bytes(written(packets, file_format))
    result = subprocess.run(
        ["tshark", "-n", "-r", str(path), "-T", "fields", "-e", "frame.time_epoch"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stderr == ""
    assert result.stdout.splitlines()[0] == "1084443427.311224000"
    assert len(result.stdout.splitlines()) == len(packets)
