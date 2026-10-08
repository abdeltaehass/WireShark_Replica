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
from hypothesis import given
from hypothesis import strategies as st

from pilotfish.core.formats import (
    CaptureFile,
    FileFormat,
    Interface,
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
def test_every_sample_reads_back_as_it_was_written_as_pcapng(capture: Path) -> None:
    """Read, write, read: the same bytes, times, comments and interfaces.

    A packet that had no time still has none, because it goes back into a
    Simple Packet Block, and each interface keeps its resolution, so a time
    counted in microseconds is written in microseconds again.
    """
    with CaptureFile(capture) as original:
        packets = list(original)
    again = read_back(written(packets, FileFormat.PCAPNG))
    assert records(again) == records(packets)
    assert [each.comments for each in again] == [each.comments for each in packets]
    assert [described(each.interface) for each in again] == [
        described(each.interface) for each in packets
    ]


@pytest.mark.parametrize("capture", REPOSITORY_SAMPLES, ids=sample_id)
def test_every_sample_reads_back_as_it_was_written_as_pcap(capture: Path) -> None:
    """pcap can't hold everything pcapng can, and says so rather than losing it."""
    with CaptureFile(capture) as original:
        packets = list(original)
    if len({each.link_type for each in packets}) > 1:
        # One link type for the whole file.
        with pytest.raises(WriteError, match="one link type"):
            written(packets, FileFormat.PCAP)
        return
    first = packets[0].interface if packets else None
    microseconds = first is not None and first.units_per_second == 1_000_000
    if microseconds and any((each.timestamp_ns or 0) % 1_000 for each in packets):
        # A header in microseconds, set by the first packet, and a later
        # packet from an interface that counted finer.
        with pytest.raises(WriteError, match="nanoseconds"):
            written(packets, FileFormat.PCAP)
        return
    again = read_back(written(packets, FileFormat.PCAP))
    # A packet with no time is given 0, since every pcap record has one.
    expected = [(time or 0, *rest) for time, *rest in records(packets)]
    assert records(again) == expected


def described(interface: Interface | None) -> tuple[object, ...]:
    """What a file says about an interface, leaving out which file it was."""
    assert interface is not None
    return (
        interface.link_type,
        interface.snaplen,
        interface.units_per_second,
        interface.offset_seconds,
        interface.name,
        interface.description,
    )


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


LITTLE_ENDIAN_PCAPS = [
    capture
    for capture in REPOSITORY_SAMPLES
    if capture.suffix in {".pcap", ".cap"}
    and capture.read_bytes()[:4] in {b"\xd4\xc3\xb2\xa1", b"M<\xb2\xa1"}
]


@pytest.mark.parametrize("capture", LITTLE_ENDIAN_PCAPS, ids=sample_id)
def test_a_pcap_file_written_again_is_the_same_file(capture: Path) -> None:
    """Not only the packets: the header too, resolution and snapshot length and all.

    The writer only writes little-endian files, so a big-endian one, such as
    nlmon-big.pcap, comes back with its bytes swapped round.
    """
    with CaptureFile(capture) as original:
        packets = list(original)
    assert written(packets, FileFormat.PCAP) == capture.read_bytes()


@pytest.mark.parametrize("capture", REPOSITORY_SAMPLES, ids=sample_id)
def test_writing_what_was_written_changes_nothing(capture: Path) -> None:
    once = written(read_back_file(capture), FileFormat.PCAPNG)
    assert written(read_back(once), FileFormat.PCAPNG) == once


def read_back_file(capture: Path) -> list[Packet]:
    with CaptureFile(capture) as file:
        return list(file)


class TestResolution:
    """Each interface's times are written in its own units."""

    @pytest.mark.parametrize(
        ("units", "tsresol"),
        [
            (1_000_000, None),
            (1_000_000_000, 9),
            (1_000, 3),
            (1, 0),
            (2**10, 0x8A),
            (2**20, 0x94),
        ],
    )
    def test_pcapng(self, units: int, tsresol: int | None) -> None:
        interface = Interface(1, 0, units, name="eth0")
        times = [interface.timestamp_ns(ticks) for ticks in (0, 1, 1_000_001, 2**40 + 3)]
        packets = [Packet(time, 3, 1, b"abc", interface=interface) for time in times]
        data = written(packets, FileFormat.PCAPNG)
        again = read_back(data)
        assert [each.timestamp_ns for each in again] == times
        assert {each.interface for each in again} == {interface}
        option = struct.pack("<HH", 9, 1)
        assert (option in data) is (tsresol is not None)
        if tsresol is not None:
            assert option + bytes([tsresol]) in data

    def test_an_offset_is_kept(self) -> None:
        interface = Interface(1, 0, 1_000_000, offset_seconds=1_000_000_000)
        time = interface.timestamp_ns(5)
        (again,) = read_back(
            written([Packet(time, 1, 1, b"x", interface=interface)], FileFormat.PCAPNG)
        )
        assert again.timestamp_ns == time
        assert again.interface == interface

    @pytest.mark.parametrize(
        ("units", "magic"), [(1_000_000, b"\xd4\xc3\xb2\xa1"), (1_000_000_000, b"M<\xb2\xa1")]
    )
    def test_pcap_keeps_microseconds_or_nanoseconds(self, units: int, magic: bytes) -> None:
        interface = Interface(1, 1514, units)
        data = written([Packet(1_000_000_000, 3, 1, b"abc", interface=interface)], FileFormat.PCAP)
        assert data[:4] == magic
        assert struct.unpack_from("<I", data, 16) == (1514,)

    def test_a_time_finer_than_its_interface_is_not_rounded(self) -> None:
        microseconds = Interface(1, 0, 1_000_000, name="en0")
        packets = [
            Packet(1_000, 1, 1, b"x", interface=microseconds),
            Packet(1_001, 1, 1, b"x", interface=microseconds),
        ]
        again = read_back(written(packets, FileFormat.PCAPNG))
        assert [each.timestamp_ns for each in again] == [1_000, 1_001]
        # The second went on a copy of the interface that counts nanoseconds.
        assert [each.interface.units_per_second for each in again if each.interface] == [
            1_000_000,
            1_000_000_000,
        ]

    def test_pcap_refuses_to_round_a_time(self) -> None:
        microseconds = Interface(1, 0, 1_000_000)
        nanoseconds = Interface(1, 0, 1_000_000_000)
        packets = [
            Packet(1_000_000_000, 1, 1, b"x", interface=microseconds),
            Packet(1_000_000_001, 1, 1, b"x", interface=nanoseconds),
        ]
        with pytest.raises(WriteError, match="nanoseconds"):
            written(packets, FileFormat.PCAP)
        # Unless the header is told to count nanoseconds from the start.
        again = read_back(written(packets, FileFormat.PCAP, nanoseconds=True))
        assert [each.timestamp_ns for each in again] == [1_000_000_000, 1_000_000_001]

    @given(
        st.sampled_from(
            [10**exponent for exponent in range(10)] + [2**exponent for exponent in range(30)]
        ),
        st.integers(-(2**62), 2**62),
        st.integers(-(10**9), 10**9),
    )
    def test_ticks_undo_timestamp_ns(self, units: int, ticks: int, offset: int) -> None:
        """Exact for every resolution up to a nanosecond."""
        interface = Interface(1, 0, units, offset_seconds=offset)
        assert interface.ticks(interface.timestamp_ns(ticks)) == ticks


class TestComments:
    def test_comments_are_kept(self) -> None:
        packets = [
            Packet(1, 3, 1, b"abc", comments=("first", "second")),
            Packet(2, 3, 1, b"abc"),
            Packet(3, 3, 1, b"abc", comments=("ünïcode ✓",)),
        ]
        again = read_back(written(packets, FileFormat.PCAPNG))
        assert [each.comments for each in again] == [("first", "second"), (), ("ünïcode ✓",)]

    def test_the_sample_comments_are_kept(self) -> None:
        with CaptureFile(SAMPLES_DIR / "wireshark-wiki" / "pcapng-example.pcapng") as file:
            packets = list(file)
        commented = {
            number: each.comments
            for number, each in enumerate(read_back(written(packets, FileFormat.PCAPNG)), 1)
            if each.comments
        }
        assert commented == {
            42: ("Hello, world!",),
            289: ("The Answer to the Ultimate Question of Life, the Universe, and Everything",),
            290: ("The Answer to the Ultimate Question of Life, the Universe, and Everything",),
            314: ("Hello, world!",),
        }

    def test_a_description_is_kept(self) -> None:
        interface = Interface(1, 0, name="en0", description="Wi-Fi")
        (again,) = read_back(
            written([Packet(1_000, 1, 1, b"x", interface=interface)], FileFormat.PCAPNG)
        )
        assert again.interface == interface


class TestPacketsWithoutTimes:
    def test_they_go_back_into_simple_packet_blocks(self) -> None:
        interface = Interface(1, 0)
        data = written([Packet(None, 3, 1, b"abc", interface=interface)], FileFormat.PCAPNG)
        assert block_types(data) == [0x0A0D0D0A, 1, 3]
        (again,) = read_back(data)
        assert again.timestamp_ns is None

    def test_a_new_section_starts_when_the_interface_isnt_first(self) -> None:
        first, second = Interface(1, 0, name="a"), Interface(1, 0, name="b")
        packets = [
            Packet(1_000, 3, 1, b"abc", interface=first),
            Packet(None, 3, 1, b"abc", interface=second),
        ]
        data = written(packets, FileFormat.PCAPNG)
        assert block_types(data) == [0x0A0D0D0A, 1, 6, 0x0A0D0D0A, 1, 3]
        again = read_back(data)
        assert [each.timestamp_ns for each in again] == [1_000, None]
        assert [each.interface for each in again] == [first, second]

    def test_one_cut_short_or_with_a_comment_needs_a_time(self) -> None:
        interface = Interface(1, 0)
        cut = Packet(None, 100, 1, b"abc", interface=interface)
        noted = Packet(None, 3, 1, b"abc", interface=interface, comments=("note",))
        data = written([cut, noted], FileFormat.PCAPNG)
        assert block_types(data) == [0x0A0D0D0A, 1, 6, 6]
        assert [each.timestamp_ns for each in read_back(data)] == [0, 0]


@pytest.mark.skipif(shutil.which("tshark") is None, reason="needs tshark")
@pytest.mark.parametrize("capture", REPOSITORY_SAMPLES, ids=sample_id)
def test_tshark_reads_a_written_file_as_it_reads_the_original(
    capture: Path, tmp_path: Path
) -> None:
    """Wireshark's own reader agrees: the same times, lengths, comments and interfaces.

    tshark lists a pcapng custom block as a row of its own, and those aren't
    packets, so they are left out of the original's rows.
    """
    path = tmp_path / "written.pcapng"
    path.write_bytes(written(read_back_file(capture), FileFormat.PCAPNG))
    fields = ["frame.time_epoch", "frame.len", "frame.cap_len", "frame.comment", "frame.encap_type"]

    def rows(capture_file: Path, *extra: str) -> list[str]:
        result = subprocess.run(
            ["tshark", "-n", "-r", str(capture_file), *extra, "-T", "fields"]
            + [argument for name in fields for argument in ("-e", name)],
            capture_output=True,
            text=True,
            check=True,
        )
        assert result.stderr == ""
        return result.stdout.splitlines()

    assert rows(path) == rows(capture, "-Y", "not frame.cb_pen")
