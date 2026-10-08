"""A long capture written across a ring of files."""

from pathlib import Path

import pytest

from pilotfish.cli.main import main
from pilotfish.cli.status import Exit
from pilotfish.core.formats import CaptureFile, FileFormat, RingBuffer, RingLimits
from pilotfish.core.packet import Interface, Packet

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
ARP_STORM = SAMPLES / "wireshark-wiki" / "arp-storm.pcap"
DNS = SAMPLES / "wireshark-wiki" / "dns.cap"

SECOND = 1_000_000_000
INTERFACE = Interface(1, 0, 1_000_000)


def packet(seconds: float, size: int = 100) -> Packet:
    return Packet(int(seconds * SECOND), size, 1, bytes(size), interface=INTERFACE)


def ring(tmp_path: Path, packets: list[Packet], **limits: int) -> RingBuffer:
    buffer = RingBuffer(tmp_path / "ring.pcapng", FileFormat.PCAPNG, RingLimits(**limits))
    for each in packets:
        buffer.write(each)
    buffer.close()
    return buffer


def contents(paths: list[Path]) -> list[list[Packet]]:
    found = []
    for path in paths:
        with CaptureFile(path) as file:
            found.append(list(file))
    return found


def test_a_new_file_once_the_last_is_big_enough(tmp_path: Path) -> None:
    # Each packet takes 100 bytes and its block 32 more; the headers about 100.
    buffer = ring(tmp_path, [packet(n) for n in range(10)], max_bytes=400)
    sizes = [len(files) for files in contents(buffer.files)]
    assert sum(sizes) == 10
    assert len(sizes) > 1
    # A file goes over the limit by at most the packet that took it there.
    for path in buffer.files[:-1]:
        assert 400 <= path.stat().st_size < 400 + 132


def test_a_new_file_once_its_packets_span_long_enough(tmp_path: Path) -> None:
    times = [0, 10, 59.9, 60, 61, 200, 260]
    buffer = ring(tmp_path, [packet(t) for t in times], max_seconds=60)
    found = contents(buffer.files)
    assert [[each.timestamp_ns for each in file] for file in found] == [
        [0, 10 * SECOND, int(59.9 * SECOND)],
        [60 * SECOND, 61 * SECOND],
        [200 * SECOND],
        [260 * SECOND],
    ]


def test_only_the_newest_files_are_kept(tmp_path: Path) -> None:
    buffer = ring(tmp_path, [packet(n * 60) for n in range(6)], max_seconds=60, max_files=2)
    assert len(buffer.files) == 6
    assert [path.exists() for path in buffer.files] == [False] * 4 + [True] * 2
    assert sorted(tmp_path.iterdir()) == buffer.files[-2:]
    assert [[each.timestamp_ns for each in file] for file in contents(buffer.files[-2:])] == [
        [240 * SECOND],
        [300 * SECOND],
    ]


def test_files_are_named_as_dumpcap_names_them(tmp_path: Path) -> None:
    buffer = ring(tmp_path, [packet(1_700_000_000), packet(1_700_000_100)], max_seconds=60)
    assert [path.name for path in buffer.files] == [
        "ring_00001_20231114221320.pcapng",
        "ring_00002_20231114221500.pcapng",
    ]


def test_a_packet_with_no_time_never_starts_a_file(tmp_path: Path) -> None:
    timeless = Packet(None, 3, 1, b"abc", interface=INTERFACE)
    buffer = ring(tmp_path, [packet(0), timeless, timeless, packet(30)], max_seconds=60)
    assert len(buffer.files) == 1
    assert buffer.files[0].name == "ring_00001_19700101000000.pcapng"


def test_no_packets_no_files(tmp_path: Path) -> None:
    assert ring(tmp_path, [], max_bytes=10).files == []
    assert list(tmp_path.iterdir()) == []


def test_every_file_is_a_capture_file_of_its_own(tmp_path: Path) -> None:
    with CaptureFile(ARP_STORM) as file:
        packets = list(file)
    buffer = RingBuffer(tmp_path / "storm.pcap", FileFormat.PCAP, RingLimits(max_bytes=5_000))
    for each in packets:
        buffer.write(each)
    buffer.close()
    assert len(buffer.files) > 5
    rejoined = [each for file in contents(buffer.files) for each in file]
    assert [bytes(each.data) for each in rejoined] == [bytes(each.data) for each in packets]
    assert all(path.suffix == ".pcap" for path in buffer.files)


def test_limits_need_a_size_or_a_duration() -> None:
    with pytest.raises(ValueError, match="size or a duration"):
        RingLimits(max_files=3)


class TestTheFlag:
    def test_splitting_a_saved_capture(self, tmp_path: Path) -> None:
        target = tmp_path / "storm.pcapng"
        argv = ["-r", str(ARP_STORM), "-w", str(target), "-b", "filesize:10", "-b", "files:3"]
        assert main(argv) == Exit.OK
        files = sorted(tmp_path.iterdir())
        assert len(files) == 3
        assert all(path.name.startswith("storm_0000") for path in files)
        assert files[-1].name.startswith("storm_00006_")

    def test_by_time(self, tmp_path: Path) -> None:
        assert (
            main(
                [
                    "-r",
                    str(DNS),
                    "-w",
                    str(tmp_path / "dns.pcap"),
                    "-F",
                    "pcap",
                    "-b",
                    "duration:60",
                ]
            )
            == Exit.OK
        )
        files = sorted(tmp_path.iterdir())
        assert [len(each) for each in contents(files)] == [8, 4, 8, 18]

    @pytest.mark.parametrize(
        ("flags", "message"),
        [
            (["-b", "filesize:10"], "needs -w FILE"),
            (["-w", "-", "-b", "filesize:10"], "needs -w FILE"),
            (["-w", "x.pcapng", "-b", "files:3"], "needs filesize:KB or duration:SECONDS"),
            (["-w", "x.pcapng", "-b", "size:3"], "isn't a -b option"),
            (["-w", "x.pcapng", "-b", "filesize"], "isn't a -b option"),
            (["-w", "x.pcapng", "-b", "filesize:0"], "a whole number above 0"),
            (["-w", "x.pcapng", "-b", "duration:1.5"], "a whole number above 0"),
        ],
    )
    def test_mistakes(
        self, flags: list[str], message: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(["-r", str(DNS), *flags]) == Exit.INVALID_OPTION
        assert message in capsys.readouterr().err

    def test_a_folder_that_isnt_there(self, capsys: pytest.CaptureFixture[str]) -> None:
        argv = ["-r", str(DNS), "-w", "/nonexistent/x.pcapng", "-b", "filesize:10"]
        assert main(argv) == Exit.OPEN_ERROR
        assert "/nonexistent: No such directory" in capsys.readouterr().err
