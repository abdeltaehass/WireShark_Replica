"""Merging capture files in time order."""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from pilotfish.cli.main import main
from pilotfish.cli.status import Exit
from pilotfish.core.formats import CaptureFile, merge
from pilotfish.core.packet import Interface, Packet

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
DNS = SAMPLES / "wireshark-wiki" / "dns.cap"
HTTP = SAMPLES / "wireshark-wiki" / "http.cap"
ICMP = SAMPLES / "made" / "icmp.pcap"
LOOPBACK = SAMPLES / "made" / "loopback.pcap"
EXAMPLE = SAMPLES / "wireshark-wiki" / "pcapng-example.pcapng"
NANOSECONDS = SAMPLES / "wireshark-wiki" / "dhcp-nanosecond.pcap"


def packets_of(path: Path) -> list[Packet]:
    with CaptureFile(path) as file:
        return list(file)


def label(source: int, time: int) -> Packet:
    return Packet(time, 1, 1, bytes([source]))


@given(st.lists(st.lists(st.integers(0, 50)).map(sorted), max_size=5))
def test_packets_come_out_in_time_order(times: list[list[int]]) -> None:
    captures = [[label(source, time) for time in each] for source, each in enumerate(times)]
    merged = list(merge(captures))
    assert sorted(merged, key=lambda each: each.timestamp_ns or 0) == merged
    assert len(merged) == sum(len(each) for each in times)


def test_a_tie_keeps_the_order_the_files_were_given_in() -> None:
    first = [label(0, 5), label(0, 5)]
    second = [label(1, 5)]
    assert [bytes(each.data) for each in merge([first, second])] == [b"\x00", b"\x00", b"\x01"]
    assert [bytes(each.data) for each in merge([second, first])] == [b"\x01", b"\x00", b"\x00"]


def test_a_packet_with_no_time_goes_first() -> None:
    timed = [label(0, 5)]
    timeless = [Packet(None, 1, 1, b"\x01")]
    assert [each.timestamp_ns for each in merge([timed, timeless])] == [None, 5]


def test_nothing_is_read_ahead() -> None:
    """A merge holds one packet from each file, so it works on files of any size."""
    pulled: list[int] = []

    def source(number: int) -> object:
        for time in range(number, 100, 2):
            pulled.append(time)
            yield label(number, time)

    merged = merge([source(0), source(1)])  # type: ignore[list-item]
    assert [next(merged).timestamp_ns for _ in range(3)] == [0, 1, 2]
    assert pulled == [0, 1, 2, 3]


class TestTheCommand:
    def test_files_merge_in_time_order(self, tmp_path: Path) -> None:
        target = tmp_path / "merged.pcapng"
        assert main(["merge", "-w", str(target), str(DNS), str(HTTP), str(ICMP)]) == Exit.OK
        merged = packets_of(target)
        originals = packets_of(DNS) + packets_of(HTTP) + packets_of(ICMP)
        assert len(merged) == len(originals)
        times = [each.timestamp_ns or 0 for each in merged]
        assert times == sorted(times)
        assert sorted(bytes(each.data) for each in merged) == sorted(
            bytes(each.data) for each in originals
        )

    def test_concatenating_keeps_the_files_in_order(self, tmp_path: Path) -> None:
        target = tmp_path / "joined.pcapng"
        assert main(["merge", "-a", "-w", str(target), str(ICMP), str(DNS)]) == Exit.OK
        assert [bytes(each.data) for each in packets_of(target)] == [
            bytes(each.data) for each in packets_of(ICMP) + packets_of(DNS)
        ]

    def test_interfaces_and_comments_survive(self, tmp_path: Path) -> None:
        target = tmp_path / "merged.pcapng"
        assert main(["merge", "-w", str(target), str(EXAMPLE), str(DNS)]) == Exit.OK
        merged = packets_of(target)
        assert sum(1 for each in merged if each.comments) == 4
        names = {each.interface.name for each in merged if each.interface}
        assert names == {"any", "ens160", None}

    def test_identical_interfaces_become_one(self, tmp_path: Path) -> None:
        target = tmp_path / "twice.pcapng"
        assert main(["merge", "-w", str(target), str(DNS), str(DNS)]) == Exit.OK
        merged = packets_of(target)
        assert len(merged) == 2 * len(packets_of(DNS))
        assert {each.interface_id for each in merged} == {0}

    def test_pcap_counts_nanoseconds_if_any_file_does(self, tmp_path: Path) -> None:
        target = tmp_path / "merged.pcap"
        argv = ["merge", "-F", "pcap", "-w", str(target), str(DNS), str(NANOSECONDS)]
        assert main(argv) == Exit.OK
        merged = packets_of(target)
        expected = packets_of(DNS) + packets_of(NANOSECONDS)
        assert sorted(each.timestamp_ns or 0 for each in merged) == sorted(
            each.timestamp_ns or 0 for each in expected
        )

    def test_writing_to_standard_output(self) -> None:
        command = Path(sys.executable).with_name("pilotfish")
        result = subprocess.run(
            [str(command), "merge", "-w", "-", str(DNS), str(ICMP)],
            capture_output=True,
            check=False,
        )
        assert result.returncode == 0
        with CaptureFile.from_bytes(result.stdout) as file:
            assert len(list(file)) == len(packets_of(DNS)) + len(packets_of(ICMP))

    @pytest.mark.parametrize(
        ("argv", "status", "message"),
        [
            (["merge", "-w", "x.pcapng", "missing.pcap"], Exit.INVALID_FILE, "missing.pcap"),
            (["merge", "-w", "/nonexistent/x.pcapng", str(DNS)], Exit.OPEN_ERROR, "No such file"),
            (
                ["merge", "-F", "pcap", "-w", "/dev/null", str(DNS), str(LOOPBACK)],
                Exit.WRITE_ERROR,
                "one link type",
            ),
        ],
    )
    def test_failures(
        self, argv: list[str], status: Exit, message: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert main(argv) == status
        assert message in capsys.readouterr().err

    def test_a_damaged_file_is_named(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        cut = tmp_path / "cut.pcap"
        cut.write_bytes(HTTP.read_bytes()[:1000])
        assert (
            main(["merge", "-w", str(tmp_path / "out.pcapng"), str(DNS), str(cut)])
            == Exit.READ_ERROR
        )
        assert f"pilotfish: {cut}: packet at offset 869 is cut short" in capsys.readouterr().err

    def test_needs_somewhere_to_write(self, capsys: pytest.CaptureFixture[str]) -> None:
        with pytest.raises(SystemExit) as exited:
            main(["merge", str(DNS)])
        assert exited.value.code == Exit.INVALID_OPTION


@pytest.mark.skipif(shutil.which("mergecap") is None, reason="needs mergecap")
def test_the_order_is_mergecaps(tmp_path: Path) -> None:
    ours, theirs = tmp_path / "ours.pcapng", tmp_path / "theirs.pcapng"
    inputs = [str(DNS), str(HTTP), str(ICMP), str(EXAMPLE)]
    assert main(["merge", "-w", str(ours), *inputs]) == Exit.OK
    subprocess.run(["mergecap", "-w", str(theirs), *inputs], check=True)
    assert [(each.timestamp_ns, bytes(each.data)) for each in packets_of(ours)] == [
        (each.timestamp_ns, bytes(each.data)) for each in packets_of(theirs)
    ]


def test_the_merged_interface_is_the_one_the_file_described() -> None:
    interface = Interface(1, 0, name="en0")
    first = [Packet(1_000, 1, 1, b"a", interface=interface)]
    (merged,) = merge([first])
    assert merged.interface is interface
