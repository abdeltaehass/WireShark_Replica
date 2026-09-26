import subprocess
import sys
from pathlib import Path

import pytest

from builders import pcap_header, pcap_record
from pilotfish import __version__
from pilotfish.cli.main import main
from programs import ethernet, ipv4, udp


def test_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    assert capsys.readouterr().out == f"pilotfish {__version__}\n"


def test_runs_as_module() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "pilotfish", "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout == f"pilotfish {__version__}\n"


def test_no_command_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    assert main([]) == 0
    assert "read" in capsys.readouterr().out


def write_pcap(path: Path, *records: bytes) -> Path:
    path.write_bytes(pcap_header(link_type=1) + b"".join(records))
    return path


def test_read_lists_packets(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    capture = write_pcap(
        tmp_path / "two.pcap",
        pcap_record("<", 1_084_443_427, 311_224, b"x" * 62),
        pcap_record("<", 1_084_443_428, 222_534, b"y" * 54, original_length=1514),
    )
    assert main(["read", str(capture)]) == 0
    assert capsys.readouterr().out == (
        "    No.  Time                   Length  Captured  Link type\n"
        "      1  1084443427.311224000       62        62  ETHERNET\n"
        "      2  1084443428.222534000     1514        54  ETHERNET\n"
    )


def test_read_in_utc(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    capture = write_pcap(tmp_path / "one.pcap", pcap_record("<", 1_084_443_427, 311_224, b""))
    assert main(["read", "--time-format", "utc", str(capture)]) == 0
    assert "2004-05-13 10:17:07.311224000" in capsys.readouterr().out


def test_read_reports_a_missing_file(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    missing = tmp_path / "missing.pcap"
    assert main(["read", str(missing)]) == 1
    assert capsys.readouterr().err == f"pilotfish: {missing}: No such file or directory\n"


def test_read_prints_packets_before_a_truncation(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    capture = write_pcap(
        tmp_path / "cut.pcap", pcap_record("<", 0, 0, b"whole"), pcap_record("<", 0, 0, b"cut")[:-1]
    )
    assert main(["read", str(capture)]) == 1
    output = capsys.readouterr()
    assert output.out.count("\n") == 2  # header and the one whole packet
    assert "is cut short: 2 of 3 bytes" in output.err


@pytest.mark.macos
def test_read_with_a_capture_filter(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    capture = write_pcap(
        tmp_path / "mixed.pcap",
        pcap_record("<", 1, 0, ethernet(ipv4(udp(1234, 80)))),
        pcap_record("<", 2, 0, ethernet(ipv4(udp(1234, 53)))),
        pcap_record("<", 3, 0, ethernet(ipv4(udp(53, 1234)))),
    )
    assert main(["read", "-f", "udp port 53", str(capture)]) == 0
    listed = capsys.readouterr().out.splitlines()
    assert len(listed) == 3  # the header and the two DNS packets
    # Packets keep the numbers they have in the file, as tshark's do.
    assert [line.split()[0] for line in listed[1:]] == ["2", "3"]


@pytest.mark.macos
def test_read_with_a_filter_that_will_not_compile(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    capture = write_pcap(tmp_path / "one.pcap", pcap_record("<", 1, 0, ethernet(ipv4(udp(1, 53)))))
    assert main(["read", "-f", "udp porrt 53", str(capture)]) == 1
    output = capsys.readouterr()
    assert output.out == ""  # the error comes before any listing
    assert output.err == (
        'pilotfish: capture filter "udp porrt 53": can\'t parse filter expression: syntax error\n'
    )


@pytest.mark.macos
def test_read_filters_every_link_type_in_a_file(capsys: pytest.CaptureFixture[str]) -> None:
    # This capture has an Ethernet interface and a Linux SLL one, so the
    # filter is compiled for each: the headers in front of the packets differ,
    # and so do the offsets the program reads. tshark and tcpdump also count
    # 178 ICMP packets here.
    samples = Path(__file__).resolve().parent.parent / "samples"
    capture = samples / "wireshark-wiki" / "pcapng-example.pcapng"
    assert main(["read", "-f", "icmp", str(capture)]) == 0
    assert len(capsys.readouterr().out.splitlines()) == 1 + 178
