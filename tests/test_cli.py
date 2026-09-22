import subprocess
import sys
from pathlib import Path

import pytest

from builders import pcap_header, pcap_record
from pilotfish import __version__
from pilotfish.cli.main import main


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
