import io
import subprocess
import sys
from pathlib import Path

import pytest

import toy
from builders import pcap_header, pcap_record
from packets import ethernet, icmp_echo, ipv4, udp
from pilotfish import __version__
from pilotfish.cli import fields
from pilotfish.cli.detail import write_tree
from pilotfish.cli.main import main
from pilotfish.core.dissect import Field, FieldRegistry, FieldType, ProtocolTree, dissect
from pilotfish.core.packet import Packet
from toy import toy_packet


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
    ping = ethernet(ipv4(icmp_echo(sequence=1), protocol=1))
    capture = write_pcap(
        tmp_path / "two.pcap",
        pcap_record("<", 1_084_443_427, 311_224, ping),
        pcap_record("<", 1_084_443_428, 222_534, ping[:40], original_length=1514),
    )
    assert main(["read", str(capture)]) == 0
    assert capsys.readouterr().out == (
        "    No.  Time                  Source                 Destination            "
        "Protocol  Length  Info\n"
        "      1  1084443427.311224000  192.0.2.1              192.0.2.2              "
        "ICMP          51  Echo (ping) request  id=0x00de, seq=1\n"
        "      2  1084443428.222534000  192.0.2.1              192.0.2.2              "
        # The second packet was cut short, so its ICMP header ran out.
        "ICMP        1514  192.0.2.1 → 192.0.2.2 [Malformed Packet]\n"
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


def test_read_prints_the_protocol_tree(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    capture = write_pcap(
        tmp_path / "trees.pcap",
        pcap_record("<", 1_112_172_466, 496_046, ethernet(ipv4(udp(1234, 53)))),
        pcap_record("<", 1_112_172_467, 0, ethernet(ipv4(udp(53, 1234)))),
    )
    assert main(["read", "-V", str(capture)]) == 0
    listed = capsys.readouterr().out
    assert listed.startswith(
        "Frame 1: 47 bytes on wire, 47 bytes captured\n"
        "    Frame number: 1\n"
        "    Frame length: 47\n"
        "    Capture length: 47\n"
        "    Epoch arrival time: 1112172466.496046000\n"
        "Ethernet II, Src: 02:00:00:00:00:02, Dst: 02:00:00:00:00:01\n"
        "    Destination: 02:00:00:00:00:01\n"
        "    Source: 02:00:00:00:00:02\n"
        "    Type: 0x0800\n"
        "Internet Protocol Version 4, Src: 192.0.2.1, Dst: 192.0.2.2\n"
        "    Version: 4\n"
        "    Header Length: 20\n"
    )
    # A blank line between packets, and the second one is there too.
    assert "\n\nFrame 2: 47 bytes on wire, 47 bytes captured\n" in listed


def detail(tree: ProtocolTree) -> str:
    out = io.StringIO()
    write_tree(tree, out)
    return out.getvalue()


def test_the_detail_view_nests_fields_and_spells_out_flags() -> None:
    packet = Packet(0, len(toy_packet()), toy.TOY_LINK_TYPE, toy_packet())
    listed = detail(dissect(packet, registry=toy.REGISTRY))
    assert "Toy Protocol 1, label toy1\n" in listed
    assert "    Flags: 1\n        Urgent: Set\n        Last: Not set\n" in listed
    assert "    Source address: 192.0.2.1\n" in listed


def test_the_detail_view_marks_a_malformed_packet() -> None:
    cut = toy_packet()[:10]
    packet = Packet(0, len(cut), toy.TOY_LINK_TYPE, cut)
    listed = detail(dissect(packet, registry=toy.REGISTRY))
    assert listed.endswith(
        "[Malformed packet: toy: toy.hardware needs 6 bytes at offset 8, but the packet has 2]\n"
    )


def test_the_detail_view_cuts_long_byte_strings_short() -> None:
    # A link type nothing decodes, so the whole frame stays as data.
    packet = Packet(0, 100, 147, bytes(range(100)))
    listed = detail(dissect(packet))
    assert "    Data: 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f" in listed
    assert "… (100 bytes)\n" in listed


def test_fields_lists_name_type_and_description() -> None:
    registry = FieldRegistry()
    registry.add(
        Field("toy.version", FieldType.UINT, "Version"),
        Field("toy.label", FieldType.STRING, "Label"),
    )
    out = io.StringIO()
    assert fields.run(out=out, registry=registry) == 0
    assert out.getvalue() == (
        "Name         Type    Description\n"
        "toy.label    string  Label\n"
        "toy.version  uint    Version\n"
    )


def test_fields_command_lists_what_pilotfish_decodes(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["fields"]) == 0
    listed = [line.split(maxsplit=2) for line in capsys.readouterr().out.splitlines()]
    assert ["frame.time_epoch", "time", "Epoch arrival time"] in listed
    assert ["frame", "protocol", "Frame"] in listed
