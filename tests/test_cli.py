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


def test_read_marks_what_the_tcp_analysis_found(capsys: pytest.CaptureFixture[str]) -> None:
    """The packet list says what a segment is, in front of the rest of the line.

    These are the same notes, in the same words and the same order, that
    tshark's Info column carries.
    """
    samples = Path(__file__).resolve().parent.parent / "samples"
    assert main(["read", str(samples / "made" / "tcp.pcap")]) == 0
    rows = capsys.readouterr().out.splitlines()
    marked = {
        int(row.split()[0]): row.split("  ")[-1]
        for row in rows[1:]
        if "[TCP " in row.split("  ")[-1]
    }
    assert marked[5] == (
        "[TCP Previous segment not captured] 50000 → 80 [PSH, ACK] Seq=301 Ack=1 Win=8000 Len=100"
    )
    assert marked[11].startswith("[TCP Dup ACK 8#2] ")
    assert marked[12].startswith("[TCP Fast Retransmission] ")
    assert marked[13].startswith("[TCP Spurious Retransmission] ")
    assert marked[16].startswith("[TCP ZeroWindowProbeAck] [TCP ZeroWindow] ")
    assert marked[22].startswith("[TCP Keep-Alive] ")
    assert marked[33].startswith("[TCP Out-Of-Order] ")
    assert marked[34].startswith("[TCP ACKed unseen segment] ")
    # The handshake's options are listed the way tshark lists them.
    assert rows[1].endswith("50000 → 80 [SYN] Seq=0 Win=8000 Len=0 MSS=1460 WS=1 SACK_PERM")


def test_read_shows_a_message_in_the_packet_that_completes_it(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A download is one line of HTTP, after the segments that carried it."""
    samples = Path(__file__).resolve().parent.parent / "samples"
    assert main(["read", str(samples / "made" / "http-download.pcap")]) == 0
    rows = {int(row.split()[0]): row for row in capsys.readouterr().out.splitlines()[1:]}
    protocols = {number: row.split()[4] for number, row in rows.items()}
    assert [protocols[number] for number in range(6, 20)] == ["TCP"] * 13 + ["HTTP"]
    assert rows[7].endswith("Len=1460 [TCP segment of a reassembled PDU]")
    assert rows[19].endswith("HTTP/1.1 200 OK  (application/octet-stream)")
    # The segment that arrived ahead of a gap is explained by the gap.
    assert "[TCP Previous segment not captured]" in rows[8]
    assert "reassembled PDU" not in rows[8]


def test_read_names_a_fragment_by_the_protocol_that_was_cut_up(
    capsys: pytest.CaptureFixture[str],
) -> None:
    samples = Path(__file__).resolve().parent.parent / "samples"
    assert main(["read", str(samples / "made" / "fragments.pcap")]) == 0
    rows = capsys.readouterr().out.splitlines()[1:]
    assert [row.split()[4] for row in rows] == [
        *["IPv4", "IPv4", "ICMP"] * 2,
        *["IPv4", "IPv4", "UDP", "IPv4"],
        *["IPv6", "ICMPv6"] * 2,
    ]


SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def test_read_with_a_display_filter(capsys: pytest.CaptureFixture[str]) -> None:
    capture = SAMPLES / "wireshark-wiki" / "http.cap"
    assert main(["read", "-Y", "http or dns", str(capture)]) == 0
    listed = capsys.readouterr().out.splitlines()
    # The packets tshark -Y lists, under the numbers they have in the file.
    assert [line.split()[0] for line in listed[1:]] == ["4", "13", "17", "18", "27", "38"]
    assert [line.split()[4] for line in listed[1:]] == [
        *["HTTP", "DNS", "DNS", "HTTP", "HTTP", "HTTP"],
    ]


def test_a_display_filter_hides_packets_without_forgetting_them(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Packets that aren't listed still count towards what the others say.

    The retransmission in packet 6 is one because of packet 4, which this
    filter leaves out, and its sequence number is still counted from the
    handshake, which it leaves out as well.
    """
    capture = SAMPLES / "made" / "tcp.pcap"
    assert main(["read", "-Y", "tcp.analysis.retransmission", str(capture)]) == 0
    listed = capsys.readouterr().out.splitlines()[1:]
    assert listed[0].split()[0] == "6"
    assert "[TCP Retransmission] 50000 → 80 [PSH, ACK] Seq=101 " in listed[0]


def test_a_display_filter_narrows_the_detail_view_too(capsys: pytest.CaptureFixture[str]) -> None:
    capture = SAMPLES / "wireshark-wiki" / "dns.cap"
    assert main(["read", "-V", "-Y", "frame.number in {2, 4}", str(capture)]) == 0
    listed = capsys.readouterr().out
    assert listed.startswith("Frame 2: ")
    assert listed.count("\nFrame ") == 1
    assert "\n\nFrame 4: " in listed


def test_an_empty_display_filter_lists_everything(capsys: pytest.CaptureFixture[str]) -> None:
    capture = SAMPLES / "wireshark-wiki" / "dns.cap"
    assert main(["read", "-Y", "", str(capture)]) == 0
    assert len(capsys.readouterr().out.splitlines()) == 1 + 38


@pytest.mark.macos
def test_a_capture_filter_and_a_display_filter_both_apply(
    capsys: pytest.CaptureFixture[str],
) -> None:
    capture = SAMPLES / "wireshark-wiki" / "http.cap"
    assert main(["read", "-f", "udp", "-Y", "dns.flags.response == 1", str(capture)]) == 0
    listed = capsys.readouterr().out.splitlines()
    assert [line.split()[0] for line in listed[1:]] == ["17"]


def test_a_display_filter_that_is_wrong_says_where(capsys: pytest.CaptureFixture[str]) -> None:
    capture = SAMPLES / "wireshark-wiki" / "http.cap"
    assert main(["read", "-Y", "ip.src == hello", str(capture)]) == 1
    output = capsys.readouterr()
    assert output.out == ""  # the error comes before any listing
    assert output.err == (
        'pilotfish: display filter: ip.src is an IPv4 address, and "hello" isn\'t one\n'
        "    ip.src == hello\n"
        "              ^~~~~\n"
    )


def test_a_wrong_display_filter_is_reported_before_the_file_is_opened(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["read", "-Y", "tcp.port ==", str(tmp_path / "missing.pcap")]) == 1
    assert capsys.readouterr().err == (
        "pilotfish: display filter: the filter ends where a field or a value was expected\n"
        "    tcp.port ==\n"
        "               ^\n"
    )


def test_filter_shows_what_a_display_filter_compiles_to(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["filter", "tcp.port in {80, 443} and not ip.addr == 10.0.0.0/8"]) == 0
    assert capsys.readouterr().out == (
        "Parsed as    (and (in tcp.port {80 443}) (not (== ip.addr 10.0.0.0/8)))\n"
        "Looks up     ip.dst, ip.src, tcp.dstport, tcp.srcport\n"
        "Compiled to  lambda found, data: any((n0.value in _k0 for n0 in "
        "found['tcp.srcport'] + found['tcp.dstport'])) and (not any((_k1 <= n1.value <= _k2 "
        "for n1 in found['ip.src'] + found['ip.dst'])))\n"
        "  where      _k0 = frozenset({80, 443})\n"
        "  where      _k1 = IPv4Address('10.0.0.0')\n"
        "  where      _k2 = IPv4Address('10.255.255.255')\n"
    )


def test_filter_says_what_is_wrong_with_a_filter(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["filter", "eth.src[0:3] == 00:1a:2g"]) == 1
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == (
        'pilotfish: display filter: "2g" isn\'t a byte; each one is two hexadecimal digits, '
        "as in 00:1a:2b\n"
        "    eth.src[0:3] == 00:1a:2g\n"
        "                          ^~\n"
    )


def test_filter_accepts_an_empty_filter(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["filter", ""]) == 0
    assert capsys.readouterr().out == "An empty filter, which every packet passes.\n"


def test_fields_lists_the_names_that_stand_for_two(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["fields"]) == 0
    listed = [line.split(maxsplit=2) for line in capsys.readouterr().out.splitlines()]
    assert ["ip.addr", "ipv4", "Source or Destination Address"] in listed
    assert ["tcp.port", "uint", "Source or Destination Port"] in listed
