"""pilotfish as a command line tool, run the way a script would run it.

These go through ``main()`` or through the installed ``pilotfish`` command,
and check what comes out the other end: JSON that jq can read and that says
what tshark's says, fields laid out as tshark lays them out, hex dumps, files
written with -w that read back as the packets that went in, pipes in both
directions, and an exit status for every way a run can fail.
"""

import csv
import io
import json
import shutil
import signal
import subprocess
import sys
from pathlib import Path

import pytest

import tshark
from fakes import FakeSource, fake_packet
from pilotfish.cli import capture, interfaces
from pilotfish.cli.export import (
    FieldPicker,
    FieldsFormat,
    JsonPrinter,
    field_text,
    index_name,
    tree_text,
)
from pilotfish.cli.hexdump import hex_dump
from pilotfish.cli.main import main
from pilotfish.cli.pipeline import Pipeline
from pilotfish.cli.status import CommandError, Exit
from pilotfish.core.capture import CaptureError, CaptureOptions, Device, PacketSource
from pilotfish.core.dissect import (
    REGISTRY,
    Field,
    FieldRegistry,
    FieldType,
    Node,
    Value,
    dissect,
)
from pilotfish.core.formats import CaptureFile
from pilotfish.core.packet import Packet

SAMPLES = tshark.SAMPLES_DIR
DNS = SAMPLES / "wireshark-wiki" / "dns.cap"
HTTP = SAMPLES / "wireshark-wiki" / "http.cap"
MIXED = SAMPLES / "wireshark-wiki" / "pcapng-example.pcapng"
COMMAND = str(Path(sys.executable).with_name("pilotfish"))
"""The console script the package installs, as pipx would put it on the PATH."""

CAPTURE_SUFFIXES = frozenset({".cap", ".ntar", ".pcap", ".pcapng"})
ALL_CAPTURES = sorted(p for p in SAMPLES.rglob("*") if p.suffix in CAPTURE_SUFFIXES)


def sample_id(capture: Path) -> str:
    return str(capture.relative_to(SAMPLES))


def run(*argv: str, stdin: bytes | None = None) -> subprocess.CompletedProcess[bytes]:
    """The installed command, run as a separate program."""
    return subprocess.run([COMMAND, *argv], input=stdin, capture_output=True, check=False)


def output(capsys: pytest.CaptureFixture[str], *argv: str) -> str:
    assert main(list(argv)) == Exit.OK
    return capsys.readouterr().out


def test_the_package_installs_a_pilotfish_command() -> None:
    result = run("--version")
    assert result.returncode == 0
    assert result.stdout.decode().startswith("pilotfish ")


@pytest.mark.skipif(shutil.which("jq") is None, reason="needs jq")
def test_json_pipes_into_jq() -> None:
    """The phase's own measure: pilotfish -r sample -Y dns -T json | jq."""
    pilotfish = subprocess.Popen(
        [COMMAND, "-r", str(DNS), "-Y", "dns", "-T", "json"], stdout=subprocess.PIPE
    )
    names = subprocess.run(
        ["jq", "-r", '.[]._source.layers.dns."dns.qry.name"'],
        stdin=pilotfish.stdout,
        capture_output=True,
        text=True,
        check=True,
    )
    assert pilotfish.stdout is not None
    pilotfish.stdout.close()
    assert pilotfish.wait() == 0
    asked = names.stdout.splitlines()
    assert len(asked) == 38
    assert asked[:3] == ["google.com", "google.com", "google.com"]


class TestJson:
    def test_it_is_an_array_of_tshark_shaped_packets(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        packets = json.loads(output(capsys, "-r", str(DNS), "-c", "2", "-T", "json"))
        assert len(packets) == 2
        first = packets[0]
        assert set(first) == {"_index", "_score", "_source"}
        assert first["_index"] == "packets-2005-03-30"
        assert first["_score"] is None
        layers = first["_source"]["layers"]
        assert list(layers) == ["frame", "eth", "ip", "udp", "dns"]
        assert layers["ip"]["ip.src"] == "192.168.170.8"
        # A field's own fields sit under <name>_tree.
        assert layers["ip"]["ip.flags_tree"]["ip.flags.df"] == "1"
        assert layers["frame"]["frame.time_epoch"] == "1112172466.496046000"

    def test_nothing_matched_is_an_empty_array(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert output(capsys, "-r", str(DNS), "-Y", "tcp", "-T", "json") == "[]\n"

    def test_a_field_that_repeats_becomes_a_list(self, capsys: pytest.CaptureFixture[str]) -> None:
        # Packet 4 answers with six mail servers.
        packets = json.loads(
            output(capsys, "-r", str(DNS), "-Y", "frame.number == 4", "-T", "json")
        )
        exchanges = packets[0]["_source"]["layers"]["dns"]["dns.mx.mail_exchange"]
        assert isinstance(exchanges, list)
        assert len(exchanges) == 6

    def test_e_picks_fields(self, capsys: pytest.CaptureFixture[str]) -> None:
        text = output(
            capsys, "-r", str(DNS), "-c", "2", "-T", "json", "-e", "ip.addr", "-e", "dns.a"
        )
        packets = json.loads(text)
        # Fields a packet doesn't have are left out, as tshark leaves them out.
        assert [entry["_source"]["layers"] for entry in packets] == [
            {"ip.addr": ["192.168.170.8", "192.168.170.20"]},
            {"ip.addr": ["192.168.170.20", "192.168.170.8"]},
        ]

    @pytest.mark.parametrize("capture", tshark.captures_with_keys(), ids=sample_id)
    def test_every_value_says_what_tshark_says(
        self, capture: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The JSON, read back, holds the values tshark's JSON holds.

        This is the dissector comparison of test_tshark.py done again through
        the printed JSON, so it checks the export as much as the decoding.
        """
        packets = json.loads(output(capsys, "-r", str(capture), "-T", "json"))
        expected = tshark.packets(capture)
        assert len(packets) == len(expected)
        skipped = {"frame.len", "frame.cap_len", "data.data", "data.len"}
        for entry, fields in zip(packets, expected, strict=True):
            printed = tshark.fields_of(entry)
            decoded: dict[str, list[Value]] = {
                name: [tshark.as_value(REGISTRY.fields[name], text) for text in texts]
                for name, texts in printed.items()
                if name in fields and name in REGISTRY.fields and name not in skipped
            }
            tshark.compare_values(decoded, fields)


class TestFields:
    def test_one_line_per_packet_a_column_per_field(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        text = output(
            capsys,
            *("-r", str(HTTP), "-c", "4", "-T", "fields"),
            *("-e", "frame.number", "-e", "ip.addr", "-e", "tcp.flags.syn"),
            *("-e", "http.request.method", "-e", "tcp.options", "-e", "_ws.col.protocol"),
        )
        assert text.splitlines() == [
            "1\t145.254.160.237,65.208.228.223\tTrue\t\t020405b401010402\tTCP",
            "2\t65.208.228.223,145.254.160.237\tTrue\t\t0204056401010402\tTCP",
            "3\t145.254.160.237,65.208.228.223\tFalse\t\t\tTCP",
            "4\t145.254.160.237,65.208.228.223\tFalse\tGET\t\tHTTP",
        ]

    def test_e_options_lay_the_values_out(self, capsys: pytest.CaptureFixture[str]) -> None:
        text = output(
            capsys,
            *("-r", str(HTTP), "-c", "4", "-T", "fields"),
            *("-E", "header=y", "-E", "separator=,", "-E", "quote=d", "-E", "occurrence=f"),
            *("-e", "frame.number", "-e", "ip.addr", "-e", "http.host"),
        )
        # tshark's output for the same flags, character for character.
        assert text.splitlines() == [
            "frame.number,ip.addr,http.host",
            '"1","145.254.160.237",',
            '"2","65.208.228.223",',
            '"3","145.254.160.237",',
            '"4","145.254.160.237","www.ethereal.com"',
        ]

    def test_the_last_occurrence_and_another_aggregator(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        text = output(
            capsys,
            *("-r", str(HTTP), "-c", "1", "-T", "fields", "-e", "ip.addr", "-e", "ip.addr"),
            *("-E", "aggregator=/s", "-E", "separator=/s"),
        )
        assert text == "145.254.160.237 65.208.228.223 145.254.160.237 65.208.228.223\n"
        text = output(
            capsys,
            "-r",
            str(HTTP),
            "-c",
            "1",
            "-T",
            "fields",
            "-e",
            "ip.addr",
            "-E",
            "occurrence=l",
        )
        assert text == "65.208.228.223\n"

    @pytest.mark.parametrize("capture", ALL_CAPTURES, ids=sample_id)
    def test_times_and_lengths_match_tshark(
        self, capture: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Every sample, against the tshark -T fields output recorded beside it."""
        text = output(
            capsys,
            *("-r", str(capture), "-T", "fields", "-E", "header=y"),
            *("-e", "frame.time_epoch", "-e", "frame.len", "-e", "frame.cap_len"),
        )
        ours = list(csv.DictReader(io.StringIO(text), delimiter="\t"))
        key = capture.with_name(f"{capture.name}.tshark.tsv")
        with key.open(newline="") as file:
            theirs = list(csv.DictReader(file, delimiter="\t", quoting=csv.QUOTE_NONE))
        assert len(ours) == len(theirs)
        with CaptureFile(capture) as file:
            link_types = [packet.link_type for packet in file]
        for mine, its, link_type in zip(ours, theirs, link_types, strict=True):
            hidden = tshark.WIRESHARK_PSEUDO_HEADER_BYTES.get(link_type, 0)
            assert tshark.parse_time(mine["frame.time_epoch"]) == tshark.parse_time(
                its["frame.time_epoch"]
            )
            assert int(mine["frame.len"]) - hidden == int(its["frame.len"])
            assert int(mine["frame.cap_len"]) - hidden == int(its["frame.cap_len"])


class TestHexDump:
    def test_a_packet_dumps_as_tshark_dumps_it(self, capsys: pytest.CaptureFixture[str]) -> None:
        # tshark -r dns.cap -c 1 -x, character for character.
        assert output(capsys, "-r", str(DNS), "-c", "1", "-x") == (
            "0000  00 c0 9f 32 41 8c 00 e0 18 b1 0c ad 08 00 45 00   ...2A.........E.\n"
            "0010  00 38 00 00 40 00 40 11 65 47 c0 a8 aa 08 c0 a8   .8..@.@.eG......\n"
            "0020  aa 14 80 1b 00 35 00 24 85 ed 10 32 01 00 00 01   .....5.$...2....\n"
            "0030  00 00 00 00 00 00 06 67 6f 6f 67 6c 65 03 63 6f   .......google.co\n"
            "0040  6d 00 00 10 00 01                                 m.....\n"
            "\n"
        )

    def test_reassembled_bytes_follow_the_packets_own(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        text = output(capsys, "-r", str(HTTP), "-Y", "frame.number == 38", "-x")
        headings = [line for line in text.splitlines() if line.endswith("bytes):")]
        assert headings == ["Packet (478 bytes):", "Reassembled TCP (18364 bytes):"]

    def test_tree_then_bytes(self, capsys: pytest.CaptureFixture[str]) -> None:
        text = output(capsys, "-r", str(DNS), "-c", "2", "-V", "-x")
        first, _ = text.split("Frame 2:")
        assert first.startswith("Frame 1: ")
        assert first.endswith("m.....\n\n")
        assert "\n\n0000  00 c0 9f 32" in first

    @pytest.mark.parametrize(
        ("data", "expected"),
        [
            (b"", ""),
            (b"A", "0000  41                                                A\n"),
            (
                bytes(range(16)),
                "0000  " + " ".join(f"{b:02x}" for b in range(16)) + "   " + "." * 16 + "\n",
            ),
        ],
    )
    def test_lines(self, data: bytes, expected: str) -> None:
        assert hex_dump(data) == expected

    def test_the_offset_widens_past_64_kib(self) -> None:
        lines = hex_dump(bytes(70_000)).splitlines()
        assert lines[0].startswith("00000  ")
        # The last line starts 16 bytes before the 70,000th.
        assert lines[-1].startswith("11160  ")


class TestWriting:
    @pytest.mark.parametrize("file_format", ["pcapng", "pcap"])
    def test_a_file_written_reads_back_the_same(
        self, tmp_path: Path, file_format: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        written = tmp_path / f"copy.{file_format}"
        assert main(["-r", str(HTTP), "-w", str(written), "-F", file_format]) == Exit.OK
        # Writing prints nothing unless asked to.
        assert capsys.readouterr().out == ""
        with CaptureFile(HTTP) as original, CaptureFile(written) as copy:
            assert copy.format == file_format
            assert [(p.timestamp_ns, bytes(p.data)) for p in copy] == [
                (p.timestamp_ns, bytes(p.data)) for p in original
            ]

    def test_only_the_packets_kept_are_written(self, tmp_path: Path) -> None:
        written = tmp_path / "http.pcapng"
        assert main(["-r", str(HTTP), "-Y", "http", "-w", str(written)]) == Exit.OK
        with CaptureFile(HTTP) as original:
            kept = [
                bytes(p.data) for number, p in enumerate(original, 1) if number in {4, 18, 27, 38}
            ]
        with CaptureFile(written) as copy:
            assert [bytes(p.data) for p in copy] == kept

    def test_p_prints_while_writing(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        text = output(capsys, "-r", str(DNS), "-c", "2", "-w", str(tmp_path / "x.pcapng"), "-P")
        assert len(text.splitlines()) == 3  # the header and two packets

    def test_quiet_prints_nothing(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert output(capsys, "-r", str(DNS), "-q") == ""

    def test_through_a_pipe_both_ways(self) -> None:
        written = run("-r", str(HTTP), "-w", "-")
        assert written.returncode == 0
        assert written.stdout.startswith(b"\x0a\x0d\x0d\x0a")
        read = run(
            "-r", "-", "-Y", "http.request", "-T", "fields", "-e", "http.host", stdin=written.stdout
        )
        assert read.returncode == 0
        assert read.stdout.decode().splitlines() == [
            "www.ethereal.com",
            "pagead2.googlesyndication.com",
        ]

    def test_reading_standard_input(self) -> None:
        read = run(
            "-r", "-", "-c", "3", "-T", "fields", "-e", "frame.number", stdin=DNS.read_bytes()
        )
        assert read.stdout == b"1\n2\n3\n"
        empty = run("-r", "-", stdin=b"")
        assert empty.returncode == Exit.INVALID_FILE
        assert empty.stderr == b"pilotfish: standard input: file is empty\n"


class TestCount:
    def test_c_counts_packets_read_not_packets_kept(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """tshark's -c with -Y: three packets are read, and only the third is kept."""
        text = output(
            capsys,
            "-r",
            str(HTTP),
            "-c",
            "3",
            "-Y",
            "frame.number > 2",
            "-T",
            "fields",
            "-e",
            "frame.number",
        )
        assert text == "3\n"

    def test_c_stops_early(self, capsys: pytest.CaptureFixture[str]) -> None:
        assert (
            output(capsys, "-r", str(DNS), "-c", "2", "-T", "fields", "-e", "frame.number")
            == "1\n2\n"
        )


@pytest.mark.parametrize(
    ("argv", "status", "error"),
    [
        (["-r", "missing.pcap"], Exit.INVALID_FILE, "pilotfish: missing.pcap: No such file"),
        (["-r", str(SAMPLES / "README.md")], Exit.INVALID_FILE, "not a pcap or pcapng file"),
        (["-r", str(DNS), "-Y", "tcp.port ="], Exit.INVALID_FILTER, "display filter: a single"),
        (["-r", str(DNS), "-i", "en0"], Exit.INVALID_OPTION, "give one or the other"),
        (["-r", str(DNS), "-s", "96"], Exit.INVALID_OPTION, "-s only means something"),
        (["-r", str(DNS), "-p", "-B", "8"], Exit.INVALID_OPTION, "-p, -B only mean something"),
        (["-r", str(DNS), "-e", "ip.src"], Exit.INVALID_OPTION, "-e names fields for -T fields"),
        (["-r", str(DNS), "-T", "fields"], Exit.INVALID_OPTION, "and none were"),
        (["-r", str(DNS), "-T", "json", "-x"], Exit.INVALID_OPTION, "not -T json"),
        (["-r", str(DNS), "-T", "fields", "-e", "ip.src", "-V"], Exit.INVALID_OPTION, "-V prints"),
        (["-r", str(DNS), "-E", "header=y"], Exit.INVALID_OPTION, "add -T fields"),
        (
            ["-r", str(DNS), "-T", "fields", "-e", "ip.src", "-E", "nope"],
            Exit.INVALID_OPTION,
            '"nope" isn\'t a -E option',
        ),
        (
            ["-r", str(DNS), "-T", "fields", "-e", "nope"],
            Exit.INVALID_OPTION,
            "some fields aren't valid:\n    nope",
        ),
        (["-r", str(DNS), "-F", "pcap"], Exit.INVALID_OPTION, "add -w FILE"),
        (["-r", str(DNS), "-d"], Exit.INVALID_OPTION, "give the filter with -f"),
        (["-r", str(DNS), "-w", "-", "-P"], Exit.INVALID_OPTION, "can't be printed there too"),
        (
            ["-r", str(DNS), "-w", "/nonexistent/x.pcapng"],
            Exit.OPEN_ERROR,
            "No such file or directory",
        ),
        (["-r", str(MIXED), "-w", "/dev/null", "-F", "pcap"], Exit.WRITE_ERROR, "one link type"),
        (["follow", "missing.pcap", "0"], Exit.INVALID_FILE, "missing.pcap"),
        (["filter", "tcp.prot"], Exit.INVALID_FILTER, 'did you mean "tcp.port"'),
    ],
)
def test_every_failure_has_its_status(
    argv: list[str], status: Exit, error: str, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(argv) == status
    assert error in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv",
    [["-c", "0"], ["-c", "x"], ["--bogus"], ["-T", "xml"], ["-c", "3", "read", str(DNS)]],
)
def test_a_command_line_that_makes_no_sense_exits_with_1(
    argv: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as exited:
        main(argv)
    assert exited.value.code == Exit.INVALID_OPTION
    assert "pilotfish: " in capsys.readouterr().err


def test_a_file_cut_short_still_closes_its_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cut = tmp_path / "cut.pcap"
    cut.write_bytes(HTTP.read_bytes()[:1000])
    assert main(["-r", str(cut), "-T", "json"]) == Exit.READ_ERROR
    output = capsys.readouterr()
    # The packets before the damage, as valid JSON, and then the reason.
    assert len(json.loads(output.out)) == 5
    assert output.err == f"pilotfish: {cut}: packet at offset 869 is cut short: 115 of 1434 bytes\n"


def test_a_reader_that_goes_away_ends_the_run_with_141() -> None:
    pilotfish = subprocess.Popen(
        [COMMAND, "-r", str(SAMPLES / "wireshark-wiki" / "arp-storm.pcap"), "-V"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert pilotfish.stdout is not None
    pilotfish.stdout.read(100)
    pilotfish.stdout.close()
    _, err = pilotfish.communicate()
    assert pilotfish.returncode == Exit.BROKEN_PIPE
    assert err == b""


class TestLive:
    """Live capture through the same flags, from a source that needs no network."""

    @pytest.fixture
    def opened(self, monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, CaptureOptions]]:
        opened: list[tuple[str, CaptureOptions]] = []

        def open_source(interface: str, options: CaptureOptions) -> PacketSource:
            opened.append((interface, options))
            return FakeSource([fake_packet(number) for number in range(1, 6)])

        devices = [Device("fake0", 0x16, description="Fake Ethernet")]
        monkeypatch.setattr(capture, "list_devices", lambda: devices)
        monkeypatch.setattr(interfaces, "list_devices", lambda: devices)
        monkeypatch.setitem(capture._SOURCES, "libpcap", open_source)
        return opened

    def test_flags_alone_capture_on_the_default_interface(
        self, opened: list[tuple[str, CaptureOptions]], capsys: pytest.CaptureFixture[str]
    ) -> None:
        packets = json.loads(output(capsys, "-c", "2", "-T", "json"))
        assert len(packets) == 2
        assert [interface for interface, _ in opened] == ["fake0"]

    def test_the_capture_options_reach_the_source(
        self, opened: list[tuple[str, CaptureOptions]], capsys: pytest.CaptureFixture[str]
    ) -> None:
        output(capsys, "-i", "fake0", "-c", "1", "-f", "udp", "-s", "96", "-p", "-B", "64", "-q")
        assert opened == [
            (
                "fake0",
                CaptureOptions(snaplen=96, promiscuous=False, buffer_size=64 * 1024, filter="udp"),
            )
        ]

    def test_a_display_filter_keeps_some_but_all_are_counted(
        self, opened: list[tuple[str, CaptureOptions]], capsys: pytest.CaptureFixture[str]
    ) -> None:
        text = output(
            capsys, "-c", "4", "-Y", "udp.srcport > 1026", "-T", "fields", "-e", "frame.number"
        )
        assert text == "3\n4\n"

    def test_writing_a_live_capture(
        self, opened: list[tuple[str, CaptureOptions]], tmp_path: Path
    ) -> None:
        written = tmp_path / "live.pcapng"
        assert main(["-i", "fake0", "-c", "3", "-w", str(written)]) == Exit.OK
        data = written.read_bytes()
        assert b"fake0" in data  # the interface is named in the file
        with CaptureFile(written) as file:
            assert [bytes(p.data) for p in file] == [bytes(fake_packet(n).data) for n in (1, 2, 3)]

    def test_d_lists_interfaces_as_tshark_does(
        self, opened: list[tuple[str, CaptureOptions]], capsys: pytest.CaptureFixture[str]
    ) -> None:
        assert output(capsys, "-D") == "1. fake0 (Fake Ethernet)\n"

    def test_an_interface_that_isnt_there(
        self,
        opened: list[tuple[str, CaptureOptions]],
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        def refuse(interface: str, options: CaptureOptions) -> PacketSource:
            raise CaptureError(f"{interface}: No such device exists")

        monkeypatch.setitem(capture._SOURCES, "libpcap", refuse)
        assert main(["-i", "nosuch0"]) == Exit.INVALID_INTERFACE
        assert capsys.readouterr().err == (
            'pilotfish: there is no interface named "nosuch0"; `pilotfish -D` lists them\n'
        )

    def test_ctrl_c_still_leaves_valid_json(self) -> None:
        source = FakeSource([fake_packet(number) for number in range(1, 6)])
        out, err = io.StringIO(), io.StringIO()
        pipeline = Pipeline(out, printer=JsonPrinter(out))
        original = pipeline.packet

        def packet(number: int, packet: Packet) -> bool:
            if number == 1:
                # Every packet is queued before Ctrl+C is pressed.
                assert source.exhausted.wait(5)
            passed = original(number, packet)
            if number == 2:
                signal.raise_signal(signal.SIGINT)
            return passed

        pipeline.packet = packet  # type: ignore[method-assign]
        assert capture.run(source, pipeline, out=out, err=err) == Exit.OK
        # Everything already captured is still printed, and the array is closed.
        assert len(json.loads(out.getvalue())) == 5


class TestValueText:
    """How a value is written, for the tree in JSON and for -T fields."""

    @staticmethod
    def node(field_type: FieldType, value: Value | None, **extra: object) -> Node:
        return Node("t.x", "X", field_type, 0, 2, value=value, **extra)  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        ("field_type", "value", "extra", "in_tree", "in_fields"),
        [
            (FieldType.BOOL, True, {}, "1", "True"),
            (FieldType.BOOL, False, {}, "0", "False"),
            (FieldType.BYTES, b"\x01\xab", {}, "01:ab", "01ab"),
            (FieldType.BYTES, b"", {}, "", ""),
            (FieldType.UINT, 80, {}, "80", "80"),
            (FieldType.UINT, 0x12, {"hex": True}, "0x0012", "0x0012"),
            (FieldType.UINT, 0x12, {"hex": True, "digits": 3}, "0x012", "0x012"),
            (FieldType.INT, -1, {}, "-1", "-1"),
            (
                FieldType.TIME,
                1_112_172_466_496_046_000,
                {},
                "1112172466.496046000",
                "1112172466.496046000",
            ),
            (FieldType.STRING, "GET", {}, "GET", "GET"),
        ],
    )
    def test_values(
        self,
        field_type: FieldType,
        value: Value,
        extra: dict[str, object],
        in_tree: str,
        in_fields: str,
    ) -> None:
        node = self.node(field_type, value, **extra)
        assert tree_text(node) == in_tree
        assert field_text(node) == in_fields

    def test_a_protocol_is_its_summary(self) -> None:
        layer = Node(
            "tcp", "Transmission Control Protocol", FieldType.PROTOCOL, 0, 20, summary="TCP, Src"
        )
        assert field_text(layer) == "TCP, Src"
        layer.summary = ""
        assert field_text(layer) == "Transmission Control Protocol"

    def test_the_index_is_the_day_in_utc(self) -> None:
        assert index_name(Packet(1_112_172_466_496_046_000, 1, 1, b"\x00")) == "packets-2005-03-30"
        assert index_name(Packet(None, 1, 1, b"\x00")) == "packets-1970-01-01"


class TestFieldsFormat:
    @pytest.mark.parametrize(
        ("option", "attribute", "value"),
        [
            ("header=y", "header", True),
            ("header=n", "header", False),
            ("separator=/t", "separator", "\t"),
            ("separator=/s", "separator", " "),
            ("separator=;", "separator", ";"),
            ("aggregator=/s", "aggregator", " "),
            ("aggregator=|", "aggregator", "|"),
            ("occurrence=f", "occurrence", "f"),
            ("occurrence=l", "occurrence", "l"),
            ("quote=d", "quote", '"'),
            ("quote=s", "quote", "'"),
            ("quote=n", "quote", ""),
        ],
    )
    def test_options(self, option: str, attribute: str, value: object) -> None:
        layout = FieldsFormat()
        layout.set(option)
        assert getattr(layout, attribute) == value

    @pytest.mark.parametrize(
        "option", ["header", "header=yes", "occurrence=2", "quote=x", "separator=", "bom=y", "=y"]
    )
    def test_anything_else_is_refused(self, option: str) -> None:
        with pytest.raises(CommandError) as caught:
            FieldsFormat().set(option)
        assert caught.value.status is Exit.INVALID_OPTION


class TestFieldPicker:
    def test_columns_by_tshark_name(self) -> None:
        picker = FieldPicker(
            ["_ws.col.number", "_ws.col.Protocol", "_ws.col.info", "_ws.col.def_src"],
            REGISTRY.fields,
        )
        with CaptureFile(DNS) as file:
            packet = next(iter(file))
        values = picker.pick(7, packet, dissect(packet))
        assert values == [
            ["7"],
            ["DNS"],
            ["Standard query 0x1032 TXT google.com"],
            ["192.168.170.8"],
        ]

    def test_unknown_names_are_all_reported_at_once(self) -> None:
        with pytest.raises(CommandError) as caught:
            FieldPicker(["ip.src", "nope", "_ws.col.nope"], REGISTRY.fields)
        assert caught.value.details == ("nope", "_ws.col.nope")

    def test_a_field_can_be_asked_for_twice(self) -> None:
        fields = REGISTRY.fields
        picker = FieldPicker(["ip.src", "ip.addr", "ip.src"], fields)
        with CaptureFile(DNS) as file:
            packet = next(iter(file))
        assert picker.pick(1, packet, dissect(packet)) == [
            ["192.168.170.8"],
            ["192.168.170.8", "192.168.170.20"],
            ["192.168.170.8"],
        ]

    def test_a_registry_of_its_own(self) -> None:
        fields = FieldRegistry()
        fields.add(Field("t.x", FieldType.UINT, "X"))
        with pytest.raises(CommandError):
            FieldPicker(["ip.src"], fields)
        assert FieldPicker(["t.x"], fields).names == ("t.x",)
