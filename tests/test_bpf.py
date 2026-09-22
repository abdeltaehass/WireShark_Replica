import errno
import os
import struct

import pytest
from hypothesis import given
from hypothesis import strategies as st

from loopback import UDP_PAYLOAD_OFFSET, LoopbackTraffic, carrying, read_until
from pilotfish.core.capture import (
    BpfSource,
    CaptureError,
    CaptureOptions,
    CapturePermissionError,
    PcapSource,
    bpf,
)
from pilotfish.core.packet import Packet


# Values printed by a C program built against <net/bpf.h> in the macOS SDK.
@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("BIOCGBLEN", 0x40044266),
        ("BIOCSBLEN", 0xC0044266),
        ("BIOCSETF", 0x80104267),
        ("BIOCPROMISC", 0x20004269),
        ("BIOCGDLT", 0x4004426A),
        ("BIOCSETIF", 0x8020426C),
        ("BIOCSRTIMEOUT", 0x8010426D),
        ("BIOCGSTATS", 0x4008426F),
        ("BIOCIMMEDIATE", 0x80044270),
        ("BIOCVERSION", 0x40044271),
    ],
)
def test_ioctl_numbers_match_the_sdk(name: str, value: int) -> None:
    assert getattr(bpf, name) == value


def bpf_record(
    packet: Packet, header_length: int = bpf.BPF_HEADER_SIZE, seconds: int | None = None
) -> bytes:
    """One record as the kernel writes it: header, padding, packet, padding to 4 bytes."""
    assert packet.timestamp_ns is not None
    whole_seconds, nanoseconds = divmod(packet.timestamp_ns, 1_000_000_000)
    header = struct.pack(
        "=IIIIH",
        whole_seconds if seconds is None else seconds,
        nanoseconds // 1_000,
        packet.captured_length,
        packet.original_length,
        header_length,
    )
    record = header.ljust(header_length, b"\0") + packet.data
    return record.ljust(-(-len(record) // 4) * 4, b"\0")


packets = st.builds(
    Packet,
    timestamp_ns=st.integers(0, 2**32 - 1).map(lambda seconds: seconds * 1_000_000_000)
    | st.integers(0, 2**32 * 1_000_000 - 1).map(lambda microseconds: microseconds * 1_000),
    original_length=st.integers(0, 2**32 - 1),
    link_type=st.just(1),
    data=st.binary(max_size=64),
)


@given(records=st.lists(st.tuples(packets, st.sampled_from([18, 20, 24, 32]))))
def test_parse_records_round_trips(records: list[tuple[Packet, int]]) -> None:
    buffer = b"".join(bpf_record(packet, header_length) for packet, header_length in records)
    assert list(bpf.parse_records(buffer, 1)) == [packet for packet, _ in records]


def test_records_follow_the_kernel_layout() -> None:
    # A real lo0 record from this Mac: 20-byte header, 40 bytes captured of 182.
    header = struct.pack("=IIIIH", 1790090335, 155331, 40, 182, 20) + b"\0\0"
    data = bytes(range(40))
    (packet,) = bpf.parse_records(header + data, 0)
    assert packet == Packet(1790090335_155331000, 182, 0, data)


def test_seconds_past_2038_read_as_unsigned() -> None:
    packet = Packet(0, 1, 1, b"x")
    (parsed,) = bpf.parse_records(bpf_record(packet, seconds=2**31 + 5), 1)
    assert parsed.timestamp_ns == (2**31 + 5) * 1_000_000_000


def test_short_header() -> None:
    record = bpf_record(Packet(0, 1, 1, b"x"))
    with pytest.raises(CaptureError, match="offset 20 is cut short: 17 of 18 header bytes"):
        list(bpf.parse_records(record + record[:17], 1))


@pytest.mark.parametrize(
    ("header_length", "message"),
    [(0, "0-byte header, shorter"), (17, "17-byte header, shorter"), (200, "past the end")],
)
def test_bad_header_length(header_length: int, message: str) -> None:
    record = bpf_record(Packet(0, 1, 1, b"xy"))
    broken = record[:16] + struct.pack("=H", header_length) + record[18:]
    with pytest.raises(CaptureError, match=message):
        list(bpf.parse_records(broken, 1))


def test_opens_the_first_free_device(monkeypatch: pytest.MonkeyPatch) -> None:
    tried: list[str] = []

    def fake_open(path: str, flags: int) -> int:
        tried.append(path)
        if len(tried) < 3:
            raise OSError(errno.EBUSY, "Resource busy")
        return 42

    monkeypatch.setattr(os, "open", fake_open)
    assert bpf.open_bpf_device() == (42, "/dev/bpf2")
    assert tried == ["/dev/bpf0", "/dev/bpf1", "/dev/bpf2"]


@pytest.mark.parametrize(
    ("error", "exception", "message"),
    [
        (errno.EACCES, CapturePermissionError, "/dev/bpf0: Permission denied"),
        (errno.ENOENT, CaptureError, "every BPF device is in use"),
        (errno.EIO, CaptureError, "/dev/bpf0: Input/output error"),
    ],
)
def test_device_open_errors(
    monkeypatch: pytest.MonkeyPatch, error: int, exception: type[CaptureError], message: str
) -> None:
    def fake_open(path: str, flags: int) -> int:
        raise OSError(error, os.strerror(error))

    monkeypatch.setattr(os, "open", fake_open)
    with pytest.raises(exception, match=f"^{message}$"):
        bpf.open_bpf_device()


def test_rejects_names_too_long_for_ifreq() -> None:
    with pytest.raises(CaptureError, match="at most 15 bytes"):
        BpfSource("a" * 16)


@pytest.mark.macos
@pytest.mark.usefixtures("capture_access")
class TestLiveCapture:
    def test_sees_the_same_packet_as_libpcap(self) -> None:
        direct = BpfSource("lo0")
        through_libpcap = PcapSource("lo0")
        try:
            assert direct.link_type == through_libpcap.link_type == 0
            with LoopbackTraffic() as traffic:
                payload = traffic.send()
                ours = read_until(direct, carrying(payload))
                theirs = read_until(through_libpcap, carrying(payload))
            assert ours.data == theirs.data
            assert ours.original_length == theirs.original_length
            assert ours.timestamp_ns is not None
            assert theirs.timestamp_ns is not None
            assert abs(ours.timestamp_ns - theirs.timestamp_ns) < 1_000_000
            assert direct.stats().received >= 1
        finally:
            direct.close()
            through_libpcap.close()

    def test_snapshot_length_comes_from_the_filter_program(self) -> None:
        source = BpfSource("lo0", CaptureOptions(snaplen=40))
        try:
            with LoopbackTraffic() as traffic:
                payload = traffic.send(100)
                packet = read_until(
                    source,
                    lambda packet: packet.data[UDP_PAYLOAD_OFFSET:] == payload[:8],
                )
            assert packet.captured_length == 40
            assert packet.original_length == UDP_PAYLOAD_OFFSET + 100
        finally:
            source.close()

    def test_buffer_size_is_what_the_kernel_granted(self) -> None:
        source = BpfSource("lo0", CaptureOptions(buffer_size=1024 * 1024))
        try:
            assert source.buffer_length == 1024 * 1024
        finally:
            source.close()

    def test_unknown_interface(self) -> None:
        with pytest.raises(CaptureError, match=r"^nope0: No such device exists$"):
            BpfSource("nope0")

    def test_closed_source_refuses_to_read(self) -> None:
        source = BpfSource("lo0")
        source.close()
        with pytest.raises(CaptureError, match="capture is closed"):
            source.read()
