import ctypes
import time

import pytest

from loopback import UDP_PAYLOAD_OFFSET, LoopbackTraffic, carrying, read_until
from pilotfish.core.capture import CaptureError, CaptureOptions, PcapSource
from pilotfish.core.capture.libpcap import PcapAddr, PcapIf, PcapPkthdr, PcapStat, Timeval

# Sizes and offsets printed by a C program built against <pcap/pcap.h> in the
# macOS SDK, so a mistake in a ctypes field list shows up here.


@pytest.mark.parametrize(
    ("structure", "size"),
    [(Timeval, 16), (PcapPkthdr, 280), (PcapStat, 12), (PcapIf, 40), (PcapAddr, 40)],
    ids=lambda value: getattr(value, "__name__", str(value)),
)
def test_structure_sizes_match_the_sdk(structure: type[ctypes.Structure], size: int) -> None:
    assert ctypes.sizeof(structure) == size


@pytest.mark.parametrize(
    ("structure", "field", "offset"),
    [
        (Timeval, "tv_usec", 8),
        (PcapPkthdr, "caplen", 16),
        (PcapPkthdr, "len", 20),
        (PcapIf, "name", 8),
        (PcapIf, "description", 16),
        (PcapIf, "addresses", 24),
        (PcapIf, "flags", 32),
    ],
)
def test_field_offsets_match_the_sdk(
    structure: type[ctypes.Structure], field: str, offset: int
) -> None:
    assert getattr(structure, field).offset == offset


@pytest.mark.macos
@pytest.mark.usefixtures("capture_access")
class TestLiveCapture:
    def test_captures_a_datagram_on_loopback(self) -> None:
        source = PcapSource("lo0")
        try:
            assert source.link_type == 0  # LINKTYPE_NULL: a 4-byte address family first
            with LoopbackTraffic() as traffic:
                before = time.time_ns()
                payload = traffic.send()
                packet = read_until(source, carrying(payload))
            assert packet.data[UDP_PAYLOAD_OFFSET:] == payload
            assert packet.original_length == packet.captured_length == UDP_PAYLOAD_OFFSET + 32
            assert packet.timestamp_ns is not None
            assert abs(packet.timestamp_ns - before) < 5_000_000_000
            assert source.stats().received >= 1
        finally:
            source.close()

    def test_snapshot_length_cuts_packets_short(self) -> None:
        source = PcapSource("lo0", CaptureOptions(snaplen=40))
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

    def test_read_times_out_without_traffic(self) -> None:
        # Other programs may be talking over loopback, so read until one read
        # comes back empty instead of expecting the first one to.
        source = PcapSource("lo0", CaptureOptions(timeout_ms=50))
        try:
            started = time.monotonic()
            while source.read() is not None:
                pass
            assert time.monotonic() - started < 5
        finally:
            source.close()

    def test_unknown_interface(self) -> None:
        with pytest.raises(CaptureError, match=r"^nope0: No such device exists$"):
            PcapSource("nope0")

    def test_closed_source_refuses_to_read(self) -> None:
        source = PcapSource("lo0")
        source.close()
        source.close()
        with pytest.raises(CaptureError, match="capture is closed"):
            source.read()
