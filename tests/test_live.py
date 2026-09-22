import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from fakes import FakeSource, fake_packet
from loopback import LoopbackTraffic
from pilotfish.core.capture import CaptureError, KernelStats, LiveCapture, PcapSource
from pilotfish.core.packet import Packet


def captured_then_stopped(source: FakeSource, queue_size: int = 100) -> LiveCapture:
    """Start a capture, let the source run dry, then stop it."""
    capture = LiveCapture(source, queue_size)
    capture.start()
    assert source.exhausted.wait(5)
    capture.stop()
    return capture


def test_delivers_every_packet_in_order() -> None:
    packets = [fake_packet(number) for number in range(50)]
    source = FakeSource(packets)
    capture = captured_then_stopped(source)
    assert list(capture) == packets
    capture.join()
    assert source.closed
    assert (capture.received, capture.dropped) == (50, 0)
    assert capture.kernel_stats == KernelStats(received=50, dropped=0)


def test_packets_arrive_while_the_capture_runs() -> None:
    source = FakeSource([fake_packet(number) for number in range(5)])
    with LiveCapture(source) as capture:
        seen = 0
        for _ in capture:
            seen += 1
            if seen == 5:
                capture.stop()
    assert seen == 5


def test_full_queue_drops_new_packets_and_counts_them() -> None:
    packets = [fake_packet(number) for number in range(10)]
    capture = captured_then_stopped(FakeSource(packets), queue_size=3)
    assert list(capture) == packets[:3]
    assert (capture.received, capture.dropped) == (10, 7)


@settings(max_examples=20)
@given(count=st.integers(0, 40), queue_size=st.integers(1, 20))
def test_every_packet_is_delivered_or_counted(count: int, queue_size: int) -> None:
    packets = [fake_packet(number) for number in range(count)]
    capture = captured_then_stopped(FakeSource(packets), queue_size)
    delivered = list(capture)
    assert delivered == packets[:queue_size]
    assert len(delivered) + capture.dropped == capture.received == count


def test_error_ends_iteration_after_the_packets_before_it() -> None:
    source = FakeSource([fake_packet(number) for number in range(5)], fail_after=3)
    capture = LiveCapture(source)
    capture.start()
    seen: list[Packet] = []
    with pytest.raises(CaptureError, match="the interface went away"):
        seen.extend(capture)
    assert len(seen) == 3
    capture.join()
    assert source.closed
    assert capture.kernel_stats == KernelStats(received=3, dropped=0)


def test_missing_statistics_are_none() -> None:
    capture = captured_then_stopped(FakeSource(stats_fail=True))
    capture.join()
    assert capture.kernel_stats is None
    assert capture.error is None


def test_stops_promptly_with_no_traffic() -> None:
    capture = LiveCapture(FakeSource())
    capture.start()
    started = time.monotonic()
    capture.stop()
    assert list(capture) == []
    capture.join()
    assert time.monotonic() - started < 1


def test_join_without_start_closes_the_source() -> None:
    source = FakeSource([fake_packet(1)])
    capture = LiveCapture(source)
    capture.stop()
    capture.join()
    assert source.closed
    assert list(capture) == []


@pytest.mark.macos
@pytest.mark.usefixtures("capture_access")
def test_live_loopback_capture_loses_nothing() -> None:
    capture = LiveCapture(PcapSource("lo0"))
    with LoopbackTraffic() as traffic, capture:
        payloads = {traffic.send() for _ in range(20)}
        deadline = time.monotonic() + 5
        for packet in capture:
            payloads.discard(bytes(packet.data[-32:]))
            if not payloads or time.monotonic() > deadline:
                break
    assert not payloads
    assert capture.dropped == 0
    assert capture.kernel_stats is not None
    assert capture.kernel_stats.received >= 20
    assert capture.kernel_stats.dropped == 0
