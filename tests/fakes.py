"""A packet source that needs no network, for testing capture without the kernel."""

import threading
import time
from collections.abc import Iterable

from pilotfish.core.capture import CaptureError, KernelStats
from pilotfish.core.packet import Packet


def fake_packet(number: int) -> Packet:
    """Packet ``number``: stamped ``number`` seconds after the epoch, 60 bytes captured."""
    return Packet(
        timestamp_ns=number * 1_000_000_000,
        original_length=60 + number,
        link_type=1,
        data=bytes([number % 256]) * 60,
    )


class FakeSource:
    """Returns ``packets`` in order, then times out on every read.

    With ``fail_after``, the read after that many packets raises, as when an
    interface disappears in the middle of a capture.
    """

    interface = "fake0"
    link_type = 1

    def __init__(
        self,
        packets: Iterable[Packet] = (),
        *,
        fail_after: int | None = None,
        stats_fail: bool = False,
        warning: str | None = None,
    ) -> None:
        self.warning = warning
        self._packets = list(packets)
        self._next = 0
        self._fail_after = fail_after
        self._stats_fail = stats_fail
        self.exhausted = threading.Event()
        """Set once every packet has been read."""
        self.closed = False

    def read(self) -> Packet | None:
        if self.closed:
            raise CaptureError("fake0: capture is closed")
        if self._next == self._fail_after:
            raise CaptureError("fake0: the interface went away")
        if self._next < len(self._packets):
            packet = self._packets[self._next]
            self._next += 1
            return packet
        self.exhausted.set()
        time.sleep(0.001)  # stands in for the read timeout
        return None

    def stats(self) -> KernelStats:
        if self._stats_fail:
            raise CaptureError("fake0: no statistics")
        return KernelStats(received=self._next, dropped=0)

    def close(self) -> None:
        self.closed = True
