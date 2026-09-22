"""Run a packet source on its own thread and hand packets over through a queue."""

import queue
import threading
from collections.abc import Iterator
from types import TracebackType
from typing import Self

from pilotfish.core.capture.source import KernelStats, PacketSource
from pilotfish.core.packet import Packet

DEFAULT_QUEUE_SIZE = 10_000

# How often a consumer waiting on an empty queue checks whether capture has ended.
_POLL_SECONDS = 0.05


class LiveCapture:
    """Captures packets from ``source`` on a background thread.

    The thread spends most of its time inside ``source.read()``, which waits
    in C with the GIL released, so whoever consumes the packets keeps
    running. Packets travel through a queue of at most ``queue_size``. When the
    consumer falls behind and the queue is full, new packets are dropped and
    counted in :attr:`dropped`. Blocking instead would only move the loss into
    the kernel's buffer.

    Iterate over the capture for its packets. Iteration ends once the capture
    has stopped and every queued packet has been taken. If the capture failed,
    iteration then raises the error.

    The capture takes ownership of ``source`` and closes it when it stops.
    """

    def __init__(self, source: PacketSource, queue_size: int = DEFAULT_QUEUE_SIZE) -> None:
        self.source = source
        self.received = 0
        """Packets read from the source."""
        self.dropped = 0
        """Packets thrown away because the queue was full."""
        self.kernel_stats: KernelStats | None = None
        """The kernel's counters, read as the capture stopped. ``None`` if unavailable."""
        self.error: Exception | None = None
        """What stopped the capture, if it failed."""
        self._queue: queue.Queue[Packet] = queue.Queue(maxsize=queue_size)
        self._stopping = threading.Event()
        self._finished = threading.Event()
        self._thread = threading.Thread(
            target=self._run, name=f"capture on {source.interface}", daemon=True
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        """Ask the capture to stop. Returns at once, so a signal handler may call it.

        The thread notices within the source's read timeout.
        """
        self._stopping.set()

    def join(self) -> None:
        """Wait for the capture thread to finish and close the source."""
        if self._thread.ident is None:
            # Never started, so the source is still open.
            self.source.close()
            self._finished.set()
        else:
            self._thread.join()

    @property
    def pending(self) -> int:
        """Packets waiting in the queue."""
        return self._queue.qsize()

    def __iter__(self) -> Iterator[Packet]:
        while True:
            try:
                packet = self._queue.get(timeout=_POLL_SECONDS)
            except queue.Empty:
                # The thread puts nothing after it finishes, so an empty queue
                # after that means every packet has been taken.
                if self._finished.is_set() and self._queue.empty():
                    break
                continue
            yield packet
        if self.error is not None:
            raise self.error

    def _run(self) -> None:
        source = self.source
        put = self._queue.put_nowait
        try:
            while not self._stopping.is_set():
                packet = source.read()
                if packet is None:
                    continue
                self.received += 1
                try:
                    put(packet)
                except queue.Full:
                    self.dropped += 1
        except Exception as error:
            self.error = error
        finally:
            try:
                self.kernel_stats = source.stats()
            except Exception:
                self.kernel_stats = None
            source.close()
            self._finished.set()

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.stop()
        self.join()
