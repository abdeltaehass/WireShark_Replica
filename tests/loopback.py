"""Traffic on lo0 for the live capture tests, which only ever capture loopback."""

import secrets
import socket
import time
from collections.abc import Callable
from types import TracebackType
from typing import Self

from pilotfish.core.capture import PacketSource
from pilotfish.core.packet import Packet

# On lo0 each packet starts with a 4-byte address family, then the IPv4 and UDP headers.
UDP_PAYLOAD_OFFSET = 4 + 20 + 8


class LoopbackTraffic:
    """Sends UDP datagrams to a socket of its own on 127.0.0.1."""

    def __init__(self) -> None:
        self._receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._receiver.bind(("127.0.0.1", 0))
        self._sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def send(self, size: int = 32) -> bytes:
        """Send a datagram of random bytes, which no other traffic will match, and return them."""
        payload = secrets.token_bytes(size)
        self._sender.sendto(payload, self._receiver.getsockname())
        return payload

    def close(self) -> None:
        self._sender.close()
        self._receiver.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def carrying(payload: bytes) -> Callable[[Packet], bool]:
    return lambda packet: payload in packet.data


def read_until(
    source: PacketSource, matches: Callable[[Packet], bool], timeout: float = 5.0
) -> Packet:
    """Read from ``source`` until a packet ``matches``. Other loopback traffic is skipped."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        packet = source.read()
        if packet is not None and matches(packet):
            return packet
    raise AssertionError(f"no matching packet within {timeout} s")
