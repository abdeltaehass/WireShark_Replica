"""Both ends of a TCP connection, for tests that need a stream, not a packet.

A segment built here isn't in any capture until the test puts it in one,
which is how a test gets a segment to arrive late, twice, or not at all.
"""

from collections.abc import Sequence

from packets import ethernet, ipv4, tcp
from pilotfish.core.dissect import REGISTRY, ProtocolTree, Registry, Session, dissect
from pilotfish.core.packet import Packet

ETHERNET = 1
CLIENT = "192.0.2.1"
SERVER = "192.0.2.2"

FIN = 0x01
SYN = 0x02
RESET = 0x04
PUSH = 0x08
ACK = 0x10

MSS = 1460
MILLISECOND = 1_000_000


class Talk:
    """One connection, keeping count of what each end has sent."""

    def __init__(
        self,
        client_port: int = 50000,
        server_port: int = 80,
        *,
        client_isn: int = 1000,
        server_isn: int = 5000,
    ) -> None:
        self.client_port = client_port
        self.server_port = server_port
        self.next = {True: client_isn, False: server_isn}

    def segment(
        self,
        payload: bytes = b"",
        *,
        from_client: bool,
        flags: int = ACK | PUSH,
        seq: int | None = None,
        break_checksum: bool = False,
    ) -> bytes:
        """The next segment from one end, acknowledging all the other has sent.

        Give ``seq`` to send from somewhere other than where this end is up
        to, which leaves its count alone: a segment sent again.
        """
        source, destination = (CLIENT, SERVER) if from_client else (SERVER, CLIENT)
        ports = (self.client_port, self.server_port)
        segment = tcp(
            *(ports if from_client else ports[::-1]),
            payload,
            seq=self.next[from_client] if seq is None else seq,
            ack=self.next[not from_client] if flags & ACK else 0,
            flags=flags,
            source=source,
            destination=destination,
            break_checksum=break_checksum,
        )
        if seq is None:
            self.next[from_client] += len(payload) + (1 if flags & (SYN | FIN) else 0)
        return ethernet(ipv4(segment, 6, source=source, destination=destination))

    def handshake(self) -> list[bytes]:
        return [
            self.segment(from_client=True, flags=SYN),
            self.segment(from_client=False, flags=SYN | ACK),
            self.segment(from_client=True, flags=ACK),
        ]

    def send(self, data: bytes, *, from_client: bool, size: int = MSS) -> list[bytes]:
        """``data`` cut into segments of ``size`` bytes."""
        return [
            self.segment(data[at : at + size], from_client=from_client)
            for at in range(0, len(data), size)
        ]

    def acknowledge(self, *, from_client: bool) -> bytes:
        return self.segment(from_client=from_client, flags=ACK)

    def finish(self, *, from_client: bool) -> bytes:
        """One end saying it has no more to send."""
        return self.segment(from_client=from_client, flags=FIN | ACK)


def captured(frames: Sequence[bytes]) -> list[Packet]:
    """The frames as a capture would hold them, a millisecond apart."""
    return [
        Packet(number * MILLISECOND, len(frame), ETHERNET, frame)
        for number, frame in enumerate(frames, start=1)
    ]


def decode(
    frames: Sequence[bytes], session: Session | None = None, registry: Registry = REGISTRY
) -> list[ProtocolTree]:
    """Decode the frames as one capture, in order."""
    session = session or Session()
    return [
        dissect(packet, number, registry, session)
        for number, packet in enumerate(captured(frames), start=1)
    ]
