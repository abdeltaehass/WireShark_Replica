"""Following a TCP stream: everything one connection said, in order.

A connection's bytes are spread over as many packets as it took to carry
them, mixed in with every other connection's, sometimes late and sometimes
twice. Following a stream puts one connection's back the way its two ends
wrote them, so that a page or a download can be read as what it was rather
than as the packets it arrived in.
"""

from collections.abc import Iterable
from dataclasses import dataclass

import pilotfish.core.protocols  # noqa: F401  (registers the dissectors)
from pilotfish.core.dissect import Session, dissect
from pilotfish.core.packet import Packet
from pilotfish.core.protocols.conversations import Endpoint
from pilotfish.core.protocols.tcp import LISTENER, Heard, Listener


@dataclass(frozen=True, slots=True)
class Chunk:
    """What one end sent before the other end spoke again."""

    from_client: bool
    data: bytes
    missed: int = 0
    """How many bytes came before these that the capture never saw. The
    other end acknowledged them, so they were sent, but not while anyone was
    recording."""


@dataclass(frozen=True, slots=True)
class FollowedStream:
    """One TCP connection, as the conversation it carried."""

    index: int
    """The stream number, as ``tcp.stream`` reports it."""
    client: Endpoint
    """The end that opened the connection: its address and port."""
    server: Endpoint
    chunks: tuple[Chunk, ...]
    """The conversation, in the order it happened."""

    @property
    def from_client(self) -> bytes:
        """Everything the client sent, as one run of bytes."""
        return b"".join(chunk.data for chunk in self.chunks if chunk.from_client)

    @property
    def from_server(self) -> bytes:
        """Everything the server sent, which for a download is the file and
        the headers in front of it."""
        return b"".join(chunk.data for chunk in self.chunks if not chunk.from_client)


def follow_tcp_stream(packets: Iterable[Packet], index: int) -> FollowedStream:
    """The conversation on one TCP connection of a capture.

    ``packets`` is the whole capture, in order, and ``index`` the stream
    number to follow. Segments that arrived out of order are put back in
    order, and bytes that were sent more than once are counted once.

    The client is whichever end sent the SYN. When the capture began after
    the connection did, it is whichever end spoke first.

    Raises :class:`LookupError` if the capture has no such stream.
    """
    session = Session()
    listener = session.store(LISTENER, lambda: Listener(index))
    for number, packet in enumerate(packets, start=1):
        dissect(packet, number, session=session)
    conversation = listener.conversation
    if conversation is None or listener.responder is None:
        raise LookupError(f"the capture has no TCP stream {index}")
    forward_is_client = conversation.state.opened_forward is not False
    ends = (conversation.initiator, listener.responder)
    client, server = ends if forward_is_client else ends[::-1]
    return FollowedStream(index, client, server, _chunks(listener.heard, forward_is_client))


def _chunks(heard: list[Heard], forward_is_client: bool) -> tuple[Chunk, ...]:
    """Join what each end sent between the other end's turns."""
    chunks: list[Chunk] = []
    run: list[bytes] = []
    missed = 0
    from_client = True
    for each in heard:
        client = each.forward == forward_is_client
        if run and (client != from_client or each.missed):
            chunks.append(Chunk(from_client, b"".join(run), missed))
            run, missed = [], 0
        if not run:
            from_client, missed = client, each.missed
        run.append(each.data)
    if run:
        chunks.append(Chunk(from_client, b"".join(run), missed))
    return tuple(chunks)
