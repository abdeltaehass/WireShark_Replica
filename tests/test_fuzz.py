"""Random bytes through every dissector.

A dissector may only ever fail one way: a packet that doesn't hold what its
headers claim raises Malformed, which the engine turns into a marked packet.
It may also decline a payload that isn't its protocol at all, which leaves
the bytes as data, and on a stream it may ask for the rest of a message that
isn't all there. Anything else escaping is a bug, and these tests are how it
gets found.

Reassembly gets the same treatment from the other side: segments and
fragments that claim to belong anywhere at all, in any order, through the
whole engine. Whatever they add up to, decoding must not raise.

The suite runs a few hundred inputs per dissector. For a longer run::

    uv run pytest tests/test_fuzz.py --hypothesis-profile=fuzz
"""

import contextlib

import pytest
from hypothesis import given
from hypothesis import strategies as st

import pilotfish.core.protocols  # noqa: F401  (registers the dissectors to fuzz)
import toy
from packets import ethernet, ipv4, tcp
from pilotfish.core.dissect import (
    REGISTRY,
    Buffer,
    Context,
    DeclinedError,
    Dissector,
    MalformedError,
    NeedMoreError,
    Reader,
    Registry,
    Session,
    dissect,
)
from pilotfish.core.follow import follow_tcp_stream
from pilotfish.core.packet import Packet
from pilotfish.core.protocols.ip import FRAGMENTS
from pilotfish.core.reassembly import Fragments
from pilotfish.core.reassembly.fragments import LIMIT, MAX_DATAGRAM

REGISTRIES = (REGISTRY, toy.REGISTRY)

LINK_TYPES = st.sampled_from([0, 1, toy.TOY_LINK_TYPE, 101, 113, 65535])

packets = st.builds(
    Packet,
    timestamp_ns=st.integers(0, 2**63 - 1),
    original_length=st.integers(0, 0xFFFF),
    link_type=LINK_TYPES,
    data=st.binary(max_size=300),
)

# Packets shaped like the toy protocol, so the fuzzing gets past the first
# field instead of stopping at a header that never matches anything.
toy_packets = st.builds(
    toy.toy_packet,
    version=st.integers(0, 0xFF),
    flags=st.integers(0, 0xFF),
    length=st.integers(0, 0xFFFF),
    next_protocol=st.sampled_from([toy.BODY, toy.LOOP, 0, 0xFFFF]),
    payload=st.binary(max_size=64),
).map(
    lambda data: Packet(
        timestamp_ns=0,
        original_length=len(data),
        link_type=toy.TOY_LINK_TYPE,
        data=data,
    )
)


def registered() -> list[tuple[Registry, Dissector]]:
    return [(registry, each) for registry in REGISTRIES for each in registry.dissectors]


@pytest.mark.parametrize(
    ("registry", "dissector"),
    registered(),
    ids=[dissector.name for _, dissector in registered()],
)
@given(data=st.binary(max_size=300))
def test_only_malformed_escapes(registry: Registry, dissector: Dissector, data: bytes) -> None:
    packet = Packet(timestamp_ns=0, original_length=len(data), link_type=1, data=data)
    reader = Reader(dissector.protocol, Buffer(data), registry.fields)
    # Malformed is the one failure a dissector is allowed, and declining the
    # payload as not its own is the one refusal. Anything else escaping fails.
    with contextlib.suppress(MalformedError, DeclinedError):
        dissector.dissect(reader, Context(packet=packet))
    # Whatever happened, the fields read so far still make a layer.
    assert reader.node().length >= 0


@pytest.mark.parametrize(
    ("registry", "dissector"),
    registered(),
    ids=[dissector.name for _, dissector in registered()],
)
@given(data=st.binary(max_size=300))
def test_on_a_stream_only_asking_for_more_escapes_as_well(
    registry: Registry, dissector: Dissector, data: bytes
) -> None:
    packet = Packet(timestamp_ns=0, original_length=len(data), link_type=1, data=data)
    reader = Reader(dissector.protocol, Buffer(data), registry.fields)
    with contextlib.suppress(MalformedError, DeclinedError, NeedMoreError):
        dissector.dissect(reader, Context(packet=packet, can_wait=True))
    assert reader.node().length >= 0


@given(packet=packets | toy_packets)
def test_dissecting_never_raises(packet: Packet) -> None:
    tree = dissect(packet, registry=toy.REGISTRY)
    assert tree.protocols[0] == "frame"


@given(packet=packets | toy_packets)
def test_every_field_points_inside_the_packet(packet: Packet) -> None:
    for node in dissect(packet, registry=toy.REGISTRY).walk():
        assert node.offset >= 0
        assert node.length >= 0
        assert node.offset + node.length <= packet.captured_length


# The start of a message of each protocol that reads a stream, so that random
# bytes after one reach the code that waits for the rest of it.
OPENINGS = st.sampled_from(
    [
        b"",
        b"GET / HTTP/1.1\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 70000\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffff\r\n",
        b"HTTP/1.0 200 OK\r\nContent-Encoding: gzip\r\n\r\n",
        b"\x16\x03\x03\x40\x00",
        b"\x17\x03\x03\x00\x10",
        b"SSH-2.0-fuzz\r\n",
        b"\x00\x00\x01\x00\x08\x14",
    ]
)

segments = st.tuples(
    st.booleans(),
    st.sampled_from([22, 80, 443, 8765]),
    st.integers(0, 4000) | st.integers(0, 2**32 - 1),
    st.integers(0, 4000),
    st.sampled_from([0x10, 0x18, 0x02, 0x12, 0x11, 0x14, 0x19]),
    st.builds(lambda opening, rest: opening + rest, OPENINGS, st.binary(max_size=120)),
)


def segment_packets(arriving: list[tuple[bool, int, int, int, int, bytes]]) -> list[Packet]:
    """Segments of a few connections, claiming whatever places they like."""
    captured = []
    for number, (from_client, port, seq, ack, flags, payload) in enumerate(arriving):
        ends = ("192.0.2.1", "192.0.2.2") if from_client else ("192.0.2.2", "192.0.2.1")
        ports = (50000, port) if from_client else (port, 50000)
        segment = tcp(
            *ports, payload, seq=seq, ack=ack, flags=flags, source=ends[0], destination=ends[1]
        )
        frame = ethernet(ipv4(segment, 6, source=ends[0], destination=ends[1]))
        captured.append(Packet(number * 1_000_000, len(frame), 1, frame))
    return captured


@given(st.lists(segments, max_size=40))
def test_segments_in_any_order_never_raise(
    arriving: list[tuple[bool, int, int, int, int, bytes]],
) -> None:
    session = Session()
    for number, packet in enumerate(segment_packets(arriving), start=1):
        tree = dissect(packet, number, session=session)
        assert tree.protocols[:4] == ("frame", "eth", "ip", "tcp")
        # Whatever was put together, every field still points inside the
        # bytes it says it came from.
        for node in tree.walk():
            size = packet.captured_length if node.source is None else len(node.source.data)
            assert 0 <= node.offset <= node.offset + node.length <= size
            assert node.source is None or node.source in tree.sources


@given(st.lists(segments, max_size=40), st.integers(0, 3))
def test_following_segments_in_any_order_never_raises(
    arriving: list[tuple[bool, int, int, int, int, bytes]], index: int
) -> None:
    with contextlib.suppress(LookupError):
        stream = follow_tcp_stream(segment_packets(arriving), index)
        sent = sum(len(payload) for *_, payload in arriving)
        assert len(stream.from_client) + len(stream.from_server) <= sent


fragments = st.tuples(
    st.integers(0, 3),
    st.integers(0, 8191),
    st.booleans(),
    st.sampled_from([1, 6, 17]),
    st.binary(max_size=64),
)


@given(st.lists(fragments, max_size=60))
def test_fragments_in_any_order_never_raise(
    arriving: list[tuple[int, int, bool, int, bytes]],
) -> None:
    session = Session()
    for number, (identifier, offset, more, protocol, payload) in enumerate(arriving, start=1):
        frame = ethernet(ipv4(payload, protocol, offset, flags=int(more), identifier=identifier))
        tree = dissect(Packet(number, len(frame), 1, frame), number, session=session)
        assert tree.protocols[:3] == ("frame", "eth", "ip")
        whole = tree.get("ip.reassembled.data")
        assert whole is None or (isinstance(whole, bytes) and len(whole) <= MAX_DATAGRAM)
    if FRAGMENTS in session:
        assert session.store(FRAGMENTS, Fragments).buffered <= LIMIT
