"""Random bytes through every dissector.

A dissector may only ever fail one way: a packet that doesn't hold what its
headers claim raises Malformed, which the engine turns into a marked packet.
Anything else escaping is a bug, and these tests are how it gets found.

The suite runs a few hundred inputs per dissector. For a longer run::

    uv run pytest tests/test_fuzz.py --hypothesis-profile=fuzz
"""

import contextlib

import pytest
from hypothesis import given
from hypothesis import strategies as st

import toy
from pilotfish.core.dissect import (
    REGISTRY,
    Buffer,
    Context,
    Dissector,
    MalformedError,
    Reader,
    Registry,
    dissect,
)
from pilotfish.core.packet import Packet

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
    # Malformed is the one failure a dissector is allowed; anything else
    # escaping fails the test.
    with contextlib.suppress(MalformedError):
        dissector.dissect(reader, Context(packet=packet))
    # Whatever happened, the fields read so far still make a layer.
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
