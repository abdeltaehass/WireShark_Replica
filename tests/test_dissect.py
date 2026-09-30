from ipaddress import IPv4Address
from typing import Any

import pytest

import toy
from pilotfish.core.dissect import (
    LINK_TYPE,
    MAX_LAYERS,
    Buffer,
    Context,
    DeclinedError,
    Dissector,
    Field,
    FieldRegistry,
    FieldType,
    Handoff,
    Node,
    ProtocolTree,
    Reader,
    Registry,
    dissect,
)
from pilotfish.core.packet import Packet
from toy import HEADER_SIZE, TOY_LINK_TYPE, Toy, ToyBody, toy_packet


def packet(data: bytes, link_type: int = TOY_LINK_TYPE) -> Packet:
    return Packet(
        timestamp_ns=1_000_000_000, original_length=len(data), link_type=link_type, data=data
    )


def fields_of(layer: Node) -> dict[str, object]:
    return {node.name: node.value for node in layer.walk() if node.value is not None}


class TestTheToyProtocol:
    """The whole framework, over a protocol made up for the purpose."""

    def tree(self, **changes: Any) -> ProtocolTree:
        return dissect(packet(toy_packet(**changes)), number=7, registry=toy.REGISTRY)

    def test_decodes_into_layers(self) -> None:
        tree = self.tree()
        assert tree.protocols == ("frame", "toy", "toybody")
        assert tree.error is None

    def test_every_field_has_its_value(self) -> None:
        assert fields_of(self.tree().layers[1]) == {
            "toy.version": 1,
            "toy.flags": toy.URGENT,
            "toy.flags.urgent": True,
            "toy.flags.last": False,
            "toy.length": 4,
            "toy.source": IPv4Address("192.0.2.1"),
            "toy.hardware": "02:00:00:00:00:01",
            "toy.next": toy.BODY,
            "toy.label": "toy1",
        }

    def test_every_field_points_at_its_bytes(self) -> None:
        layer = self.tree().layers[1]
        spans = {node.name: (node.offset, node.length) for node in layer.walk()}
        assert spans == {
            "toy": (0, HEADER_SIZE),  # the layer covers its header, not the payload
            "toy.version": (0, 1),
            "toy.flags": (1, 1),
            "toy.flags.urgent": (1, 1),  # a flag points at the byte it came from
            "toy.flags.last": (1, 1),
            "toy.length": (2, 2),
            "toy.source": (4, 4),
            "toy.hardware": (8, 6),
            "toy.next": (14, 2),
            "toy.label": (16, 4),
        }

    def test_flags_hang_under_the_byte_they_came_from(self) -> None:
        flags = self.tree().find("toy.flags")
        assert flags is not None
        assert [child.name for child in flags.children] == [
            "toy.flags.urgent",
            "toy.flags.last",
        ]
        assert [child.value for child in flags.children] == [True, False]

    def test_the_frame_layer_describes_the_capture(self) -> None:
        tree = self.tree()
        assert fields_of(tree.layers[0]) == {
            "frame.number": 7,
            "frame.len": HEADER_SIZE + 4,
            "frame.cap_len": HEADER_SIZE + 4,
            "frame.time_epoch": 1_000_000_000,
        }
        assert tree.layers[0].summary == "Frame 7: 24 bytes on wire, 24 bytes captured"

    def test_the_payload_reaches_the_protocol_it_names(self) -> None:
        tree = self.tree(payload=b"hello")
        assert tree.get("toybody.body") == b"hello"
        assert tree.layers[-1].offset == HEADER_SIZE

    def test_the_info_line_comes_from_the_innermost_dissector(self) -> None:
        assert self.tree().info == "Toy toy1, 4 bytes"

    def test_a_next_protocol_nothing_handles_is_data(self) -> None:
        tree = self.tree(next_protocol=1234)
        assert tree.protocols == ("frame", "toy", "data")
        assert tree.get("data.data") == b"body"
        # The toy header had already said what the packet is.
        assert tree.info == "Toy toy1"

    def test_a_header_cut_short_marks_the_packet(self) -> None:
        tree = dissect(packet(toy_packet()[:10]), registry=toy.REGISTRY)
        assert tree.error == "toy: toy.hardware needs 6 bytes at offset 8, but the packet has 2"
        # The fields read before the bytes ran out are still there.
        assert fields_of(tree.layers[1]) == {
            "toy.version": 1,
            "toy.flags": toy.URGENT,
            "toy.flags.urgent": True,
            "toy.flags.last": False,
            "toy.length": 4,
            "toy.source": IPv4Address("192.0.2.1"),
        }
        assert tree.protocols == ("frame", "toy")

    def test_a_length_longer_than_the_packet_takes_what_there_is(self) -> None:
        # A capture cut short by a snapshot length looks like this, so it is
        # what was captured that counts, not what the header claims.
        tree = self.tree(length=4000)
        assert tree.get("toybody.body") == b"body"
        assert tree.error is None

    def test_nothing_after_the_header_ends_the_tree(self) -> None:
        tree = self.tree(payload=b"")
        assert tree.protocols == ("frame", "toy")


def test_a_protocol_that_never_finishes_is_given_up_on() -> None:
    data = toy_packet(next_protocol=toy.LOOP, payload=b"x" * 40)
    tree = dissect(packet(data), registry=toy.REGISTRY)
    assert tree.error == f"stopped after {MAX_LAYERS} layers"
    assert len(tree.layers) == MAX_LAYERS


class TestTheTree:
    def test_finding_fields(self) -> None:
        tree = dissect(packet(toy_packet()), registry=toy.REGISTRY)
        assert tree.get("toy.label") == "toy1"
        assert tree.get("nothing.here") is None
        assert "toy.label" in tree
        assert "nothing.here" not in tree
        assert [node.name for node in tree.walk()][:2] == ["frame", "frame.number"]

    def test_a_field_that_appears_more_than_once(self) -> None:
        node = Node("toy", "Toy", FieldType.PROTOCOL, 0, 2)
        node.children = [
            Node("toy.version", "Version", FieldType.UINT, 0, 1, value=1),
            Node("toy.version", "Version", FieldType.UINT, 1, 1, value=2),
        ]
        tree = dissect(packet(b""), registry=toy.REGISTRY)
        tree.layers.append(node)
        assert tree.values("toy.version") == [1, 2]


class TestTheRegistry:
    def test_one_instance_of_each_dissector(self) -> None:
        registry = Registry()
        first = registry.add(Toy, LINK_TYPE, (TOY_LINK_TYPE,))
        assert registry.add(Toy, toy.NEXT, (1,)) is first
        assert registry.find(LINK_TYPE, TOY_LINK_TYPE) is first
        assert registry.find(toy.NEXT, 1) is first

    def test_an_unknown_value_routes_nowhere(self) -> None:
        assert Registry().find(LINK_TYPE, 999) is None

    def test_two_dissectors_cannot_claim_one_value(self) -> None:
        registry = Registry()
        registry.add(Toy, LINK_TYPE, (TOY_LINK_TYPE,))
        with pytest.raises(ValueError, match=f"{LINK_TYPE} {TOY_LINK_TYPE} already goes to toy"):
            registry.add(ToyBody, LINK_TYPE, (TOY_LINK_TYPE,))

    def test_registering_adds_the_protocol_and_its_fields(self) -> None:
        registry = Registry()
        registry.add(Toy)
        assert registry.fields["toy"].type is FieldType.PROTOCOL
        assert registry.fields["toy.source"].type is FieldType.IPV4
        assert [each.name for each in registry.dissectors] == ["toy"]

    def test_the_table_can_be_listed(self) -> None:
        registry = Registry()
        registry.add(Toy, LINK_TYPE, (TOY_LINK_TYPE, 1))
        assert registry.tables() == (LINK_TYPE,)
        assert sorted(registry.table(LINK_TYPE)) == [1, TOY_LINK_TYPE]


class TestTheFieldRegistry:
    def test_registering_the_same_field_twice_is_fine(self) -> None:
        fields = FieldRegistry()
        field = Field("toy.version", FieldType.UINT, "Version")
        fields.add(field)
        fields.add(field)
        assert len(fields) == 1

    def test_one_name_cannot_have_two_types(self) -> None:
        fields = FieldRegistry()
        fields.add(Field("toy.version", FieldType.UINT, "Version"))
        with pytest.raises(ValueError, match=r"toy\.version is already registered as uint"):
            fields.add(Field("toy.version", FieldType.STRING, "Version"))

    def test_fields_come_out_in_name_order(self) -> None:
        fields = FieldRegistry()
        fields.add(
            Field("toy.version", FieldType.UINT, "Version"),
            Field("toy.label", FieldType.STRING, "Label"),
        )
        assert [field.name for field in fields] == ["toy.label", "toy.version"]
        assert "toy.label" in fields
        assert fields["toy.label"].protocol == "toy"

    def test_an_unregistered_name_says_so(self) -> None:
        with pytest.raises(KeyError, match=r"no field named 'toy\.nope' is registered"):
            FieldRegistry()["toy.nope"]


class TestTheReader:
    def reader(self, data: bytes, *fields: Field) -> Reader:
        registry = FieldRegistry()
        registry.add(*fields)
        return Reader(Field("test", FieldType.PROTOCOL, "Test"), Buffer(data), registry)

    def test_a_field_must_be_registered(self) -> None:
        reader = self.reader(b"\x01")
        with pytest.raises(KeyError, match=r"no field named 'test\.version'"):
            reader.uint8("test.version")

    def test_a_value_must_match_the_registered_type(self) -> None:
        reader = self.reader(b"\x01", Field("test.name", FieldType.STRING, "Name"))
        with pytest.raises(TypeError, match=r"test\.name is a string field, not int"):
            reader.uint8("test.name")

    def test_the_layer_covers_its_header(self) -> None:
        reader = self.reader(b"\x01\x02\x03\x04", Field("test.a", FieldType.UINT, "A"))
        reader.uint8("test.a")
        payload = reader.payload()
        assert payload.remaining == 3
        assert reader.node().length == 1

    def test_a_payload_can_be_shorter_than_what_is_left(self) -> None:
        reader = self.reader(b"\x01\x02\x03\x04", Field("test.a", FieldType.UINT, "A"))
        reader.uint8("test.a")
        assert reader.payload(2).remaining == 2

    def test_a_layer_can_say_how_far_it_reaches(self) -> None:
        reader = self.reader(b"\x01\x02", Field("test.a", FieldType.UINT, "A"))
        reader.uint8("test.a")
        reader.set_length(2)
        assert reader.node().length == 2


def test_a_dissector_must_decode_something() -> None:
    class Empty(Dissector):
        name = "empty"
        title = "Empty"

    registry = Registry()
    registry.add(Empty, LINK_TYPE, (1,))
    with pytest.raises(NotImplementedError):
        Empty().dissect(
            Reader(Empty().protocol, Buffer(b""), registry.fields),
            Context(packet=packet(b"", link_type=1)),
        )


def test_handoffs_carry_the_bytes_and_where_to_look_them_up() -> None:
    handoff = Handoff("ethertype", 0x0800, Buffer(b"\x45\x00"))
    assert (handoff.table, handoff.key) == ("ethertype", 0x0800)
    assert handoff.payload.remaining == 2


PORTS = "ports"
"""A table keyed by port, as the transport protocols' tables are."""


class Transport(Dissector):
    """Hands over what follows under both of its ports, lower one first.

    This is the shape UDP and TCP hand a payload on with: a port each end,
    either of which may be the one that says what the payload is, and a list
    of dissectors to ask when neither does.
    """

    name = "transport"
    title = "Transport"
    fields = (Field("transport.port", FieldType.UINT, "Port"),)

    def dissect(self, reader: Reader, context: Context) -> Handoff:
        first = reader.uint16("transport.port")
        second = reader.uint16("transport.port")
        return Handoff(
            PORTS,
            min(first, second),
            reader.payload(),
            also=(max(first, second),),
            heuristics=PORTS,
        )


class Known(Dissector):
    """What a well-known port routes to."""

    name = "known"
    title = "Known"

    def dissect(self, reader: Reader, context: Context) -> None:
        context.info = "known"
        reader.set_length(reader.remaining)
        return None


class Guessed(Dissector):
    """A dissector that recognises its own payloads by how they start."""

    name = "guessed"
    title = "Guessed"

    def looks_like(self, payload: Buffer, context: Context) -> bool:
        return bytes(payload.peek(min(payload.remaining, 4))) == b"GUES"

    def dissect(self, reader: Reader, context: Context) -> None:
        context.info = "guessed"
        reader.set_length(reader.remaining)
        return None


class Picky(Dissector):
    """A dissector that only decodes payloads it recognises."""

    name = "picky"
    title = "Picky"

    def dissect(self, reader: Reader, context: Context) -> None:
        if not bytes(reader.buffer.peek(4)).startswith(b"MINE"):
            raise DeclinedError
        reader.set_length(reader.remaining)
        context.info = "picky"
        return None


class TestRouting:
    """How a handoff finds the dissector for what comes next."""

    def registry(self, *, port: int | None = None, heuristic: bool = False) -> Registry:
        registry = Registry()
        registry.add(Transport, LINK_TYPE, (TOY_LINK_TYPE,))
        if port is not None:
            registry.add(Known, PORTS, (port,))
        if heuristic:
            registry.add_heuristic(Guessed, PORTS)
        return registry

    def decode(self, registry: Registry, ports: tuple[int, int], payload: bytes) -> ProtocolTree:
        data = b"".join(port.to_bytes(2, "big") for port in ports) + payload
        return dissect(packet(data), registry=registry)

    def test_the_lower_port_is_tried_first(self) -> None:
        tree = self.decode(self.registry(port=53), (50000, 53), b"body")
        assert tree.protocols == ("frame", "transport", "known")

    def test_the_other_port_is_tried_next(self) -> None:
        # A server talking back has the well-known port at the other end.
        tree = self.decode(self.registry(port=50000), (50000, 53), b"body")
        assert tree.protocols == ("frame", "transport", "known")

    def test_a_dissector_that_recognises_the_payload_gets_it(self) -> None:
        tree = self.decode(self.registry(heuristic=True), (50000, 50001), b"GUESwhat")
        assert tree.protocols == ("frame", "transport", "guessed")
        assert tree.info == "guessed"

    def test_a_port_that_matches_wins_over_a_heuristic(self) -> None:
        registry = self.registry(port=53, heuristic=True)
        tree = self.decode(registry, (50000, 53), b"GUESwhat")
        assert tree.protocols == ("frame", "transport", "known")

    def test_a_payload_nothing_recognises_is_data(self) -> None:
        tree = self.decode(self.registry(heuristic=True), (50000, 50001), b"mystery")
        assert tree.protocols == ("frame", "transport", "data")

    def test_the_heuristics_are_asked_in_the_order_they_registered(self) -> None:
        registry = self.registry(heuristic=True)
        registry.add_heuristic(Known, PORTS)
        assert [each.name for each in registry.heuristics(PORTS)] == ["guessed", "known"]
        # Registering the same one again doesn't ask it twice.
        registry.add_heuristic(Guessed, PORTS)
        assert len(registry.heuristics(PORTS)) == 2

    def test_a_dissector_that_declines_leaves_the_bytes_as_data(self) -> None:
        # A port says what a payload usually holds, not what it always holds.
        registry = self.registry()
        registry.add(Picky, PORTS, (53,))
        tree = self.decode(registry, (50000, 53), b"NOPE not this protocol")
        assert tree.protocols == ("frame", "transport", "data")
        assert tree.get("data.data") == b"NOPE not this protocol"

    def test_the_same_dissector_decodes_what_it_does_recognise(self) -> None:
        registry = self.registry()
        registry.add(Picky, PORTS, (53,))
        tree = self.decode(registry, (50000, 53), b"MINE after all")
        assert tree.protocols == ("frame", "transport", "picky")
        assert tree.info == "picky"

    def test_a_table_with_no_heuristics_has_nothing_to_ask(self) -> None:
        assert self.registry().heuristics(PORTS) == ()
        assert self.registry().guess(PORTS, Buffer(b"GUES"), Context(packet=packet(b""))) is None
