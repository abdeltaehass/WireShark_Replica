"""How the engine deals with a dissector that reads a stream.

A stream has no idea where its messages begin and end, and a dissector has no
idea what the stream is holding back. The engine sits between them: it tells
the stream what the dissector made of each offer, and offers the dissector
whatever the stream comes back with. These tests put a scripted stream on one
side and a toy dissector on the other, and watch what passes between them.
"""

from dataclasses import dataclass, field

from pilotfish.core.dissect import (
    LINK_TYPE,
    MAX_LAYERS,
    Buffer,
    Context,
    DeclinedError,
    Dissector,
    Field,
    FieldType,
    Handoff,
    MalformedError,
    NeedMoreError,
    ProtocolTree,
    Reader,
    Registry,
    Session,
    Source,
    Stream,
    dissect,
)
from pilotfish.core.packet import Packet

LINK = 147
MESSAGES = "carrier.next"


@dataclass
class Scripted(Stream):
    """A stream that does what the test says, and notes what it was told."""

    is_open: bool = True
    after_taken: list[Buffer] = field(default_factory=list)
    """What to offer next, each time the dissector has decoded something."""
    after_held: list[Buffer] = field(default_factory=list)
    """What to offer instead, each time the dissector asks for more."""
    told: list[tuple[object, ...]] = field(default_factory=list)

    @property
    def open(self) -> bool:
        return self.is_open

    def taken(self, count: int) -> Buffer | None:
        self.told.append(("taken", count))
        return self.after_taken.pop(0) if self.after_taken else None

    def held(self, more: NeedMoreError) -> Buffer | None:
        self.told.append(("held", more.count, more.to_end))
        return self.after_held.pop(0) if self.after_held else None


class Carrier(Dissector):
    """Hands its whole payload on as the front of whatever stream the test
    left in the session, or as a plain payload if it left none."""

    name = "carrier"
    title = "Carrier"

    def dissect(self, reader: Reader, context: Context) -> Handoff:
        stream = context.session.store("stream", lambda: None)
        return Handoff(MESSAGES, 1, reader.payload(), stream=stream)


class Message(Dissector):
    """A one-byte length and that many bytes.

    A length of 0xff is not this protocol's, 0xfe is a message that makes no
    sense, and 0xfd is a dissector that returns without reading anything.
    """

    name = "msg"
    title = "Message"
    fields = (
        Field("msg.length", FieldType.UINT, "Length"),
        Field("msg.body", FieldType.BYTES, "Body"),
        Field("msg.could_wait", FieldType.BOOL, "Could have waited"),
    )

    def dissect(self, reader: Reader, context: Context) -> None:
        length = reader.buffer.peek(1)[0]
        if length == 0xFF:
            raise DeclinedError
        if length == 0xFD:
            return None
        missing = 1 + length - reader.remaining
        if length < 0xFE and missing > 0 and context.can_wait:
            raise NeedMoreError(missing)
        reader.uint8("msg.length")
        reader.add("msg.could_wait", context.can_wait)
        if length == 0xFE:
            raise MalformedError("a message that makes no sense")
        body = reader.bytes("msg.body", min(length, reader.remaining))
        context.describe(body.decode())
        return None


REGISTRY = Registry()
REGISTRY.add(Carrier, LINK_TYPE, (LINK,))
REGISTRY.add(Message, MESSAGES, (1,))


def message(body: bytes) -> bytes:
    return bytes([len(body)]) + body


def run(data: bytes, stream: Stream | None) -> ProtocolTree:
    session = Session()
    session.store("stream", lambda: stream)
    return dissect(Packet(0, len(data), LINK, data), registry=REGISTRY, session=session)


class TestWhatTheEngineTellsAStream:
    def test_how_much_of_the_offer_was_decoded(self) -> None:
        stream = Scripted()
        tree = run(message(b"one") + b"left over", stream)
        assert tree.protocols == ("frame", "carrier", "msg")
        assert stream.told == [("taken", 4)]

    def test_that_a_message_is_not_all_there(self) -> None:
        stream = Scripted()
        tree = run(b"\x09half", stream)
        # The layer is thrown away: nothing of the message is in the tree.
        assert tree.protocols == ("frame", "carrier")
        assert stream.told == [("held", 5, False)]

    def test_that_a_message_made_no_sense_takes_everything_offered(self) -> None:
        # Kept, the same bytes would come back with every packet after it.
        stream = Scripted()
        tree = run(b"\xfe and the rest", stream)
        assert tree.error == "msg: a message that makes no sense"
        assert stream.told == [("taken", 14)]

    def test_that_bytes_which_are_not_the_protocol_were_taken_as_data(self) -> None:
        stream = Scripted()
        tree = run(b"\xff not a message", stream)
        assert tree.protocols == ("frame", "carrier", "data")
        assert stream.told == [("taken", 15)]

    def test_a_dissector_that_reads_nothing_counts_as_having_read_it_all(self) -> None:
        # Otherwise the same bytes would be offered to it for ever.
        stream = Scripted()
        run(b"\xfd unread", stream)
        assert stream.told == [("taken", 8)]


class TestWhatTheEngineDoesWithTheAnswer:
    def test_the_next_message_is_decoded_in_the_same_packet(self) -> None:
        stream = Scripted(after_taken=[Buffer(message(b"two"), 4), Buffer(message(b"three"), 8)])
        tree = run(message(b"one"), stream)
        assert tree.protocols == ("frame", "carrier", "msg", "msg", "msg")
        assert tree.values("msg.body") == [b"one", b"two", b"three"]
        # Each message adds to what the packet list says, not replaces it.
        assert tree.info == "one, two, three"

    def test_a_message_that_needs_more_ends_the_packet_but_keeps_the_others(self) -> None:
        stream = Scripted(after_taken=[Buffer(b"\x09half", 4)])
        tree = run(message(b"one"), stream)
        assert tree.values("msg.body") == [b"one"]
        assert tree.info == "one"
        assert stream.told == [("taken", 4), ("held", 5, False)]

    def test_more_bytes_than_were_shown_are_tried_straight_away(self) -> None:
        # The stream had the rest all along, behind what it offered.
        stream = Scripted(after_held=[Buffer(message(b"whole one"))])
        tree = run(b"\x09whole", stream)
        assert tree.values("msg.body") == [b"whole one"]
        assert tree.get("msg.could_wait") is True
        assert stream.told == [("held", 4, False), ("taken", 10)]

    def test_the_same_bytes_again_are_not_tried_while_waiting_is_possible(self) -> None:
        # A stream that kept handing back what it had would never let the
        # packet end.
        stream = Scripted(after_held=[Buffer(b"\x09half") for _ in range(5)])
        tree = run(b"\x09half", stream)
        assert tree.protocols == ("frame", "carrier")
        assert stream.told == [("held", 5, False)]

    def test_a_stream_that_cannot_wait_makes_the_dissector_make_do(self) -> None:
        stream = Scripted(is_open=False)
        tree = run(b"\x09half", stream)
        assert tree.values("msg.body") == [b"half"]
        assert tree.get("msg.could_wait") is False
        assert stream.told == [("taken", 5)]

    def test_a_stream_that_gives_up_waiting_says_so_with_the_same_bytes(self) -> None:
        class GivesUp(Scripted):
            def held(self, more: NeedMoreError) -> Buffer | None:
                self.is_open = False
                return super().held(more)

        stream = GivesUp(after_held=[Buffer(b"\x09half")])
        tree = run(b"\x09half", stream)
        assert tree.values("msg.body") == [b"half"]
        assert tree.get("msg.could_wait") is False

    def test_too_many_messages_for_one_packet_are_left_for_the_next(self) -> None:
        stream = Scripted(after_taken=[Buffer(message(b"again")) for _ in range(100)])
        tree = run(message(b"first"), stream)
        assert len(tree.layers) == MAX_LAYERS
        # Stopping here is not the packet's fault, so it isn't marked.
        assert tree.error is None

    def test_bytes_from_somewhere_other_than_the_packet_are_listed(self) -> None:
        whole = message(b"put together")
        source = Source("Reassembled", whole)
        stream = Scripted(after_held=[Buffer(whole, 0, source)])
        tree = run(b"\x0cput", stream)
        assert tree.sources == [source]
        body = tree.find("msg.body")
        assert body is not None
        assert body.source is source
        assert (body.offset, body.length) == (1, 12)
        assert tree.layers[1].source is None


class TestWithoutAStream:
    def test_a_dissector_is_told_it_cannot_wait(self) -> None:
        tree = run(b"\x09half", None)
        assert tree.get("msg.could_wait") is False
        assert tree.values("msg.body") == [b"half"]

    def test_asking_for_more_anyway_leaves_the_bytes_as_data(self) -> None:
        class Insists(Dissector):
            name = "insists"
            title = "Insists"

            def dissect(self, reader: Reader, context: Context) -> None:
                raise NeedMoreError(1)

        registry = Registry()
        registry.add(Carrier, LINK_TYPE, (LINK,))
        registry.add(Insists, MESSAGES, (1,))
        tree = dissect(Packet(0, 4, LINK, b"data"), registry=registry)
        assert tree.protocols == ("frame", "carrier", "data")
        assert tree.error is None


def test_need_more_says_what_it_needs() -> None:
    assert (NeedMoreError().count, NeedMoreError().to_end) == (None, False)
    assert NeedMoreError(12).count == 12
    assert NeedMoreError(to_end=True).to_end
