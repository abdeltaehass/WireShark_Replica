"""Messages that span packets, decoded in the packet that completes them.

What the reassembled fields decode to is checked against tshark in
test_tshark.py. These are the things tshark can't answer: which packet a
message lands in, where its fields say their bytes are, and what happens when
the pieces are late, repeated, contradictory or missing.
"""

import gzip
import struct
from hashlib import sha256
from pathlib import Path

import pytest

import pilotfish.core.protocols  # noqa: F401  (registers the dissectors)
from packets import ethernet, icmp, icmp_echo, icmpv6, ipv4, ipv6, udp
from pilotfish.core.dissect import (
    LINK_TYPE,
    Context,
    DeclinedError,
    Dissector,
    Field,
    FieldType,
    NeedMoreError,
    ProtocolTree,
    Reader,
    Registry,
    Session,
    dissect,
)
from pilotfish.core.formats import CaptureFile
from pilotfish.core.packet import Packet
from pilotfish.core.protocols import http
from pilotfish.core.protocols.checksum import ChecksumStatus
from pilotfish.core.protocols.ethernet import ETHERTYPE, ETHERTYPE_IPV4, Ethernet
from pilotfish.core.protocols.ip import FRAGMENTS, IP_PROTO, PROTO_TCP
from pilotfish.core.protocols.ipv4 import IPv4
from pilotfish.core.protocols.tcp import TCP_PORT, WAITING, Tcp
from pilotfish.core.reassembly import Fragments
from streams import ACK, CLIENT, ETHERNET, FIN, PUSH, RESET, SERVER, SYN, Talk, decode
from tshark import captures_with_keys

ICMP = 1
UDP = 17
SECOND = 1_000_000_000


def fragmented(
    datagram: bytes, protocol: int, size: int = 1480, *, identifier: int = 7
) -> list[bytes]:
    """One IPv4 datagram as the frames a router would cut it into."""
    return [
        ethernet(
            ipv4(
                datagram[at : at + size],
                protocol,
                at // 8,
                flags=0b001 if at + size < len(datagram) else 0,
                identifier=identifier,
            )
        )
        for at in range(0, len(datagram), size)
    ]


PING = icmp_echo(payload=bytes(range(256)) * 12)


class TestIPv4Fragments:
    def test_a_datagram_is_decoded_in_the_packet_that_completes_it(self) -> None:
        first, second, last = decode(fragmented(PING, ICMP))
        for early in (first, second):
            assert early.protocols == ("frame", "eth", "ip", "data")
            assert early.info.startswith("Fragmented IP protocol (proto=1, off=")
        assert last.protocols == ("frame", "eth", "ip", "icmp")
        assert last.error is None
        assert last.values("ip.fragment") == [1, 2, 3]
        assert last.get("ip.fragment.count") == 3
        assert last.get("ip.reassembled.length") == len(PING)
        assert last.get("ip.reassembled.data") == PING
        assert last.info.startswith("Echo (ping) request")

    def test_the_checksum_is_taken_over_the_whole_datagram(self) -> None:
        # The checksum covers every byte of the message, so it only comes
        # out right if the pieces went back exactly where they belong.
        *_, last = decode(fragmented(PING, ICMP))
        assert last.get("icmp.checksum.status") == ChecksumStatus.GOOD

    def test_reassembled_fields_point_into_the_reassembled_bytes(self) -> None:
        *_, last = decode(fragmented(PING, ICMP))
        [source] = last.sources
        assert source.name == "Reassembled IPv4"
        assert source.data == PING
        ip, message = last.layers[2], last.layers[3]
        assert all(node.source is None for node in ip.walk())
        assert all(node.source is source for node in message.walk())
        # The sequence number is two bytes, six into the message.
        sequence = last.find("icmp.seq")
        assert sequence is not None
        assert source.data[sequence.offset : sequence.offset + sequence.length] == b"\x00\x01"

    def test_fragments_that_arrive_backwards(self) -> None:
        first, second, last = decode(fragmented(PING, ICMP)[::-1])
        assert first.protocols[-1] == second.protocols[-1] == "data"
        assert last.protocols[-1] == "icmp"
        assert last.get("ip.reassembled.data") == PING
        assert last.get("icmp.checksum.status") == ChecksumStatus.GOOD

    def test_a_udp_datagram_and_its_checksum(self) -> None:
        datagram = udp(50000, 50001, bytes(3000), source=CLIENT, destination=SERVER)
        *_, last = decode(fragmented(datagram, UDP))
        assert last.protocols == ("frame", "eth", "ip", "udp", "data")
        assert last.get("udp.checksum.status") == ChecksumStatus.GOOD
        assert last.get("udp.length") == 3008

    def test_two_datagrams_whose_fragments_arrive_mixed_together(self) -> None:
        ours = fragmented(PING, ICMP, identifier=1)
        theirs = fragmented(icmp_echo(sequence=2, payload=bytes(2000)), ICMP, identifier=2)
        trees = decode([ours[0], theirs[0], ours[1], theirs[1], ours[2]])
        assert [tree.protocols[-1] for tree in trees] == ["data", "data", "data", "icmp", "icmp"]
        assert trees[3].get("icmp.seq") == 2
        assert trees[4].get("icmp.seq") == 1

    def test_a_fragment_sent_twice_is_noted(self) -> None:
        first, last = fragmented(PING[:2000], ICMP)
        *_, tree = decode([first, first, last])
        assert tree.get("ip.fragment.overlap") is True
        assert "ip.fragment.overlap.conflict" not in tree
        assert tree.get("ip.fragment.count") == 3

    def test_fragments_that_disagree_keep_the_bytes_that_came_first(self) -> None:
        datagram = udp(50000, 50001, b"A" * 16)
        rewrite = ethernet(ipv4(b"B" * 8, UDP, 1, flags=0b001, identifier=7))
        frames = [
            ethernet(ipv4(datagram[:16], UDP, flags=0b001, identifier=7)),
            rewrite,
            ethernet(ipv4(datagram[16:], UDP, 2, flags=0, identifier=7)),
        ]
        *_, tree = decode(frames)
        assert tree.get("ip.fragment.overlap.conflict") is True
        assert tree.get("ip.reassembled.data") == datagram
        assert tree.get("udp.payload") == b"A" * 16

    def test_a_fragment_reaching_past_the_largest_datagram_is_malformed(self) -> None:
        # The "ping of death": every fragment is legal, and they add up to
        # more than a datagram's length can say.
        frame = ethernet(ipv4(bytes(1480), ICMP, 8189, flags=0, identifier=7))
        [tree] = decode([frame])
        assert tree.error is not None
        assert "past the 65535 a datagram can hold" in tree.error

    def test_a_fragment_whose_header_is_damaged_is_left_alone(self) -> None:
        first, _, last = fragmented(PING, ICMP)
        damaged = ethernet(
            ipv4(PING[1480:2960], ICMP, 185, flags=0b001, identifier=7, break_checksum=True)
        )
        trees = decode([first, damaged, last])
        assert all(tree.protocols[-1] == "data" for tree in trees)

    def test_a_fragment_the_capture_cut_short_is_left_alone(self) -> None:
        session = Session()
        first, second, last = fragmented(PING, ICMP)
        cut = Packet(SECOND, len(second), ETHERNET, second[:600])
        dissect(Packet(SECOND, len(first), ETHERNET, first), 1, session=session)
        dissect(cut, 2, session=session)
        tree = dissect(Packet(SECOND, len(last), ETHERNET, last), 3, session=session)
        assert tree.protocols[-1] == "data"

    def test_a_fragment_quoted_in_an_error_message_is_not_one_of_the_captures(self) -> None:
        session = Session()
        quoted = ipv4(PING[:8], ICMP, flags=0b001, identifier=7)
        unreachable = ethernet(ipv4(icmp(3, 1, bytes(4) + quoted), ICMP, source=SERVER))
        tree = dissect(Packet(SECOND, len(unreachable), ETHERNET, unreachable), 1, session=session)
        assert tree.error is None
        assert FRAGMENTS not in session or len(session.store(FRAGMENTS, Fragments)) == 0

    def test_fragments_too_far_apart_in_time_are_not_the_same_datagram(self) -> None:
        session = Session()
        first, second, last = fragmented(PING, ICMP)
        times = (0, 10 * SECOND, 45 * SECOND)
        trees = [
            dissect(Packet(when, len(frame), ETHERNET, frame), number, session=session)
            for number, (when, frame) in enumerate(zip(times, (first, second, last), strict=True))
        ]
        assert [tree.protocols[-1] for tree in trees] == ["data", "data", "data"]

    def test_a_flood_of_first_fragments_is_held_to_a_fixed_amount(self) -> None:
        session = Session()
        for number in range(5000):
            frame = ethernet(ipv4(bytes(1480), UDP, flags=0b001, identifier=number))
            dissect(Packet(SECOND, len(frame), ETHERNET, frame), number + 1, session=session)
        waiting = session.store(FRAGMENTS, Fragments)
        assert waiting.buffered <= 4 * 1024 * 1024
        assert len(waiting) <= 1024

    def test_one_capture_does_not_finish_another_captures_datagram(self) -> None:
        first, second, last = fragmented(PING, ICMP)
        decode([first, second])
        [tree] = decode([last])
        assert tree.protocols[-1] == "data"


def fragment_header(next_header: int, offset: int, more: bool, identifier: int = 0xF00D) -> bytes:
    return struct.pack(">BBHI", next_header, 0, offset | int(more), identifier)


def fragmented_v6(datagram: bytes, next_header: int, size: int = 1232) -> list[bytes]:
    return [
        ethernet(
            ipv6(
                fragment_header(next_header, at, at + size < len(datagram))
                + datagram[at : at + size],
                44,
            ),
            0x86DD,
        )
        for at in range(0, len(datagram), size)
    ]


PING6 = icmpv6(128, 0, struct.pack(">HH", 0x00DE, 1) + bytes(range(250)) * 8)


class TestIPv6Fragments:
    def test_a_datagram_is_decoded_in_the_packet_that_completes_it(self) -> None:
        first, last = decode(fragmented_v6(PING6, 58))
        assert first.protocols == ("frame", "eth", "ipv6", "ipv6.fraghdr", "data")
        assert first.info == "IPv6 fragment (off=0 more=y ident=0x0000f00d nxt=58)"
        assert last.protocols == ("frame", "eth", "ipv6", "ipv6.fraghdr", "icmpv6", "data")
        assert last.values("ipv6.fragment") == [1, 2]
        assert last.get("ipv6.reassembled.length") == len(PING6)
        assert last.get("icmpv6.checksum.status") == ChecksumStatus.GOOD
        assert [source.name for source in last.sources] == ["Reassembled IPv6"]

    def test_fragments_that_arrive_backwards(self) -> None:
        first, last = decode(fragmented_v6(PING6, 58)[::-1])
        assert first.protocols[-1] == "data"
        assert first.info == "IPv6 fragment (off=1232 more=n ident=0x0000f00d nxt=58)"
        assert "icmpv6" in last.protocols
        assert last.get("ipv6.reassembled.data") == PING6

    def test_a_fragment_header_on_a_whole_datagram_changes_nothing(self) -> None:
        # Some stacks add the header to a datagram that was never cut up.
        echo = icmpv6(128, 0, struct.pack(">HH", 0x00DE, 1) + b"whole")
        [tree] = decode([ethernet(ipv6(fragment_header(58, 0, False) + echo, 44), 0x86DD)])
        assert "icmpv6" in tree.protocols
        assert "ipv6.fragment" not in tree
        assert not tree.sources


class Records(Dissector):
    """A protocol made up for these tests: a two-byte length, then that many
    bytes. One record is read at a time, and one that isn't all here is asked
    for again when the rest has arrived."""

    name = "rec"
    title = "Record"
    fields = (
        Field("rec.length", FieldType.UINT, "Length"),
        Field("rec.body", FieldType.BYTES, "Body"),
    )

    def dissect(self, reader: Reader, context: Context) -> None:
        if reader.remaining < 2:
            if context.can_wait:
                raise NeedMoreError
            raise DeclinedError
        length = int.from_bytes(reader.buffer.peek(2), "big")
        if length == 0xFFFF:
            raise DeclinedError
        missing = 2 + length - reader.remaining
        if missing > 0 and context.can_wait:
            raise NeedMoreError(missing)
        reader.uint16("rec.length")
        body = reader.bytes("rec.body", min(length, reader.remaining))
        context.describe(f"Record of {len(body)}")
        return None


class Everything(Dissector):
    """Another: a message with no length, which lasts until the stream closes."""

    name = "all"
    title = "Everything"
    fields = (Field("all.said", FieldType.BYTES, "Said"),)

    def dissect(self, reader: Reader, context: Context) -> None:
        if context.can_wait:
            raise NeedMoreError(to_end=True)
        reader.bytes("all.said", reader.remaining)
        return None


RECORDS_PORT = 7000
EVERYTHING_PORT = 7001

REGISTRY = Registry()
"""The real link, network and transport layers, with the toys on top."""
REGISTRY.add(Ethernet, LINK_TYPE, (ETHERNET,))
REGISTRY.add(IPv4, ETHERTYPE, (ETHERTYPE_IPV4,))
REGISTRY.add(Tcp, IP_PROTO, (PROTO_TCP,))
REGISTRY.add(Records, TCP_PORT, (RECORDS_PORT,))
REGISTRY.add(Everything, TCP_PORT, (EVERYTHING_PORT,))


def record(body: bytes) -> bytes:
    return len(body).to_bytes(2, "big") + body


def records(frames: list[bytes]) -> list[ProtocolTree]:
    return decode(frames, registry=REGISTRY)


def bodies(tree: ProtocolTree) -> list[bytes]:
    return [bytes(value) for value in tree.values("rec.body")]  # type: ignore[arg-type]


BODY = bytes(range(256)) * 16


class TestMessagesOverTcp:
    def talk(self) -> Talk:
        return Talk(server_port=RECORDS_PORT)

    def test_a_message_in_one_segment_is_read_from_the_packet(self) -> None:
        [tree] = records(self.talk().send(record(b"hello"), from_client=True))
        assert tree.protocols[-1] == "rec"
        assert bodies(tree) == [b"hello"]
        assert not tree.sources
        assert "tcp.segment_data" not in tree
        body = tree.find("rec.body")
        assert body is not None
        assert body.source is None

    def test_a_message_across_segments_is_decoded_in_the_last_of_them(self) -> None:
        frames = self.talk().send(record(BODY), from_client=True)
        assert len(frames) == 3
        first, second, last = records(frames)
        for early in (first, second):
            assert early.protocols[-1] == "tcp"
            assert early.info.endswith(WAITING)
            assert early.get("tcp.segment_data") == early.get("tcp.payload")
        assert last.protocols[-1] == "rec"
        assert bodies(last) == [BODY]
        assert last.values("tcp.segment") == [1, 2, 3]
        assert last.get("tcp.segment.count") == 3
        assert last.get("tcp.reassembled.length") == len(BODY) + 2
        assert last.info == f"Record of {len(BODY)}"

    def test_a_reassembled_message_points_into_the_reassembled_bytes(self) -> None:
        *_, last = records(self.talk().send(record(BODY), from_client=True))
        [source] = last.sources
        assert source.name == "Reassembled TCP"
        assert source.data == record(BODY)
        body = last.find("rec.body")
        assert body is not None
        assert body.source is source
        assert source.data[body.offset : body.offset + body.length] == BODY
        # The segment's own bytes are still where they were, in the packet.
        segment = last.find("tcp.segment_data")
        assert segment is not None
        assert segment.source is None

    def test_several_messages_in_one_segment(self) -> None:
        payload = record(b"one") + record(b"two") + record(b"three")
        [tree] = records(self.talk().send(payload, from_client=True))
        assert tree.protocols[-3:] == ("rec", "rec", "rec")
        assert bodies(tree) == [b"one", b"two", b"three"]
        assert tree.info == "Record of 3, Record of 3, Record of 5"

    def test_the_end_of_one_message_a_whole_one_and_the_start_of_another(self) -> None:
        talk = self.talk()
        stream = record(b"a" * 100) + record(b"b" * 10) + record(b"c" * 100)
        cuts = (stream[:60], stream[60:150], stream[150:])
        first, middle, last = records([talk.segment(piece, from_client=True) for piece in cuts])
        assert first.protocols[-1] == "tcp"
        assert bodies(middle) == [b"a" * 100, b"b" * 10]
        # The first message is the reassembled one. The second is all in
        # this packet, so it is read from the packet.
        assert [layer.source is not None for layer in middle.layers[-2:]] == [True, False]
        assert middle.values("tcp.segment") == [1, 2]
        # The bytes that finished the first message, and the ones that
        # start the third.
        assert middle.values("tcp.segment_data") == [stream[60:102], stream[114:150]]
        assert bodies(last) == [b"c" * 100]
        assert last.values("tcp.segment") == [2, 3]

    def test_a_length_that_is_itself_split_across_segments(self) -> None:
        talk = self.talk()
        whole = record(b"split")
        first, last = records(
            [talk.segment(whole[:1], from_client=True), talk.segment(whole[1:], from_client=True)]
        )
        assert first.protocols[-1] == "tcp"
        assert bodies(last) == [b"split"]

    def test_a_segment_that_overtakes_another_waits_for_it(self) -> None:
        one, two, three = self.talk().send(record(BODY), from_client=True)
        _, early, late = records([one, three, two])
        assert early.protocols[-1] == "tcp"
        assert early.get("tcp.analysis.lost_segment") is True
        assert early.get("tcp.segment_data") == early.get("tcp.payload")
        assert bodies(late) == [BODY]
        assert set(late.values("tcp.segment")) == {1, 2, 3}

    def test_a_segment_sent_twice_is_only_counted_once(self) -> None:
        one, two, three = self.talk().send(record(BODY), from_client=True)
        *_, again, last = records([one, two, two, three])
        assert again.protocols[-1] == "tcp"
        assert again.get("tcp.segment_data") == again.get("tcp.payload")
        assert not again.info.endswith(WAITING)
        assert bodies(last) == [BODY]

    def test_a_segment_that_repeats_some_bytes_and_adds_others(self) -> None:
        talk = self.talk()
        whole = record(b"x" * 300)
        first = talk.segment(whole[:200], from_client=True)
        # Sent again from further back than where the sender had got to.
        overlapping = talk.segment(whole[100:], from_client=True, seq=1000 + 100)
        _, last = records([first, overlapping])
        assert bodies(last) == [b"x" * 300]
        # The hundred bytes that repeat, then the rest, which finish it.
        assert last.values("tcp.segment_data") == [whole[100:200], whole[200:]]

    def test_a_capture_that_starts_mid_connection_starts_with_what_it_sees(self) -> None:
        # Nothing says what came before the first segment a capture holds,
        # so there is nothing to wait for.
        talk = self.talk()
        talk.segment(record(b"a" * 50), from_client=True)
        [tree] = records([talk.segment(record(b"b" * 50), from_client=True)])
        assert bodies(tree) == [b"b" * 50]

    def test_a_gap_in_the_middle_is_given_up_on_and_the_stream_carries_on(self) -> None:
        talk = Talk(server_port=RECORDS_PORT)
        handshake = talk.handshake()
        first = talk.segment(record(b"a" * 50), from_client=True)
        # Sent, received and acknowledged, but never captured.
        talk.segment(record(b"b" * 50), from_client=True)
        third = talk.segment(record(b"c" * 50), from_client=True)
        seen = talk.acknowledge(from_client=False)
        fourth = talk.segment(record(b"d" * 50), from_client=True)
        trees = records([*handshake, first, third, seen, fourth])
        assert bodies(trees[3]) == [b"a" * 50]
        assert trees[4].protocols[-1] == "tcp"
        # What was waiting behind the gap comes out with the next segment.
        assert bodies(trees[6]) == [b"c" * 50, b"d" * 50]

    def test_a_segment_that_arrived_damaged_does_not_join_the_stream(self) -> None:
        talk = self.talk()
        whole = record(b"y" * 200)
        first = talk.segment(whole[:100], from_client=True)
        damaged = talk.segment(b"!" * 102, from_client=True, seq=1100, break_checksum=True)
        resent = talk.segment(whole[100:], from_client=True)
        _, bad, last = records([first, damaged, resent])
        assert bad.get("tcp.checksum.status") == ChecksumStatus.BAD
        assert bodies(last) == [b"y" * 200]

    def test_the_same_ports_used_again_start_a_new_stream(self) -> None:
        old = Talk(server_port=RECORDS_PORT)
        new = Talk(server_port=RECORDS_PORT, client_isn=900_000, server_isn=700_000)
        frames = [
            *old.handshake(),
            old.segment(record(b"old" * 100)[:100], from_client=True),
            *new.handshake(),
            *new.send(record(b"new"), from_client=True),
        ]
        *_, last = records(frames)
        assert bodies(last) == [b"new"]

    def test_bytes_that_are_not_the_protocol_stay_data_and_are_not_kept(self) -> None:
        talk = self.talk()
        junk, fine = records(
            [
                talk.segment(b"\xff\xff not a record", from_client=True),
                talk.segment(record(b"fine"), from_client=True),
            ]
        )
        assert junk.protocols[-1] == "data"
        assert bodies(fine) == [b"fine"]
        assert not fine.sources

    def test_each_direction_is_a_stream_of_its_own(self) -> None:
        talk = self.talk()
        asked = record(b"q" * 60)
        told = record(b"a" * 60)
        trees = records(
            [
                talk.segment(asked[:30], from_client=True),
                talk.segment(told[:30], from_client=False),
                talk.segment(asked[30:], from_client=True),
                talk.segment(told[30:], from_client=False),
            ]
        )
        assert bodies(trees[2]) == [b"q" * 60]
        assert bodies(trees[3]) == [b"a" * 60]
        assert trees[2].values("tcp.segment") == [1, 3]
        assert trees[3].values("tcp.segment") == [2, 4]

    def test_a_segment_quoted_in_an_error_message_does_not_join_the_stream(self) -> None:
        talk = self.talk()
        whole = record(b"z" * 40)
        first = talk.segment(whole[:20], from_client=True)
        quoted = first[14:]
        unreachable = ethernet(ipv4(icmp(3, 1, bytes(4) + quoted), ICMP, source=SERVER))
        last = talk.segment(whole[20:], from_client=True)
        trees = records([first, unreachable, last])
        assert bodies(trees[2]) == [b"z" * 40]
        assert trees[2].values("tcp.segment") == [1, 3]


class TestAMessageThatLastsUntilTheStreamCloses:
    def test_it_is_decoded_in_the_packet_that_closes_the_stream(self) -> None:
        talk = Talk(server_port=EVERYTHING_PORT)
        frames = [
            *talk.handshake(),
            *talk.send(b"a" * 3000, from_client=False),
            talk.finish(from_client=False),
        ]
        *waiting, closed = records(frames)[3:]
        assert all(tree.protocols[-1] == "tcp" for tree in waiting)
        assert closed.get("all.said") == b"a" * 3000
        # The closing segment counts as one of the message's, as Wireshark
        # counts it, though it carried nothing.
        assert closed.values("tcp.segment") == [4, 5, 6, 7]

    def test_a_reset_closes_it_too(self) -> None:
        talk = Talk(server_port=EVERYTHING_PORT)
        frames = [
            *talk.handshake(),
            *talk.send(b"cut off", from_client=False),
            talk.segment(from_client=False, flags=RESET | ACK),
        ]
        *_, reset = records(frames)
        assert reset.get("all.said") == b"cut off"

    def test_the_last_bytes_can_come_with_the_close(self) -> None:
        talk = Talk(server_port=EVERYTHING_PORT)
        frames = [
            *talk.handshake(),
            talk.segment(b"first, ", from_client=False),
            talk.segment(b"and last", from_client=False, flags=FIN | ACK | PUSH),
        ]
        *_, closed = records(frames)
        assert closed.get("all.said") == b"first, and last"

    def test_a_close_that_arrives_before_the_bytes_ahead_of_it_waits(self) -> None:
        talk = Talk(server_port=EVERYTHING_PORT)
        handshake = talk.handshake()
        one, two = talk.send(b"b" * 2000, from_client=False)
        close = talk.finish(from_client=False)
        *_, early, late = records([*handshake, one, close, two])
        assert early.protocols[-1] == "tcp"
        assert late.get("all.said") == b"b" * 2000


def response(body: bytes, *headers: str, status: str = "200 OK") -> bytes:
    lines = [f"HTTP/1.1 {status}", *headers, "", ""]
    return "\r\n".join(lines).encode() + body


FILE = b"".join(sha256(number.to_bytes(4, "big")).digest() for number in range(400))


class TestHttp:
    def exchange(self, answer: bytes, request: bytes = b"GET /file HTTP/1.1\r\n\r\n") -> Talk:
        self.frames = (talk := Talk()).handshake()
        self.frames += talk.send(request, from_client=True)
        self.frames += talk.send(answer, from_client=False)
        return talk

    def test_a_download_is_decoded_whole_in_its_last_packet(self) -> None:
        self.exchange(response(FILE, f"Content-Length: {len(FILE)}"))
        *waiting, last = decode(self.frames)[4:]
        assert len(waiting) == 8
        assert all(tree.protocols[-1] == "tcp" for tree in waiting)
        assert last.protocols[-2:] == ("http", "data")
        file = last.get("http.file_data")
        assert isinstance(file, bytes)
        assert sha256(file).digest() == sha256(FILE).digest()
        assert last.get("http.request_in") == 4
        assert last.get("tcp.segment.count") == 9

    def test_headers_that_are_themselves_split(self) -> None:
        answer = response(b"body", "Content-Length: 4", "Content-Type: text/plain")
        talk = Talk()
        frames = [
            talk.segment(answer[:20], from_client=False),
            talk.segment(answer[20:50], from_client=False),
            talk.segment(answer[50:], from_client=False),
        ]
        *waiting, last = decode(frames)
        assert all(tree.protocols[-1] == "tcp" for tree in waiting)
        assert last.get("http.response.code") == 200
        assert last.get("http.file_data") == b"body"
        assert last.info == "HTTP/1.1 200 OK  (text/plain)"

    def test_a_request_line_too_long_for_one_segment(self) -> None:
        # An address with a long query in it outgrows a segment before the
        # line that carries it has ended.
        address = "/search?q=" + "x" * 3000
        request = f"GET {address} HTTP/1.1\r\nHost: example.com\r\n\r\n".encode()
        *waiting, last = decode(Talk().send(request, from_client=True))
        assert len(waiting) == 2
        assert all(tree.protocols[-1] == "tcp" for tree in waiting)
        assert last.get("http.request.uri") == address

    def test_a_method_cut_in_half(self) -> None:
        talk = Talk()
        request = b"GET / HTTP/1.1\r\n\r\n"
        first, last = decode(
            [
                talk.segment(request[:2], from_client=True),
                talk.segment(request[2:], from_client=True),
            ]
        )
        assert first.protocols[-1] == "tcp"
        assert last.get("http.request.method") == "GET"

    def test_bytes_on_the_http_port_that_are_not_http_are_not_waited_for(self) -> None:
        [tree] = decode([Talk().segment(b"a" * 100, from_client=True)])
        assert tree.protocols[-1] == "data"
        assert "tcp.segment_data" not in tree

    def test_a_body_sent_in_chunks_across_segments(self) -> None:
        chunks = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
        talk = Talk()
        answer = response(chunks, "Transfer-Encoding: chunked")
        frames = talk.send(answer, from_client=False, size=9)
        *waiting, last = decode(frames)
        assert all(tree.protocols[-1] == "tcp" for tree in waiting)
        assert last.values("http.chunk_size") == [5, 6, 0]
        assert last.values("http.chunk_data") == [b"hello", b" world"]
        assert last.get("http.file_data") == b"hello world"

    @pytest.mark.parametrize("size", [b"-2", b"+5", b"0x5", b"5_0", b"fffffffff", b"five", b""])
    def test_a_chunk_size_that_is_not_one_ends_the_body_there(self, size: bytes) -> None:
        # A sign is the dangerous one: a chunk of minus two bytes would be
        # stepped over by going nowhere, for ever.
        answer = response(b"5\r\nhello\r\n" + size + b"\r\nrest", "Transfer-Encoding: chunked")
        [tree] = decode(Talk().send(answer, from_client=False))
        assert tree.error is None
        assert tree.values("http.chunk_data") == [b"hello"]
        assert tree.get("http.file_data") == b"hello"

    def test_a_compressed_body_is_unpacked(self) -> None:
        text = b"the same line, over and over\n" * 200
        packed = gzip.compress(text)
        self.exchange(response(packed, f"Content-Length: {len(packed)}", "Content-Encoding: gzip"))
        *_, last = decode(self.frames)
        assert last.get("http.file_data") == text

    def test_a_body_that_claims_to_be_compressed_and_is_not(self) -> None:
        self.exchange(response(b"plain", "Content-Length: 5", "Content-Encoding: gzip"))
        *_, last = decode(self.frames)
        assert last.protocols[-2:] == ("http", "data")
        assert "http.file_data" not in last

    def test_a_body_built_to_swell_is_only_unpacked_so_far(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # A megabyte of zeros is a kilobyte once compressed. The same trick
        # at scale is a few kilobytes that unpack into gigabytes.
        monkeypatch.setattr(http, "MAX_DECODED", 4096)
        bomb = gzip.compress(bytes(1_000_000))
        self.exchange(response(bomb, f"Content-Length: {len(bomb)}", "Content-Encoding: gzip"))
        *_, last = decode(self.frames)
        assert last.get("http.file_data") == bytes(4096)

    def test_a_body_with_no_length_ends_when_the_server_hangs_up(self) -> None:
        talk = self.exchange(response(b"old style " * 300))
        self.frames.append(talk.finish(from_client=False))
        *waiting, closed = decode(self.frames)[4:]
        assert all(tree.protocols[-1] == "tcp" for tree in waiting)
        assert closed.get("http.file_data") == b"old style " * 300

    def test_the_answer_to_head_has_no_body_to_wait_for(self) -> None:
        self.exchange(
            response(b"", "Content-Length: 50000"), request=b"HEAD /file HTTP/1.1\r\n\r\n"
        )
        *_, last = decode(self.frames)
        assert last.protocols[-1] == "http"
        assert last.get("http.content_length") == 50000
        assert "http.file_data" not in last

    @pytest.mark.parametrize("status", ["304 Not Modified", "204 No Content"])
    def test_an_answer_that_never_has_a_body(self, status: str) -> None:
        self.exchange(response(b"", status=status))
        *_, last = decode(self.frames)
        assert last.protocols[-1] == "http"

    def test_a_tunnel_is_not_waited_for_as_a_body(self) -> None:
        self.exchange(
            response(b"", status="200 Connection established"),
            request=b"CONNECT example.com:443 HTTP/1.1\r\n\r\n",
        )
        *_, last = decode(self.frames)
        assert last.protocols[-1] == "http"

    def test_two_answers_in_one_segment_each_answer_their_own_request(self) -> None:
        talk = Talk()
        requests = b"GET /a HTTP/1.1\r\n\r\n" + b"GET /b HTTP/1.1\r\n\r\n"
        answers = response(b"first", "Content-Length: 5") + response(b"second", "Content-Length: 6")
        asked, answered = decode(
            [talk.segment(requests, from_client=True), talk.segment(answers, from_client=False)]
        )
        assert asked.values("http.request.uri") == ["/a", "/b"]
        assert answered.protocols[-4:] == ("http", "data", "http", "data")
        assert answered.values("http.file_data") == [b"first", b"second"]
        assert answered.values("http.request.uri") == ["/a", "/b"]

    def test_an_interim_answer_leaves_the_request_waiting_for_its_real_one(self) -> None:
        talk = Talk()
        frames = [
            talk.segment(b"POST /form HTTP/1.1\r\nContent-Length: 0\r\n\r\n", from_client=True),
            talk.segment(response(b"", status="100 Continue"), from_client=False),
            talk.segment(response(b"ok", "Content-Length: 2"), from_client=False),
        ]
        _, interim, final = decode(frames)
        assert interim.get("http.request_in") == 1
        assert final.get("http.request_in") == 1

    def test_a_request_with_a_body_across_segments(self) -> None:
        form = b"field=" + b"v" * 3000
        request = b"POST /form HTTP/1.1\r\nContent-Length: %d\r\n\r\n" % len(form) + form
        *waiting, last = decode(Talk().send(request, from_client=True))
        assert all(tree.protocols[-1] == "tcp" for tree in waiting)
        assert last.get("http.request.method") == "POST"
        assert last.get("http.file_data") == form

    def test_a_message_cut_short_by_the_capture_gives_up_what_it_has(self) -> None:
        # A snapshot length kept the first 200 bytes of the frame. With no
        # more to come, part of a body is all there is to show.
        answer = response(b"x" * 1000, "Content-Length: 1000")
        frame = Talk().segment(answer, from_client=False)
        tree = dissect(Packet(SECOND, len(frame), ETHERNET, frame[:200]))
        assert tree.get("http.response.code") == 200
        assert tree.get("http.file_data") == b"x" * (
            200 - 54 - len(response(b"", "Content-Length: 1000"))
        )
        assert tree.info == "HTTP/1.1 200 OK "


def tls_record(kind: int, body: bytes) -> bytes:
    return struct.pack(">BHH", kind, 0x0303, len(body)) + body


class TestTls:
    def test_a_record_across_segments_is_decoded_in_the_last_of_them(self) -> None:
        talk = Talk(server_port=443)
        data = bytes(range(256)) * 12
        first, second, last = decode(talk.send(tls_record(23, data), from_client=False))
        assert first.protocols[-1] == second.protocols[-1] == "tcp"
        assert last.protocols[-1] == "tls"
        assert last.get("tls.record.length") == len(data)
        assert last.get("tls.app_data") == data
        assert last.info == "Application Data"

    def test_a_record_header_split_across_segments(self) -> None:
        talk = Talk(server_port=443)
        stream = tls_record(20, b"\x01") + tls_record(23, bytes(40))
        whole, header, rest = decode(
            [
                talk.segment(stream[:6], from_client=False),
                talk.segment(stream[6:9], from_client=False),
                talk.segment(stream[9:], from_client=False),
            ]
        )
        assert whole.info == "Change Cipher Spec"
        assert header.protocols[-1] == "tcp"
        assert rest.get("tls.app_data") == bytes(40)

    def test_whole_records_are_decoded_and_the_start_of_the_next_is_left(self) -> None:
        talk = Talk(server_port=443)
        stream = tls_record(23, bytes(30)) + tls_record(23, bytes(range(60)))
        first, last = decode(
            [
                talk.segment(stream[:50], from_client=False),
                talk.segment(stream[50:], from_client=False),
            ]
        )
        assert first.values("tls.app_data") == [bytes(30)]
        assert first.get("tcp.segment_data") == stream[35:50]
        assert last.values("tls.app_data") == [bytes(range(60))]
        assert last.values("tcp.segment") == [1, 2]

    def test_with_no_more_to_come_part_of_a_record_is_shown_as_that(self) -> None:
        # A segment the capture cut short can't be added to, so what it
        # holds of the record is all that will ever be seen.
        payload = tls_record(23, bytes(1000))
        frame = Talk(server_port=443).segment(payload, from_client=False)
        tree = dissect(Packet(SECOND, len(frame), ETHERNET, frame[:99]))
        assert tree.get("tls.segment.data") == payload[:45]
        assert "tls.record.length" not in tree


def ssh_packet(payload: bytes, padding: int = 8) -> bytes:
    return struct.pack(">IB", 1 + len(payload) + padding, padding) + payload + bytes(padding)


class TestSsh:
    def test_a_key_exchange_message_across_segments(self) -> None:
        names = b"curve25519-sha256," * 60
        lists = [names, *([b"none"] * 9)]
        body = bytes(16) + b"".join(struct.pack(">I", len(each)) + each for each in lists)
        kexinit = ssh_packet(bytes([20]) + body + b"\x00" + bytes(4))
        talk = Talk(server_port=22)
        frames = [talk.segment(b"SSH-2.0-OpenSSH_9.6\r\n", from_client=True)]
        frames += talk.send(kexinit, from_client=True, size=500)
        greeting, *waiting, last = decode(frames)
        assert greeting.get("ssh.protocol") == "SSH-2.0-OpenSSH_9.6"
        assert all(tree.protocols[-1] == "tcp" for tree in waiting)
        assert last.get("ssh.message_code") == 20
        assert last.get("ssh.kex_algorithms") == names.decode()
        assert last.info == "Client: Key Exchange Init"

    def test_a_binary_packet_on_another_port_needs_a_greeting_first(self) -> None:
        # A length and a padding count look like a great many protocols.
        talk = Talk(server_port=2222)
        [alone] = decode([talk.segment(ssh_packet(bytes([20]) + bytes(40)), from_client=True)])
        assert alone.protocols[-1] == "data"
        talk = Talk(server_port=2222)
        _, after = decode(
            [
                talk.segment(b"SSH-2.0-OpenSSH_9.6\r\n", from_client=True),
                talk.segment(ssh_packet(bytes([21])), from_client=True),
            ]
        )
        assert after.protocols[-1] == "ssh"
        assert after.get("ssh.message_code") == 21


def test_a_syn_that_carries_data_starts_the_stream_after_itself() -> None:
    # TCP Fast Open sends the first bytes along with the SYN.
    talk = Talk(server_port=RECORDS_PORT)
    whole = record(b"fast" * 20)
    opening = talk.segment(whole[:30], from_client=True, flags=SYN)
    rest = talk.segment(whole[30:], from_client=True, flags=ACK | PUSH)
    _, last = records([opening, rest])
    assert bodies(last) == [b"fast" * 20]


@pytest.mark.parametrize("capture", captures_with_keys(), ids=lambda capture: capture.name)
def test_every_field_points_inside_the_bytes_it_came_from(capture: Path) -> None:
    """A field's offset and length mean something only against the right bytes.

    For most fields those are the packet's. For a field decoded from a
    reassembled message they are the reassembled bytes, which the tree has to
    list, or nothing could show where the field came from.
    """
    session = Session()
    with CaptureFile(capture) as file:
        for number, packet in enumerate(file, start=1):
            tree = dissect(packet, number, session=session)
            for node in tree.walk():
                where = f"{node.name}, packet {number} of {capture.name}"
                within = packet.captured_length
                if node.source is not None:
                    assert node.source in tree.sources, where
                    within = len(node.source.data)
                assert 0 <= node.offset <= node.offset + node.length <= within, where
