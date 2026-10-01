"""TCP: the header, its options, and what a connection's history says about it.

Most of a TCP header is plain reading. The interesting part is what can only
be known by remembering the rest of the connection: sequence numbers counted
from where the connection started rather than from the random number it chose,
and the judgements Wireshark makes about a segment that doesn't advance the
sequence number, which is either a retransmission, an out-of-order segment or
a duplicate of one already acknowledged.

The other thing a connection's history gives is its bytes in order. TCP
delivers a stream, and cuts it into segments wherever it pleases, so a
message can start in one packet and finish several later. Each direction's
bytes are put back in sequence as they arrive, and the protocol on top reads
whole messages off the front. A segment that only carries part of one is
listed as that, and the message is decoded in the packet that completes it.

References: RFC 9293 for the protocol, RFC 7323 for window scaling and
timestamps, RFC 2018 for selective acknowledgement. The analysis follows
Wireshark's ``tcp_analyze_sequence_number`` so its verdicts can be compared
with ours.
"""

from dataclasses import dataclass, field

from pilotfish.core.dissect import (
    Buffer,
    Context,
    Dissector,
    Field,
    FieldType,
    Handoff,
    MalformedError,
    NeedMoreError,
    Reader,
    Source,
    Stream,
    register,
)
from pilotfish.core.protocols.checksum import (
    ChecksumStatus,
    offloaded,
    pseudo_header,
    verify,
)
from pilotfish.core.protocols.conversations import Conversation, Conversations, Endpoint
from pilotfish.core.protocols.ip import IP_PROTO, PROTO_TCP
from pilotfish.core.reassembly import Flow

TCP_PORT = "tcp.port"
"""The table keyed by port, for what a segment carries."""

HEURISTICS = "tcp"
"""Dissectors to ask about a payload no port claimed."""

HEADER_SIZE = 20
WORD = 0xFFFFFFFF

FIN = 0x001
SYN = 0x002
RESET = 0x004
PUSH = 0x008
ACK = 0x010
URGENT = 0x020
ECE = 0x040
CWR = 0x080
ACCURATE_ECN = 0x100

# Every flag's letter, in the order Wireshark writes them, highest bit first.
_LETTERS = (
    (0x800, "R"),
    (0x400, "R"),
    (0x200, "R"),
    (ACCURATE_ECN, "N"),
    (CWR, "C"),
    (ECE, "E"),
    (URGENT, "U"),
    (ACK, "A"),
    (PUSH, "P"),
    (RESET, "R"),
    (SYN, "S"),
    (FIN, "F"),
)
_UNSET = "·"

OPTION_END = 0
OPTION_NOP = 1
OPTION_MSS = 2
OPTION_WINDOW_SCALE = 3
OPTION_SACK_PERMITTED = 4
OPTION_SACK = 5
OPTION_TIMESTAMPS = 8

MAX_WINDOW_SCALE = 14
"""RFC 7323 allows no more shift than this."""

SCALE_UNKNOWN = -1
"""What Wireshark reports when it never saw the handshake."""
SCALE_NOT_USED = -2
"""What it reports when the handshake had no window scale option."""

OUT_OF_ORDER_WINDOW_NS = 3_000_000
"""How soon after the last acknowledgement a gap still counts as re-ordering,
when the connection's round trip isn't known."""
FAST_RETRANSMISSION_NS = 20_000_000
"""How soon after duplicate acknowledgements a retransmission counts as fast."""
DUPLICATE_ACKS_BEFORE_FAST = 2

WINDOW_UNSEEN = -1
"""The window of a direction nothing has been seen from, which no real window
can be equal to."""

LISTENER = "tcp.listener"
"""Where a capture keeps whoever is following one of its connections."""

WAITING = " [TCP segment of a reassembled PDU]"
"""What the packet list says of a segment whose bytes belong to a message
that a later packet completes."""


@dataclass(slots=True)
class Sent:
    """A segment sent and not yet acknowledged."""

    sequence: int
    end: int
    frame: int
    time: int


@dataclass(slots=True)
class Side:
    """What has been seen in one direction of a connection."""

    base_seq: int | None = None
    """The sequence number this direction started from, which the relative
    numbers count from."""
    saw_syn: bool = False
    window_scale: int | None = None
    """The shift from this direction's SYN, if it had the option."""
    scale_pending: bool = False
    """Whether the scale has yet to take effect: it doesn't apply until this
    side has sent an ordinary acknowledgement after its SYN."""
    next_seq: int = 0
    """The sequence number expected next: the highest end seen so far."""
    next_seq_time: int = 0
    last_length: int = 0
    """How much data the segment that last moved ``next_seq`` carried, which
    tells a bare acknowledgement from data."""
    max_seq_to_be_acked: int = 0
    """How far this side has been seen to reach without a gap, so anything
    acknowledged beyond it was never captured."""
    last_ack: int = 0
    last_ack_time: int = 0
    last_non_duplicate_ack: int = 0
    """The frame number of the last acknowledgement that wasn't a duplicate."""
    duplicate_acks: int = 0
    window: int = WINDOW_UNSEEN
    """The window this side last advertised, as it was written rather than scaled."""
    last_flags: frozenset[str] = frozenset()
    """What the analysis said about the last segment from this side."""
    sent: list[Sent] = field(default_factory=list)
    """Segments sent and not yet acknowledged, newest first."""
    flow: Flow = field(default_factory=Flow)
    """The bytes this side sent, back in the order it sent them."""


@dataclass(slots=True)
class Connection:
    forward: Side = field(default_factory=Side)
    reverse: Side = field(default_factory=Side)
    syn_time: int | None = None
    """When the last SYN that opened the connection was sent."""
    initial_rtt: int | None = None
    """From that SYN to the first ordinary acknowledgement: the round trip of
    the handshake, which is what re-ordering is measured against."""
    opened_forward: bool | None = None
    """Whether the end that sent the capture's first packet is the one that
    opened the connection. Not known unless a SYN was captured."""


@dataclass(frozen=True, slots=True)
class Heard:
    """A run of bytes one end sent, in the order it sent them."""

    forward: bool
    """Whether they went the way the connection's first packet did."""
    data: bytes
    missed: int = 0
    """How many bytes the capture lost just before these."""


@dataclass(slots=True)
class Listener:
    """Whoever is following one connection.

    While a capture has a listener the segments are put in order and nothing
    more: no protocol on top is decoded, since all that is wanted is the
    bytes.
    """

    stream: int
    heard: list[Heard] = field(default_factory=list)
    conversation: Conversation[Connection] | None = None
    responder: Endpoint | None = None
    """The end that didn't send the first packet."""


@dataclass(frozen=True, slots=True)
class Segment:
    """One segment, as the analysis sees it: sequence numbers already counted
    from the start of the connection."""

    frame: int
    time: int
    flags: int
    sequence: int
    acknowledged: int
    length: int
    window: int
    """The window this end advertised, as it was written in the header. The
    scaling is applied where it is compared, as Wireshark applies it, because
    it only takes effect once the handshake is over."""


@register(IP_PROTO, PROTO_TCP)
class Tcp(Dissector):
    name = "tcp"
    title = "Transmission Control Protocol"
    fields = (
        Field("tcp.srcport", FieldType.UINT, "Source Port"),
        Field("tcp.dstport", FieldType.UINT, "Destination Port"),
        Field("tcp.stream", FieldType.UINT, "Stream index"),
        Field("tcp.len", FieldType.UINT, "TCP Segment Len"),
        Field("tcp.seq", FieldType.UINT, "Sequence Number"),
        Field("tcp.seq_raw", FieldType.UINT, "Sequence Number (raw)"),
        Field("tcp.nxtseq", FieldType.UINT, "Next Sequence Number"),
        Field("tcp.ack", FieldType.UINT, "Acknowledgment Number"),
        Field("tcp.ack_raw", FieldType.UINT, "Acknowledgment number (raw)"),
        Field("tcp.hdr_len", FieldType.UINT, "Header Length"),
        Field("tcp.flags", FieldType.UINT, "Flags", hex=True, digits=3),
        Field("tcp.flags.res", FieldType.UINT, "Reserved"),
        Field("tcp.flags.ae", FieldType.BOOL, "Accurate ECN"),
        Field("tcp.flags.cwr", FieldType.BOOL, "Congestion Window Reduced"),
        Field("tcp.flags.ece", FieldType.BOOL, "ECN-Echo"),
        Field("tcp.flags.urg", FieldType.BOOL, "Urgent"),
        Field("tcp.flags.ack", FieldType.BOOL, "Acknowledgment"),
        Field("tcp.flags.push", FieldType.BOOL, "Push"),
        Field("tcp.flags.reset", FieldType.BOOL, "Reset"),
        Field("tcp.flags.syn", FieldType.BOOL, "Syn"),
        Field("tcp.flags.fin", FieldType.BOOL, "Fin"),
        Field("tcp.flags.str", FieldType.STRING, "Flags"),
        Field("tcp.window_size_value", FieldType.UINT, "Window"),
        Field("tcp.window_size", FieldType.UINT, "Calculated window size"),
        Field("tcp.window_size_scalefactor", FieldType.INT, "Window size scaling factor"),
        Field("tcp.checksum", FieldType.UINT, "Checksum", hex=True),
        Field("tcp.checksum.status", FieldType.UINT, "Checksum status"),
        Field("tcp.urgent_pointer", FieldType.UINT, "Urgent Pointer"),
        Field("tcp.options", FieldType.BYTES, "TCP Options"),
        Field("tcp.option_kind", FieldType.UINT, "Kind"),
        Field("tcp.option_len", FieldType.UINT, "Length"),
        Field("tcp.options.nop", FieldType.BYTES, "TCP Option - No-Operation (NOP)"),
        Field("tcp.options.eol", FieldType.BYTES, "TCP Option - End of Option List (EOL)"),
        Field("tcp.options.mss", FieldType.BYTES, "TCP Option - Maximum segment size"),
        Field("tcp.options.mss_val", FieldType.UINT, "MSS Value"),
        Field("tcp.options.wscale", FieldType.BYTES, "TCP Option - Window scale"),
        Field("tcp.options.wscale.shift", FieldType.UINT, "Shift count"),
        Field("tcp.options.wscale.multiplier", FieldType.UINT, "Multiplier"),
        Field("tcp.options.sack_perm", FieldType.BYTES, "TCP Option - SACK permitted"),
        Field("tcp.options.sack", FieldType.BYTES, "TCP Option - SACK"),
        Field("tcp.options.sack.count", FieldType.UINT, "SACK Block Count"),
        Field("tcp.options.sack_le", FieldType.UINT, "Left Edge"),
        Field("tcp.options.sack_re", FieldType.UINT, "Right Edge"),
        Field("tcp.options.timestamp", FieldType.BYTES, "TCP Option - Timestamps"),
        Field("tcp.options.timestamp.tsval", FieldType.UINT, "Timestamp value"),
        Field("tcp.options.timestamp.tsecr", FieldType.UINT, "Timestamp echo reply"),
        Field("tcp.payload", FieldType.BYTES, "TCP payload"),
        Field("tcp.segment_data", FieldType.BYTES, "TCP segment data"),
        Field("tcp.segment", FieldType.UINT, "TCP Segment"),
        Field("tcp.segment.count", FieldType.UINT, "Segment count"),
        Field("tcp.reassembled.length", FieldType.UINT, "Reassembled TCP length"),
        Field("tcp.reassembled.data", FieldType.BYTES, "Reassembled TCP Data"),
        # What the connection's history says about this segment.
        Field("tcp.analysis.acks_frame", FieldType.UINT, "This is an ACK to the segment in frame"),
        Field("tcp.analysis.ack_rtt", FieldType.TIME, "The RTT to ACK the segment was"),
        Field("tcp.analysis.initial_rtt", FieldType.TIME, "iRTT"),
        Field("tcp.analysis.retransmission", FieldType.BOOL, "Retransmission"),
        Field("tcp.analysis.fast_retransmission", FieldType.BOOL, "Fast retransmission"),
        Field("tcp.analysis.spurious_retransmission", FieldType.BOOL, "Spurious retransmission"),
        Field("tcp.analysis.out_of_order", FieldType.BOOL, "Out-of-Order segment"),
        Field("tcp.analysis.lost_segment", FieldType.BOOL, "Previous segment not captured"),
        Field(
            "tcp.analysis.ack_lost_segment",
            FieldType.BOOL,
            "ACKed segment that wasn't captured",
        ),
        Field("tcp.analysis.duplicate_ack", FieldType.BOOL, "Duplicate ACK"),
        Field("tcp.analysis.duplicate_ack_num", FieldType.UINT, "Duplicate ACK #"),
        Field("tcp.analysis.duplicate_ack_frame", FieldType.UINT, "Duplicate to the ACK in frame"),
        Field("tcp.analysis.zero_window", FieldType.BOOL, "Zero window"),
        Field("tcp.analysis.zero_window_probe", FieldType.BOOL, "Zero window probe"),
        Field("tcp.analysis.zero_window_probe_ack", FieldType.BOOL, "Zero window probe ack"),
        Field("tcp.analysis.keep_alive", FieldType.BOOL, "Keep-Alive"),
        Field("tcp.analysis.keep_alive_ack", FieldType.BOOL, "Keep-Alive ACK"),
        Field("tcp.analysis.window_full", FieldType.BOOL, "Window is full"),
        Field("tcp.analysis.window_update", FieldType.BOOL, "Window update"),
    )

    def dissect(self, reader: Reader, context: Context) -> Handoff | None:
        whole = reader.buffer.peek(reader.remaining)
        source_port = reader.uint16("tcp.srcport")
        destination_port = reader.uint16("tcp.dstport")
        context.source_port, context.destination_port = source_port, destination_port
        raw_seq = reader.uint32("tcp.seq_raw")
        raw_ack = reader.uint32("tcp.ack_raw")

        offset = reader.buffer.offset
        word = reader.buffer.uint(2, name="tcp.flags")
        header_length = (word >> 12) * 4
        flags = word & 0x0FFF
        reader.add("tcp.hdr_len", header_length, offset=offset, length=1)
        if header_length < HEADER_SIZE:
            raise MalformedError(f"a header of {header_length} bytes is shorter than TCP's 20")
        self._flags(reader, flags, offset)

        window = reader.uint16("tcp.window_size_value")
        checksum = reader.uint16("tcp.checksum")
        status = self._status(context, whole, checksum)
        with reader.inside():
            reader.add("tcp.checksum.status", int(status))
        reader.uint16("tcp.urgent_pointer")

        conversations = context.session.store(self.name, lambda: Conversations(Connection))
        conversation, forward = conversations.find(
            (context.source or "", source_port), (context.destination or "", destination_port)
        )
        connection = conversation.state
        side = connection.forward if forward else connection.reverse
        other = connection.reverse if forward else connection.forward
        reader.add("tcp.stream", conversation.index)

        # Sequence numbers count from the start of this connection, as
        # Wireshark's do, which takes knowing where it started. It is worked
        # out before the options because a selective acknowledgement names
        # sequence numbers of the other direction.
        _remember_bases(side, other, flags, raw_seq, raw_ack)
        assert side.base_seq is not None
        notes = self._options(reader, header_length - HEADER_SIZE, side, other)
        payload_length = reader.remaining
        reader.add("tcp.len", payload_length, offset=reader.buffer.offset, length=0)

        sequence = (raw_seq - side.base_seq) & WORD
        reader.add("tcp.seq", sequence, offset=8, length=0)
        counted = payload_length + (1 if flags & (SYN | FIN) else 0)
        reader.add("tcp.nxtseq", sequence + counted, offset=reader.buffer.offset, length=0)
        acknowledged = 0
        if flags & ACK:
            base = other.base_seq if other.base_seq is not None else 0
            acknowledged = (raw_ack - base) & WORD
            reader.add("tcp.ack", acknowledged, offset=12, length=0)

        scaled = self._window(reader, window, side, flags)
        segment = Segment(
            frame=context.number,
            time=context.packet.timestamp_ns or 0,
            flags=flags,
            sequence=sequence,
            acknowledged=acknowledged,
            length=payload_length,
            window=window,
        )
        found = self._analyse(reader, connection, side, other, segment)

        summary = f"Transmission Control Protocol, Src Port: {source_port}, "
        summary += f"Dst Port: {destination_port}, Seq: {sequence}"
        summary += f", Ack: {acknowledged}" if flags & ACK else ""
        reader.summarize(f"{summary}, Len: {payload_length}")
        described = f"{source_port} → {destination_port} [{_named(flags)}] Seq={sequence}"
        described += f" Ack={acknowledged}" if flags & ACK else ""
        # The window as it means, not as it was written, which is what
        # Wireshark's packet list shows.
        described += f" Win={scaled} Len={payload_length}{notes}"
        context.describe(_markers(found, side) + described)
        if flags & SYN and not flags & ACK:
            connection.opened_forward = forward
        elif flags & SYN and connection.opened_forward is None:
            connection.opened_forward = not forward
        payload = reader.payload()
        data = payload.peek(payload.remaining)
        if data:
            reader.add("tcp.payload", data, offset=payload.offset, length=len(data))
        ports = (min(source_port, destination_port), max(source_port, destination_port))
        if context.in_error or context.truncated or status is ChecksumStatus.BAD:
            # None of these can join the stream: a segment quoted in an error
            # message isn't part of the connection, one the capture cut short
            # is missing bytes, and one that arrived damaged was thrown away
            # by whoever received it. Each is read for what it holds alone.
            if context.truncated and not context.in_error:
                side.flow.restart()
            if not payload.remaining:
                return None
            return Handoff(TCP_PORT, ports[0], payload, also=ports[1:], heuristics=HEURISTICS)
        listening = self._listening(context, conversation, forward)
        delivery = self._join(reader, context, side, other, segment, payload, data)
        if listening:
            # Somebody is following a stream of this capture, and wants its
            # bytes in order and nothing decoded from them.
            side.flow.take(len(side.flow.pending))
            return None
        offer = delivery.offer() if delivery is not None else None
        if offer is None:
            return None
        return Handoff(
            TCP_PORT, ports[0], offer, also=ports[1:], heuristics=HEURISTICS, stream=delivery
        )

    @staticmethod
    def _listening(context: Context, conversation: Conversation[Connection], forward: bool) -> bool:
        """Whether somebody is following a connection of this capture.

        The first packet of the connection they asked for is where they start
        listening to each of its directions.
        """
        if LISTENER not in context.session:
            return False
        listener = context.session.store(LISTENER, lambda: Listener(conversation.index))
        if listener.stream != conversation.index or listener.conversation is not None:
            return True
        listener.conversation = conversation
        source: Endpoint = (context.source or "", context.source_port)
        destination: Endpoint = (context.destination or "", context.destination_port)
        listener.responder = destination if forward else source
        heard = listener.heard
        state = conversation.state
        state.forward.flow.heard = lambda data, missed: heard.append(Heard(True, data, missed))
        state.reverse.flow.heard = lambda data, missed: heard.append(Heard(False, data, missed))
        return True

    @staticmethod
    def _join(
        reader: Reader,
        context: Context,
        side: Side,
        other: Side,
        segment: Segment,
        payload: Buffer,
        data: bytes,
    ) -> "Delivery | None":
        """Put the segment's bytes into its direction's stream.

        Returns the segment's turn at the stream when there is something in
        order to show the protocol on top, and ``None`` for a segment that
        brought nothing new or is waiting on a gap.
        """
        flow = side.flow
        if segment.flags & ACK and not segment.flags & RESET:
            # What this end has received settles what the capture is still
            # waiting to see from the other.
            other.flow.acknowledge(other.flow.position(segment.acknowledged))
        if segment.flags & SYN and (flow.next is None or segment.sequence):
            # A SYN starts the numbering, and takes the first number itself.
            # One that isn't where this connection began is the same ports
            # being used over again.
            flow.restart(segment.sequence + 1)
        closing = bool(segment.flags & (FIN | RESET))
        if not (segment.length or closing):
            return None
        position = flow.position(segment.sequence + (1 if segment.flags & SYN else 0))
        added = flow.add(position, data, segment.frame)
        if closing:
            flow.close(position + segment.length)
        delivery = Delivery(reader, context, flow, payload, data, position, added.seen)
        # The front of a segment can repeat what an earlier one brought.
        delivery.mark(0, min(added.seen, segment.length))
        if added.fresh or (closing and flow.ready):
            return delivery
        # Ahead of a gap, and kept until the bytes before it arrive.
        delivery.mark(added.seen, segment.length)
        return None

    @staticmethod
    def _flags(reader: Reader, flags: int, offset: int) -> None:
        reader.add("tcp.flags", flags, offset=offset, length=2)
        with reader.inside():
            reader.add("tcp.flags.res", (flags >> 9) & 0x7)
            reader.add("tcp.flags.ae", bool(flags & ACCURATE_ECN))
            reader.add("tcp.flags.cwr", bool(flags & CWR))
            reader.add("tcp.flags.ece", bool(flags & ECE))
            reader.add("tcp.flags.urg", bool(flags & URGENT))
            reader.add("tcp.flags.ack", bool(flags & ACK))
            reader.add("tcp.flags.push", bool(flags & PUSH))
            reader.add("tcp.flags.reset", bool(flags & RESET))
            reader.add("tcp.flags.syn", bool(flags & SYN))
            reader.add("tcp.flags.fin", bool(flags & FIN))
            letters = "".join(letter if flags & bit else _UNSET for bit, letter in _LETTERS)
            reader.add("tcp.flags.str", letters)

    @staticmethod
    def _status(context: Context, whole: bytes, checksum: int) -> ChecksumStatus:
        """Whether the checksum over the pseudo header and the segment adds up."""
        if context.truncated or context.source is None or context.destination is None:
            return ChecksumStatus.UNVERIFIED
        source, destination = context.source, context.destination
        pseudo = pseudo_header(source, destination, PROTO_TCP, len(whole))
        if verify(pseudo, whole) is ChecksumStatus.GOOD:
            # RFC 1624: a sum that comes to 0xffff is sent as zero, so a
            # segment carrying 0xffff was built wrongly however well it adds up.
            return ChecksumStatus.BAD if checksum == 0xFFFF else ChecksumStatus.GOOD
        # Windows leaves the length out of the sum it hands a card a large
        # segment with, so a segment on its way out can carry either form.
        without_length = pseudo_header(source, destination, PROTO_TCP, 0)
        if offloaded(pseudo, checksum) or offloaded(without_length, checksum):
            return ChecksumStatus.GOOD
        return ChecksumStatus.BAD

    @staticmethod
    def _window(reader: Reader, window: int, side: Side, flags: int) -> int:
        """The window, and what it means once the scaling from the handshake is
        known, which is the number the packet list shows."""
        if flags & SYN:
            # Scaling doesn't apply to the handshake itself.
            reader.add("tcp.window_size", window, offset=14, length=2)
            return window
        if side.window_scale is None:
            factor = SCALE_NOT_USED if side.saw_syn else SCALE_UNKNOWN
            reader.add("tcp.window_size_scalefactor", factor, offset=14, length=2)
            reader.add("tcp.window_size", window, offset=14, length=2)
            return window
        factor = 1 << side.window_scale
        reader.add("tcp.window_size_scalefactor", factor, offset=14, length=2)
        reader.add("tcp.window_size", window * factor, offset=14, length=2)
        return window * factor

    def _options(self, reader: Reader, count: int, side: Side, other: Side) -> str:
        """The options after the fixed header, which is where scaling is agreed.

        Returns what they add to the packet list, as Wireshark adds it: the
        sizes and shifts a handshake settles, and the timestamps that follow.
        """
        if count <= 0:
            return ""
        start = reader.buffer.offset
        reader.add("tcp.options", reader.buffer.peek(count), offset=start, length=count)
        end = start + count
        notes = ""
        while reader.buffer.offset < end:
            offset = reader.buffer.offset
            # Each option hangs under a field of its own, as it does in
            # Wireshark, so the kind and the length are read before they are
            # added to the tree: which option it is decides what they go under.
            kind = reader.buffer.uint(1, name="tcp.option_kind")
            if kind in {OPTION_END, OPTION_NOP}:
                # Padding to the next word boundary is more of these, and each
                # one of them is an option in its own right.
                name = "tcp.options.eol" if kind == OPTION_END else "tcp.options.nop"
                reader.add(name, bytes([kind]), offset=offset, length=1)
                with reader.inside():
                    reader.add("tcp.option_kind", kind, offset=offset, length=1)
                continue
            length = reader.buffer.uint(1, name="tcp.option_len")
            if length < 2:
                raise MalformedError(f"option {kind} claims a length of {length}")
            body = min(length - 2, max(end - reader.buffer.offset, 0))
            notes += self._option(reader, kind, offset, length, body, side, other)
        # An option that ran over the end of the list leaves the rest of it
        # unread, and what is left belongs to the header, not to the payload.
        reader.skip(max(end - reader.buffer.offset, 0), "tcp.options")
        return notes

    def _option(
        self,
        reader: Reader,
        kind: int,
        offset: int,
        length: int,
        body: int,
        side: Side,
        other: Side,
    ) -> str:
        """One option, by kind, with what it says hanging under it, and what it
        adds to the packet list.

        Anything unrecognised is stepped over: the kind and the length are all
        that can be said about it.
        """
        if kind == OPTION_MSS and body >= 2:
            self._named(reader, "tcp.options.mss", kind, offset, length, 2)
            with reader.inside():
                self._head(reader, kind, length, offset)
                size = reader.uint16("tcp.options.mss_val")
            return f" MSS={size}"
        if kind == OPTION_WINDOW_SCALE and body >= 1:
            self._named(reader, "tcp.options.wscale", kind, offset, length, 1)
            with reader.inside():
                self._head(reader, kind, length, offset)
                shift = min(reader.uint8("tcp.options.wscale.shift"), MAX_WINDOW_SCALE)
                reader.add("tcp.options.wscale.multiplier", 1 << shift)
            side.window_scale = shift
            return f" WS={1 << shift}"
        if kind == OPTION_SACK_PERMITTED:
            self._named(reader, "tcp.options.sack_perm", kind, offset, length, 0)
            with reader.inside():
                self._head(reader, kind, length, offset)
            return " SACK_PERM"
        if kind == OPTION_SACK and body % 8 == 0:
            self._named(reader, "tcp.options.sack", kind, offset, length, body)
            notes = ""
            with reader.inside():
                self._head(reader, kind, length, offset)
                reader.add("tcp.options.sack.count", body // 8)
                # The edges name what the other direction sent, so they count
                # from where that direction started, as an acknowledgement does.
                base = other.base_seq or 0
                for _ in range(body // 8):
                    for name, shown in (
                        ("tcp.options.sack_le", "SLE"),
                        ("tcp.options.sack_re", "SRE"),
                    ):
                        at = reader.buffer.offset
                        edge = (reader.buffer.uint(4, name=name) - base) & WORD
                        reader.add(name, edge, offset=at, length=4)
                        notes += f" {shown}={edge}"
            return notes
        if kind == OPTION_TIMESTAMPS and body >= 8:
            self._named(reader, "tcp.options.timestamp", kind, offset, length, 8)
            with reader.inside():
                self._head(reader, kind, length, offset)
                value = reader.uint32("tcp.options.timestamp.tsval")
                echo = reader.uint32("tcp.options.timestamp.tsecr")
            return f" TSval={value} TSecr={echo}"
        self._head(reader, kind, length, offset)
        reader.skip(body, "tcp.option")
        return ""

    @staticmethod
    def _named(reader: Reader, name: str, kind: int, offset: int, length: int, body: int) -> None:
        """The field the rest of an option hangs under, holding its bytes."""
        reader.add(
            name, bytes([kind, length]) + reader.buffer.peek(body), offset=offset, length=length
        )

    @staticmethod
    def _head(reader: Reader, kind: int, length: int, offset: int) -> None:
        """The kind and length every option but a one-byte one starts with."""
        reader.add("tcp.option_kind", kind, offset=offset, length=1)
        reader.add("tcp.option_len", length, offset=offset + 1, length=1)

    def _analyse(
        self, reader: Reader, connection: Connection, side: Side, other: Side, segment: Segment
    ) -> set[str]:
        """What the connection's history says about this segment.

        These checks, their order, and what each of them settles are
        Wireshark's ``tcp_analyze_sequence_number``, so that its verdicts and
        pilotfish's can be compared packet for packet.
        """
        found = self._judge(side, other, segment)
        if segment.acknowledged != side.last_ack:
            # An acknowledgement that moved is not a duplicate of the one
            # before it, so the count of duplicates starts again.
            side.duplicate_acks = 0
            side.last_non_duplicate_ack = segment.frame
        self._acknowledged_gap(side, other, segment, found)
        self._retransmission(connection, side, other, segment, found)
        acknowledged = self._remember(connection, side, other, segment, found)
        self._record(reader, connection, side, segment, found, acknowledged)
        return found

    @staticmethod
    def _judge(side: Side, other: Side, segment: Segment) -> set[str]:
        """What this segment is, from what the two sides have said so far.

        A zero window probe, a keep-alive acknowledgement and the answer to a
        probe each settle the matter on their own, so they return rather than
        letting a later check add to the verdict.
        """
        expected = side.next_seq
        quiet = not segment.flags & (SYN | FIN | RESET)
        if segment.length == 1 and segment.sequence == expected and other.window == 0:
            # One byte sent into a window with no room for it, to ask whether
            # the window has opened.
            return {"zero_window_probe"}

        found: set[str] = set()
        if segment.window == 0 and quiet:
            found.add("zero_window")
        if expected and segment.sequence > expected and not segment.flags & RESET:
            # Past what was expected, so what was in between wasn't captured.
            found.add("lost_segment")
        if segment.length <= 1 and expected and segment.sequence == expected - 1 and quiet:
            # A keep-alive holds nothing new and starts one byte early.
            found.add("keep_alive")

        repeats = (
            segment.length == 0
            and segment.sequence == expected
            and segment.acknowledged == side.last_ack
            and quiet
        )
        if repeats and segment.window and segment.window != side.window:
            found.add("window_update")
        if (
            segment.length
            and quiet
            and other.saw_syn
            and segment.sequence + segment.length == other.last_ack + _offered(other)
        ):
            # The data reaches the far edge of what the other end said it
            # could take, so the sender has to wait for a window update.
            found.add("window_full")

        if repeats and segment.window and segment.window == side.window:
            if "keep_alive" in other.last_flags:
                return found | {"keep_alive_ack"}
            side.duplicate_acks += 1
            found.add("duplicate_ack")
            return found
        if (
            segment.length == 0
            and segment.window == 0
            and side.window == 0
            and segment.sequence == expected
            and segment.acknowledged in (side.last_ack, side.last_ack + 1)
            and quiet
            and "zero_window_probe" in other.last_flags
        ):
            # The answer to a probe comes back with the window still shut. It
            # may acknowledge the byte the probe carried even so, in which
            # case that byte counts after all.
            if segment.acknowledged == side.last_ack + 1:
                other.next_seq = other.max_seq_to_be_acked = segment.acknowledged
            return found | {"zero_window_probe_ack"}
        return found

    @staticmethod
    def _acknowledged_gap(side: Side, other: Side, segment: Segment, found: set[str]) -> None:
        """Whether this acknowledges something that was never captured."""
        if not (
            segment.flags & ACK
            and other.max_seq_to_be_acked
            and segment.acknowledged > other.max_seq_to_be_acked
        ):
            return
        if (
            segment.acknowledged == side.last_ack + 1
            and segment.sequence == side.next_seq
            and "zero_window_probe" in other.last_flags
        ):
            # An ordinary acknowledgement opening the window again, taking the
            # byte a probe carried with it.
            other.next_seq = other.max_seq_to_be_acked = segment.acknowledged
            found.add("window_update")
            return
        # Move the boundary past the whole run of segments above what is being
        # acknowledged, so the same missing segment isn't reported again for
        # each of the ones that follow it.
        other.max_seq_to_be_acked = _reach_above(other, segment.acknowledged)
        found.add("ack_lost_segment")

    @staticmethod
    def _retransmission(
        connection: Connection, side: Side, other: Side, segment: Segment, found: set[str]
    ) -> None:
        """Which kind of resend a segment that doesn't advance the sequence
        number is, which is the one judgement with a clock in it."""
        if not (segment.length or segment.flags & (SYN | FIN)) or "keep_alive" in found:
            return
        behind = bool(side.next_seq) and segment.sequence < side.next_seq
        if segment.length > 1 and segment.sequence == side.next_seq - 1:
            # More than the one byte a probe carries, so it really is new data
            # even though it starts where a probe would have.
            behind = False
        end = segment.sequence + segment.length
        if segment.length and other.last_ack and end <= other.last_ack:
            # Sending data the other end acknowledged long ago was pointless.
            found.add("spurious_retransmission")
            return
        if not behind:
            return
        # The clock runs from the other end's last acknowledgement, which is
        # what a sender would have been reacting to.
        since_ack = max(segment.time - other.last_ack_time, 0)
        if (
            since_ack < FAST_RETRANSMISSION_NS
            and other.duplicate_acks >= DUPLICATE_ACKS_BEFORE_FAST
            and other.last_ack == segment.sequence
        ):
            # The other end asked for this segment twice over, and the sender
            # didn't wait for a timeout to send it.
            found.add("fast_retransmission")
            return
        soon = connection.initial_rtt or OUT_OF_ORDER_WINDOW_NS
        already_sent = any(
            sent.sequence <= segment.sequence and end <= sent.end for sent in side.sent
        )
        counted = segment.length + (1 if segment.flags & (SYN | FIN) else 0)
        # Soon enough to be the network delivering a segment late rather than
        # the sender sending it again, as long as it isn't simply the one
        # already at the front, or the only thing since was an acknowledgement
        # carrying no data.
        if (
            since_ack < soon
            and not already_sent
            and (side.next_seq != segment.sequence + counted or side.last_length == 0)
        ):
            found.add("out_of_order")
            return
        found.add("retransmission")

    @staticmethod
    def _remember(
        connection: Connection, side: Side, other: Side, segment: Segment, found: set[str]
    ) -> Sent | None:
        """Keep what the segments after this one will be judged against, and
        say which segment this one acknowledges."""
        counted = segment.length + (1 if segment.flags & (SYN | FIN) else 0)
        end = segment.sequence + counted
        if segment.length or segment.flags & (SYN | FIN):
            side.sent.insert(0, Sent(segment.sequence, end, segment.frame, segment.time))
        if not side.next_seq or end > side.next_seq + (1 if segment.flags & (SYN | FIN) else 0):
            side.last_length = segment.length
        # A probe carries a byte the window has no room for, so it doesn't
        # move what comes next.
        probe = "zero_window_probe" in found
        if (not side.next_seq or end > side.next_seq) and not probe:
            side.next_seq = end
            side.next_seq_time = segment.time
        # How far this side reaches without a gap only moves on from where it
        # already was, so a segment landing past a hole doesn't carry it along.
        if (not side.max_seq_to_be_acked or segment.sequence == side.max_seq_to_be_acked) and (
            not probe
        ):
            side.max_seq_to_be_acked = side.next_seq
        side.window = segment.window
        side.last_ack = segment.acknowledged
        side.last_ack_time = segment.time
        side.last_flags = frozenset(found)
        if segment.flags & SYN:
            side.scale_pending = True
            if not segment.flags & ACK:
                connection.syn_time = segment.time
        elif segment.flags & ACK:
            if connection.syn_time is not None and connection.initial_rtt is None:
                connection.initial_rtt = segment.time - connection.syn_time
            side.scale_pending = False
        return _acknowledge(other, segment)

    @staticmethod
    def _record(
        reader: Reader,
        connection: Connection,
        side: Side,
        segment: Segment,
        found: set[str],
        acknowledged: Sent | None,
    ) -> None:
        """Add a field for each judgement, and for what the segment acknowledges."""
        if acknowledged is not None:
            reader.add("tcp.analysis.acks_frame", acknowledged.frame)
            if segment.time != acknowledged.time:
                reader.add("tcp.analysis.ack_rtt", segment.time - acknowledged.time)
        if connection.initial_rtt is not None:
            # Wireshark only shows the handshake's round trip on the packets it
            # has something else to say about. It belongs to the whole
            # connection, so pilotfish shows it on every segment of it.
            reader.add("tcp.analysis.initial_rtt", connection.initial_rtt)
        for name in sorted(found):
            reader.add(f"tcp.analysis.{name}", True)
        if found & {"fast_retransmission", "spurious_retransmission"}:
            # Wireshark reports both of these as retransmissions as well.
            reader.add("tcp.analysis.retransmission", True)
        if "duplicate_ack" in found:
            reader.add("tcp.analysis.duplicate_ack_num", side.duplicate_acks)
            if side.last_non_duplicate_ack:
                reader.add("tcp.analysis.duplicate_ack_frame", side.last_non_duplicate_ack)


class Delivery(Stream):
    """One segment's turn at its stream.

    The segment's bytes have joined the stream by the time this exists. What
    is left is to offer the protocol on top whatever is now in order, as many
    messages as that turns out to hold, and to say which of the segment's own
    bytes ended up decoded somewhere other than in this packet.

    What gets offered is the segment's own bytes when the message at the front
    starts in this segment, so its fields point into the packet as usual.
    When the message started in an earlier packet, the bytes offered are the
    reassembled ones, and the segments they came from are listed.
    """

    def __init__(
        self,
        reader: Reader,
        context: Context,
        flow: Flow,
        payload: Buffer,
        data: bytes,
        position: int,
        seen: int,
    ) -> None:
        self._reader = reader
        self._context = context
        self._flow = flow
        self._frame = context.number
        self._data = data
        self._offset = payload.offset
        self._origin = payload.source
        self._position = position
        """Where the segment's first byte belongs in the stream."""
        self._seen = seen
        """How many of its leading bytes an earlier segment had brought."""
        self._whole: Source | None = None
        """The reassembled bytes on offer, when the offer isn't the segment's own."""
        self._frames: tuple[int, ...] = ()
        self._inside = (0, 0)
        """Which of the segment's bytes are among them."""
        self._used = 0
        self._decoded = False

    @property
    def open(self) -> bool:
        return self._flow.open

    def offer(self) -> Buffer | None:
        """The bytes at the front of the stream, if they are worth decoding."""
        flow = self._flow
        if not flow.ready:
            self.wait()
            return None
        size = len(flow.pending)
        if len(flow.pieces) == 1 and flow.pieces[0].frame == self._frame:
            # Everything waiting came in this segment, and is the end of it.
            self._whole = None
            start = len(self._data) - size
            return Buffer(memoryview(self._data)[start:], self._offset + start, self._origin)
        # Just the message that was being waited for, when its length is
        # known and everything after it came in this segment, so that what
        # follows can be read from the packet itself.
        extent, last = size, flow.pieces[-1]
        if flow.exact and last.frame == self._frame and size - last.length <= flow.wanted <= size:
            extent = flow.wanted
        whole = bytes(flow.pending[:extent])
        self._whole = Source("Reassembled TCP", whole)
        self._used = 0
        self._frames = _frames(flow, extent)
        if flow.to_end and self._frame not in self._frames:
            # A message that ran to the end of the stream was finished by the
            # segment that closed it, which Wireshark counts as one of its
            # segments even when it carried nothing.
            self._frames += (self._frame,)
        mine = self._position + self._seen
        end = self._position + len(self._data)
        self._inside = (
            max(flow.start, mine) - self._position,
            min(flow.start + extent, end) - self._position,
        )
        return Buffer(whole, 0, self._whole)

    def taken(self, count: int) -> Buffer | None:
        whole = self._whole
        if whole is not None and not self._used:
            # The first message out of reassembled bytes says where they
            # came from.
            for frame in self._frames:
                self._reader.add("tcp.segment", frame)
            self._reader.add("tcp.segment.count", len(self._frames))
            self._reader.add("tcp.reassembled.length", len(whole.data))
            self._reader.add("tcp.reassembled.data", whole.data)
        self._flow.take(count)
        self._decoded = True
        if whole is not None:
            self._used += count
            if self._used < len(whole.data):
                return Buffer(memoryview(whole.data)[self._used :], self._used, whole)
            self.mark(*self._inside)
            self._whole = None
        return self.offer() if self._flow.pending else None

    def held(self, more: NeedMoreError) -> Buffer | None:
        flow = self._flow
        shown = len(flow.pending)
        if self._whole is not None:
            shown = len(self._whole.data) - self._used
        flow.wait(more.count, to_end=more.to_end, have=shown)
        if not flow.ready:
            self.wait()
            return None
        # Either the bytes it wants are here already, behind the ones it was
        # shown, or the stream has no way of getting it any more.
        if self._whole is not None and self._used:
            self.mark(*self._inside)
        return self.offer()

    def wait(self) -> None:
        """Leave what the segment brought for the packet that completes it."""
        low = max(self._flow.start - self._position, self._seen)
        if self._whole is not None and self._used:
            low = self._inside[0]
        if low >= len(self._data):
            return
        self.mark(low, len(self._data))
        if not self._decoded:
            self._context.info += WAITING

    def mark(self, low: int, high: int) -> None:
        """Record bytes of the segment that weren't decoded as part of it.

        They belong to a message that another packet completes, or were
        brought by an earlier segment already.
        """
        if low < high:
            self._reader.add(
                "tcp.segment_data",
                self._data[low:high],
                offset=self._offset + low,
                length=high - low,
            )


def _frames(flow: Flow, extent: int) -> tuple[int, ...]:
    """The packets the first ``extent`` waiting bytes arrived in."""
    frames: dict[int, None] = {}
    for piece in flow.pieces:
        if extent <= 0:
            break
        frames[piece.frame] = None
        extent -= piece.length
    return tuple(frames)


def _offered(side: Side) -> int:
    """The window this side last advertised, scaled if it said how.

    Scaling is agreed in the handshake but only takes effect once it is over,
    so the window in a SYN and in the acknowledgement that answers it mean
    exactly what they say.
    """
    if side.window_scale is None or side.scale_pending:
        return side.window
    return side.window << side.window_scale


def _reach_above(side: Side, acknowledged: int) -> int:
    """How far this side's unacknowledged segments reach above an
    acknowledgement, if they run on from it without a gap."""
    left = right = 0
    for sent in side.sent:
        if left == right:
            left, right = sent.sequence, sent.end
        if sent.sequence >= acknowledged:
            if sent.end == left:
                left = sent.sequence
            else:
                left, right = sent.sequence, sent.end
    return right if acknowledged == left and right > acknowledged else acknowledged


def _acknowledge(side: Side, segment: Segment) -> Sent | None:
    """Drop the segments this one acknowledges, and return the oldest one it
    acknowledges exactly, which is what the round trip is measured from."""
    if not segment.flags & ACK:
        return None
    acknowledged: Sent | None = None
    outstanding: list[Sent] = []
    for sent in side.sent:
        if segment.acknowledged == sent.end:
            acknowledged = sent
        elif sent.sequence < segment.acknowledged < sent.end:
            # Part of a segment, which happens when a sender repackages what
            # it has already sent. The rest of it is still outstanding.
            acknowledged = sent
            outstanding.append(Sent(segment.acknowledged, sent.end, sent.frame, sent.time))
        elif sent.end > segment.acknowledged:
            outstanding.append(sent)
    side.sent = outstanding
    return acknowledged


_MARKERS = (
    # What Wireshark puts in front of the Info column, in the order it writes
    # them, which is the reverse of the order it adds them in.
    ("zero_window_probe_ack", "[TCP ZeroWindowProbeAck] "),
    ("zero_window", "[TCP ZeroWindow] "),
    ("zero_window_probe", "[TCP ZeroWindowProbe] "),
    ("duplicate_ack", ""),
    ("keep_alive_ack", "[TCP Keep-Alive ACK] "),
    ("keep_alive", "[TCP Keep-Alive] "),
    ("window_full", "[TCP Window Full] "),
    ("window_update", "[TCP Window Update] "),
    ("ack_lost_segment", "[TCP ACKed unseen segment] "),
    ("lost_segment", "[TCP Previous segment not captured] "),
    ("out_of_order", "[TCP Out-Of-Order] "),
    ("spurious_retransmission", "[TCP Spurious Retransmission] "),
    ("fast_retransmission", "[TCP Fast Retransmission] "),
    ("retransmission", "[TCP Retransmission] "),
)


def _markers(found: set[str], side: Side) -> str:
    """What the packet list says in front of a segment the analysis judged."""
    notes = []
    for name, text in _MARKERS:
        if name not in found:
            continue
        if name == "duplicate_ack":
            # This one counts: the acknowledgement it repeats, and how often.
            notes.append(f"[TCP Dup ACK {side.last_non_duplicate_ack}#{side.duplicate_acks}] ")
        else:
            notes.append(text)
    return "".join(notes)


def _named(flags: int) -> str:
    """The flags as tshark writes them in the Info column: ``SYN, ACK``."""
    names = (
        (FIN, "FIN"),
        (SYN, "SYN"),
        (RESET, "RST"),
        (PUSH, "PSH"),
        (ACK, "ACK"),
        (URGENT, "URG"),
        (ECE, "ECE"),
        (CWR, "CWR"),
    )
    return ", ".join(name for bit, name in names if flags & bit)


def _remember_bases(side: Side, other: Side, flags: int, raw_seq: int, raw_ack: int) -> None:
    """Where each direction's sequence numbers are counted from.

    A connection whose handshake was captured counts from the number in the
    SYN. One joined halfway counts from the first segment seen, which is why
    its first segment is sequence 1 rather than 0. The other direction's start
    comes from what this segment acknowledges.
    """
    if side.base_seq is None:
        side.base_seq = raw_seq if flags & SYN else (raw_seq - 1) & WORD
        side.saw_syn = bool(flags & SYN)
    if other.base_seq is None and flags & ACK:
        other.base_seq = (raw_ack - 1) & WORD
