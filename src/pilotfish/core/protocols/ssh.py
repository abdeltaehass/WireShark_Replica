"""SSH: the greeting, the algorithms each end offers, and then silence.

A session opens in plain text — each end announces its software version on a
line of its own — and continues in a binary packet format whose messages are
readable only until the two agree a key. What a capture can tell you is
therefore the versions, the algorithms each end supports, and afterwards the
size and direction of packets whose contents are gone.

That short readable part is worth more than it looks: the exact list of
algorithms a client offers is a habit of the software that built it, which
is what the HASSH fingerprint below turns into one short string.

Reference: RFC 4253 for the protocol, and the HASSH method by Ben Reardon and
Adel Karimi.
"""

from dataclasses import dataclass, field
from hashlib import md5

from pilotfish.core.dissect import (
    Buffer,
    Context,
    DeclinedError,
    Dissector,
    Field,
    FieldType,
    Reader,
    heuristic,
    register,
)
from pilotfish.core.protocols.conversations import Conversations
from pilotfish.core.protocols.tcp import HEURISTICS, TCP_PORT

PORT = 22

GREETING = b"SSH-"
MAX_PACKET = 35000
"""What RFC 4253 says an implementation must accept, and a sanity check here."""

KEX_INIT = 20
NEW_KEYS = 21

MESSAGES = {
    1: "Disconnect",
    2: "Ignore",
    3: "Unimplemented",
    4: "Debug",
    5: "Service Request",
    6: "Service Accept",
    7: "Extension Information",
    KEX_INIT: "Key Exchange Init",
    NEW_KEYS: "New Keys",
    30: "Diffie-Hellman Key Exchange Init",
    31: "Diffie-Hellman Key Exchange Reply",
    50: "User Authentication Request",
    51: "User Authentication Failure",
    52: "User Authentication Success",
    53: "User Authentication Banner",
    80: "Global Request",
    90: "Channel Open",
    91: "Channel Open Confirmation",
    93: "Window Adjust",
    94: "Channel Data",
    96: "Channel EOF",
    97: "Channel Close",
    98: "Channel Request",
}

# The ten lists a key exchange init carries, in the order they are sent.
LISTS = (
    "kex_algorithms",
    "server_host_key_algorithms",
    "encryption_algorithms_client_to_server",
    "encryption_algorithms_server_to_client",
    "mac_algorithms_client_to_server",
    "mac_algorithms_server_to_client",
    "compression_algorithms_client_to_server",
    "compression_algorithms_server_to_client",
    "languages_client_to_server",
    "languages_server_to_client",
)

# What HASSH is taken over: the client's half, and the server's.
HASSH_CLIENT = (
    "kex_algorithms",
    "encryption_algorithms_client_to_server",
    "mac_algorithms_client_to_server",
    "compression_algorithms_client_to_server",
)
HASSH_SERVER = (
    "kex_algorithms",
    "encryption_algorithms_server_to_client",
    "mac_algorithms_server_to_client",
    "compression_algorithms_server_to_client",
)


@dataclass(slots=True)
class Side:
    """One direction of a session: how far in, and whether it can still be read."""

    packets: int = 0
    encrypted: bool = False


@dataclass(slots=True)
class Session:
    forward: Side = field(default_factory=Side)
    reverse: Side = field(default_factory=Side)


@dataclass(slots=True)
class Sessions:
    conversations: Conversations[Session] = field(default_factory=lambda: Conversations(Session))


@heuristic(HEURISTICS)
@register(TCP_PORT, PORT)
class Ssh(Dissector):
    name = "ssh"
    title = "SSH Protocol"
    fields = (
        Field("ssh.protocol", FieldType.STRING, "Protocol"),
        Field("ssh.direction", FieldType.UINT, "Direction"),
        Field("ssh.seq_num", FieldType.UINT, "Sequence number"),
        Field("ssh.packet_length", FieldType.UINT, "Packet Length"),
        Field("ssh.packet_length_encrypted", FieldType.BYTES, "Packet Length (encrypted)"),
        Field("ssh.padding_length", FieldType.UINT, "Padding Length"),
        Field("ssh.message_code", FieldType.UINT, "Message Code"),
        Field("ssh.cookie", FieldType.BYTES, "Cookie"),
        Field("ssh.first_kex_packet_follows", FieldType.UINT, "First KEX Packet Follows"),
        Field("ssh.kex.reserved", FieldType.BYTES, "Reserved"),
        Field("ssh.padding_string", FieldType.BYTES, "Padding String"),
        Field("ssh.encrypted_packet", FieldType.BYTES, "Encrypted Packet"),
        Field("ssh.kex.hassh_algorithms", FieldType.STRING, "hassh algorithms"),
        Field("ssh.kex.hassh", FieldType.STRING, "hassh"),
        Field("ssh.kex.hasshserver_algorithms", FieldType.STRING, "hasshServer algorithms"),
        Field("ssh.kex.hasshserver", FieldType.STRING, "hasshServer"),
        *(
            field
            for name in LISTS
            for field in (
                Field(f"ssh.{name}_length", FieldType.UINT, f"{name} length"),
                Field(f"ssh.{name}", FieldType.STRING, name),
            )
        ),
    )

    def dissect(self, reader: Reader, context: Context) -> None:
        if not self.looks_like(reader.buffer, context):
            raise DeclinedError
        sessions = context.session.store(self.name, Sessions)
        conversation, forward = sessions.conversations.find(
            (str(context.source or ""), context.source_port),
            (str(context.destination or ""), context.destination_port),
        )
        state = conversation.state
        side = state.forward if forward else state.reverse
        client = context.destination_port == PORT or forward
        reader.add("ssh.direction", 0 if client else 1)

        notes = []
        while reader.remaining:
            note = self._packet(reader, side, client)
            if note is None:
                break
            notes.append(note)
        reader.summarize(self.title)
        context.describe(f"{'Client' if client else 'Server'}: {', '.join(notes)}")
        return None

    def _packet(self, reader: Reader, side: Side, client: bool) -> str | None:
        """One thing on the wire: a greeting line, or a binary packet."""
        start = bytes(reader.buffer.peek(min(reader.remaining, 4)))
        if start.startswith(GREETING):
            return self._greeting(reader)
        if reader.remaining < 6:
            return None
        if side.encrypted:
            return self._encrypted(reader)
        length = int.from_bytes(start, "big")
        if not 0 < length <= min(MAX_PACKET, reader.remaining - 4):
            # The rest of a packet that started in an earlier segment, which
            # takes reassembly to read: the next phase.
            return self._encrypted(reader)
        reader.uint32("ssh.packet_length")
        padding = reader.uint8("ssh.padding_length")
        body = reader.payload(length - 1)
        reader.add("ssh.seq_num", side.packets)
        side.packets += 1
        code = body.uint(1)
        reader.add("ssh.message_code", code, offset=body.offset - 1, length=1)
        if code == KEX_INIT:
            self._kex_init(reader, body, client)
        if code == NEW_KEYS:
            # Everything this side sends from here on is encrypted.
            side.encrypted = True
        if padding and body.remaining >= padding:
            offset = body.offset + body.remaining - padding
            reader.add(
                "ssh.padding_string",
                body.peek(body.remaining)[-padding:],
                offset=offset,
                length=padding,
            )
        return MESSAGES.get(code, f"Unknown ({code})")

    @staticmethod
    def _greeting(reader: Reader) -> str:
        """The line each end opens with, naming what it is."""
        rest = bytes(reader.buffer.peek(reader.remaining))
        line, _, _ = rest.partition(b"\r\n")
        text = line.decode("latin-1")
        offset = reader.buffer.offset
        reader.skip(min(len(line) + 2, reader.remaining), "ssh.protocol")
        reader.add("ssh.protocol", text, offset=offset, length=len(line))
        return f"Protocol ({text})"

    @staticmethod
    def _encrypted(reader: Reader) -> str:
        """A packet whose contents went away with the keys."""
        length = reader.remaining
        offset = reader.buffer.offset
        if length >= 4:
            reader.bytes("ssh.packet_length_encrypted", 4)
        reader.add(
            "ssh.encrypted_packet",
            reader.buffer.peek(reader.remaining),
            offset=offset + 4,
            length=reader.remaining,
        )
        reader.skip(reader.remaining, "ssh.encrypted_packet")
        return f"Encrypted packet (len={length})"

    def _kex_init(self, reader: Reader, body: Buffer, client: bool) -> None:
        """What each end is willing to use, in ten lists of names."""
        if body.remaining < 16:
            return
        offset = body.offset
        reader.add("ssh.cookie", bytes(body.read(16)), offset=offset, length=16)
        offered: dict[str, str] = {}
        for name in LISTS:
            if body.remaining < 4:
                return
            offset = body.offset
            length = body.uint(4)
            reader.add(f"ssh.{name}_length", length, offset=offset, length=4)
            names = bytes(body.read(min(length, body.remaining))).decode("ascii", "replace")
            reader.add(f"ssh.{name}", names, offset=offset + 4, length=len(names))
            offered[name] = names
        if body.remaining >= 1:
            offset = body.offset
            reader.add("ssh.first_kex_packet_follows", body.uint(1), offset=offset, length=1)
        if body.remaining >= 4:
            offset = body.offset
            reader.add("ssh.kex.reserved", bytes(body.read(4)), offset=offset, length=4)
        self._hassh(reader, offered, client)

    @staticmethod
    def _hassh(reader: Reader, offered: dict[str, str], client: bool) -> None:
        """What this end's offer looks like, as one line and as a digest of it."""
        wanted = HASSH_CLIENT if client else HASSH_SERVER
        text = ";".join(offered.get(name, "") for name in wanted)
        prefix = "hassh" if client else "hasshserver"
        reader.add(f"ssh.kex.{prefix}_algorithms", text)
        reader.add(f"ssh.kex.{prefix}", md5(text.encode(), usedforsecurity=False).hexdigest())

    def looks_like(self, payload: Buffer, context: Context) -> bool:
        """Whether a payload starts a greeting or a plausible binary packet."""
        if payload.remaining < 6:
            return False
        start = bytes(payload.peek(min(payload.remaining, 8)))
        if start.startswith(GREETING):
            return True
        length = int.from_bytes(start[:4], "big")
        padding = start[4]
        return (
            context.source_port == PORT
            or context.destination_port == PORT
            or (0 < length <= MAX_PACKET and 4 <= padding < 64)
        )
