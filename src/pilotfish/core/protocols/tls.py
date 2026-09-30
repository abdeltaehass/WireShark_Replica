"""TLS: the record layer, and the handshake that happens in the clear.

Everything after the handshake is encrypted, so what a capture can tell you
about a TLS connection is what the two ends say before the keys exist: which
versions and ciphers each will accept, and, in the ClientHello, the name of
the server being asked for. That name is the reason this dissector earns its
place — it is the last plainly readable thing in a modern web request.

A record may hold several handshake messages, a message may be split across
records and a record across TCP segments. The last of those needs reassembly,
which is the next phase; the first two are handled here.

References: RFC 8446 for TLS 1.3, RFC 5246 for 1.2, RFC 6066 for the server
name extension and RFC 7301 for ALPN.
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

PORTS = (443, 465, 563, 636, 989, 990, 992, 993, 995, 5061, 8443)
"""The ports that carry TLS without anyone having to say so."""

CHANGE_CIPHER_SPEC = 20
ALERT = 21
HANDSHAKE = 22
APPLICATION_DATA = 23

CONTENT_TYPES = {
    CHANGE_CIPHER_SPEC: "Change Cipher Spec",
    ALERT: "Alert",
    HANDSHAKE: "Handshake",
    APPLICATION_DATA: "Application Data",
}

CLIENT_HELLO = 1
SERVER_HELLO = 2
CERTIFICATE = 11

HANDSHAKES = {
    0: "Hello Request",
    CLIENT_HELLO: "Client Hello",
    SERVER_HELLO: "Server Hello",
    3: "Hello Verify Request",
    4: "New Session Ticket",
    5: "End of Early Data",
    8: "Encrypted Extensions",
    CERTIFICATE: "Certificate",
    12: "Server Key Exchange",
    13: "Certificate Request",
    14: "Server Hello Done",
    15: "Certificate Verify",
    16: "Client Key Exchange",
    20: "Finished",
    24: "Key Update",
}

SERVER_NAME = 0
SUPPORTED_GROUPS = 10
EC_POINT_FORMATS = 11
SIGNATURE_ALGORITHMS = 13
ALPN = 16
SUPPORTED_VERSIONS = 43
KEY_SHARE = 51

TLS13 = 0x0304

ALERT_LEVELS = {1: "Warning", 2: "Fatal"}
ALERT_DESCRIPTIONS = {
    0: "Close Notify",
    10: "Unexpected Message",
    20: "Bad Record MAC",
    40: "Handshake Failure",
    42: "Bad Certificate",
    46: "Certificate Unknown",
    47: "Illegal Parameter",
    48: "Unknown CA",
    50: "Decode Error",
    51: "Decrypt Error",
    70: "Protocol Version",
    80: "Internal Error",
    112: "Unrecognized Name",
}


@dataclass(slots=True)
class Fingerprint:
    """The pieces of a hello that JA3 turns into one short string.

    Fingerprinting a client by what it offers, rather than by what it claims
    to be, is how a piece of software is recognised through TLS: the list of
    ciphers and extensions is a habit of the library that built the hello,
    and it doesn't change between connections.

    Reference: the JA3 method, by John Althouse, Jeff Atkinson and Josh Atkins.
    """

    version: int = 0
    ciphers: list[int] = field(default_factory=list)
    extensions: list[int] = field(default_factory=list)
    groups: list[int] = field(default_factory=list)
    formats: list[int] = field(default_factory=list)

    def text(self, client: bool) -> str:
        """The string the fingerprint is taken over."""
        pieces = [
            str(self.version),
            "-".join(str(each) for each in self.ciphers),
            "-".join(str(each) for each in self.extensions),
        ]
        if client:
            pieces.append("-".join(str(each) for each in self.groups))
            pieces.append("-".join(str(each) for each in self.formats))
        return ",".join(pieces)


def is_grease(value: int) -> bool:
    """Whether a number is one of the values reserved to keep TLS flexible.

    A client throws these into its lists so that a server which chokes on
    anything it doesn't know is found out early. They mean nothing, so a
    fingerprint leaves them out.

    Reference: RFC 8701.
    """
    return value & 0x0F0F == 0x0A0A and value >> 8 == value & 0xFF


@dataclass(slots=True)
class Connection:
    """What a connection has agreed, which changes how its records read."""

    version: int = 0
    """The version its ServerHello settled on, once it has."""


@dataclass(slots=True)
class Streams:
    """The TLS connections of one capture, numbered as they are met."""

    conversations: Conversations[Connection] = field(
        default_factory=lambda: Conversations(Connection)
    )


@heuristic(HEURISTICS)
@register(TCP_PORT, *PORTS)
class Tls(Dissector):
    name = "tls"
    title = "Transport Layer Security"
    fields = (
        Field("tls.stream", FieldType.UINT, "Stream index"),
        Field("tls.record.content_type", FieldType.UINT, "Content Type"),
        Field("tls.record.opaque_type", FieldType.UINT, "Opaque Type"),
        Field("tls.record.version", FieldType.UINT, "Version", hex=True),
        Field("tls.record.length", FieldType.UINT, "Length"),
        Field("tls.app_data", FieldType.BYTES, "Encrypted Application Data"),
        Field("tls.change_cipher_spec", FieldType.BOOL, "Change Cipher Spec Message"),
        Field("tls.alert_message.level", FieldType.UINT, "Level"),
        Field("tls.alert_message.desc", FieldType.UINT, "Description"),
        Field("tls.handshake.type", FieldType.UINT, "Handshake Type"),
        Field("tls.handshake.length", FieldType.UINT, "Length"),
        Field("tls.handshake.version", FieldType.UINT, "Version", hex=True),
        Field("tls.handshake.random", FieldType.BYTES, "Random"),
        Field("tls.handshake.random_time", FieldType.TIME, "GMT Unix Time"),
        Field("tls.handshake.random_bytes", FieldType.BYTES, "Random Bytes"),
        Field("tls.handshake.session_id_length", FieldType.UINT, "Session ID Length"),
        Field("tls.handshake.session_id", FieldType.BYTES, "Session ID"),
        Field("tls.handshake.cipher_suites_length", FieldType.UINT, "Cipher Suites Length"),
        Field("tls.handshake.ciphersuite", FieldType.UINT, "Cipher Suite", hex=True),
        Field("tls.handshake.comp_methods_length", FieldType.UINT, "Compression Methods Length"),
        Field("tls.handshake.comp_method", FieldType.UINT, "Compression Method"),
        Field("tls.handshake.extensions_length", FieldType.UINT, "Extensions Length"),
        Field("tls.handshake.extension.type", FieldType.UINT, "Type"),
        Field("tls.handshake.extension.len", FieldType.UINT, "Length"),
        Field("tls.handshake.extension.data", FieldType.BYTES, "Data"),
        Field(
            "tls.handshake.extensions_server_name_list_len",
            FieldType.UINT,
            "Server Name list length",
        ),
        Field("tls.handshake.extensions_server_name_type", FieldType.UINT, "Server Name Type"),
        Field("tls.handshake.extensions_server_name_len", FieldType.UINT, "Server Name length"),
        Field("tls.handshake.extensions_server_name", FieldType.STRING, "Server Name"),
        Field("tls.handshake.extensions_alpn_len", FieldType.UINT, "ALPN Extension Length"),
        Field("tls.handshake.extensions_alpn_str_len", FieldType.UINT, "ALPN string length"),
        Field("tls.handshake.extensions_alpn_str", FieldType.STRING, "ALPN Next Protocol"),
        Field(
            "tls.handshake.extensions.supported_versions_len",
            FieldType.UINT,
            "Supported Versions length",
        ),
        Field(
            "tls.handshake.extensions.supported_version",
            FieldType.UINT,
            "Supported Version",
            hex=True,
        ),
        Field(
            "tls.handshake.extensions_supported_groups_length",
            FieldType.UINT,
            "Supported Groups List Length",
        ),
        Field(
            "tls.handshake.extensions_supported_group",
            FieldType.UINT,
            "Supported Group",
            hex=True,
        ),
        Field(
            "tls.handshake.extensions_ec_point_formats_length",
            FieldType.UINT,
            "EC point formats Length",
        ),
        Field("tls.handshake.extensions_ec_point_format", FieldType.UINT, "EC point format"),
        Field("tls.handshake.sig_hash_alg_len", FieldType.UINT, "Signature Hash Algorithms Length"),
        Field("tls.handshake.sig_hash_alg", FieldType.UINT, "Signature Algorithm", hex=True),
        Field("tls.handshake.sig_hash_hash", FieldType.UINT, "Signature Hash Algorithm Hash"),
        Field("tls.handshake.sig_hash_sig", FieldType.UINT, "Signature Hash Algorithm Signature"),
        Field(
            "tls.handshake.extensions_key_share_client_length",
            FieldType.UINT,
            "Client Key Share Length",
        ),
        Field("tls.handshake.extensions_key_share_group", FieldType.UINT, "Group"),
        Field(
            "tls.handshake.extensions_key_share_key_exchange_length",
            FieldType.UINT,
            "Key Exchange Length",
        ),
        Field("tls.handshake.extensions_key_share_key_exchange", FieldType.BYTES, "Key Exchange"),
        Field("tls.handshake.certificates_length", FieldType.UINT, "Certificates Length"),
        Field("tls.handshake.certificate_length", FieldType.UINT, "Certificate Length"),
        Field("tls.handshake.certificate", FieldType.BYTES, "Certificate"),
        Field("tls.segment.data", FieldType.BYTES, "TLS segment data"),
        Field("tls.handshake.ja3_full", FieldType.STRING, "JA3 Fullstring"),
        Field("tls.handshake.ja3", FieldType.STRING, "JA3"),
        Field("tls.handshake.ja3s_full", FieldType.STRING, "JA3S Fullstring"),
        Field("tls.handshake.ja3s", FieldType.STRING, "JA3S"),
    )

    def dissect(self, reader: Reader, context: Context) -> None:
        if not self.looks_like(reader.buffer, context):
            # The rest of a record that started in an earlier packet, which
            # takes reassembly to read: the next phase.
            raise DeclinedError
        connection = self._connection(reader, context)
        notes: list[str] = []
        while reader.remaining >= 5:
            notes.extend(self._record(reader, connection))
        reader.summarize(self.title)
        context.describe(", ".join(notes))
        return None

    def _connection(self, reader: Reader, context: Context) -> Connection:
        """Which connection this is, and what it has agreed so far."""
        streams = context.session.store(self.name, Streams)
        conversation, _ = streams.conversations.find(
            (str(context.source or ""), context.source_port),
            (str(context.destination or ""), context.destination_port),
        )
        reader.add("tls.stream", conversation.index)
        return conversation.state

    def _record(self, reader: Reader, connection: Connection) -> list[str]:
        """One record: what it holds, how long it is, and then its contents.

        A record whose length reaches past this segment isn't decoded at all:
        the rest of it is in a packet that hasn't been read yet, and putting
        the two together is the next phase's job.
        """
        start = reader.buffer.peek(5)
        if int.from_bytes(start[3:5], "big") > reader.remaining - 5:
            reader.bytes("tls.segment.data", reader.remaining)
            return []
        kind = start[0]
        # Once the handshake is over, TLS 1.3 sends everything as application
        # data, whatever it really is, so Wireshark names the type opaque.
        opaque = kind == APPLICATION_DATA and connection.version == TLS13
        reader.uint8("tls.record.opaque_type" if opaque else "tls.record.content_type")
        reader.uint16("tls.record.version")
        length = reader.uint16("tls.record.length")
        body = reader.payload(length)
        if kind == HANDSHAKE:
            return self._handshakes(reader, body, connection)
        if kind == APPLICATION_DATA:
            reader.add(
                "tls.app_data",
                body.peek(body.remaining),
                offset=body.offset,
                length=body.remaining,
            )
            return ["Application Data"]
        if kind == CHANGE_CIPHER_SPEC and body.remaining:
            # The message is one byte that has to be 1, so Wireshark's item
            # says only that it is there.
            offset = body.offset
            body.skip(1)
            reader.add("tls.change_cipher_spec", True, offset=offset, length=1)
            return ["Change Cipher Spec"]
        if kind == ALERT and body.remaining >= 2:
            return [self._alert(reader, body)]
        return [CONTENT_TYPES.get(kind, f"Unknown record ({kind})")]

    @staticmethod
    def _alert(reader: Reader, body: Buffer) -> str:
        """An alert, which is two bytes: how bad, and what happened."""
        offset = body.offset
        level, description = body.uint(1), body.uint(1)
        reader.add("tls.alert_message.level", level, offset=offset, length=1)
        reader.add("tls.alert_message.desc", description, offset=offset + 1, length=1)
        return (
            f"Alert ({ALERT_LEVELS.get(level, 'Unknown')}): "
            f"{ALERT_DESCRIPTIONS.get(description, f'Unknown ({description})')}"
        )

    def _handshakes(self, reader: Reader, body: Buffer, connection: Connection) -> list[str]:
        """The handshake messages inside one record, of which there may be several."""
        notes = []
        while body.remaining >= 4:
            offset = body.offset
            kind = body.uint(1)
            length = body.uint(3)
            reader.add("tls.handshake.type", kind, offset=offset, length=1)
            reader.add("tls.handshake.length", length, offset=offset + 1, length=3)
            message = body.take(min(length, body.remaining))
            note = HANDSHAKES.get(kind, f"Unknown handshake ({kind})")
            with reader.inside():
                note += self._message(reader, message, kind, connection)
            notes.append(note)
        return notes

    def _message(self, reader: Reader, message: Buffer, kind: int, connection: Connection) -> str:
        """One handshake message, for the kinds that are readable."""
        if kind in (CLIENT_HELLO, SERVER_HELLO):
            return self._hello(reader, message, kind, connection)
        if kind == CERTIFICATE:
            self._certificates(reader, message)
        return ""

    def _hello(self, reader: Reader, message: Buffer, kind: int, connection: Connection) -> str:
        """A hello: what the sender offers, or what the server picked."""
        if message.remaining < 34:
            return ""
        fingerprint = Fingerprint(version=int.from_bytes(message.peek(2), "big"))
        reader.add("tls.handshake.version", message.uint(2), offset=message.offset - 2, length=2)
        self._random(reader, message)
        self._vector(
            reader, message, 1, "tls.handshake.session_id_length", "tls.handshake.session_id"
        )
        if kind == CLIENT_HELLO:
            offset = message.offset
            suites = message.uint(2)
            reader.add("tls.handshake.cipher_suites_length", suites, offset=offset, length=2)
            for _ in range(suites // 2):
                if message.remaining < 2:
                    break
                suite = message.uint(2)
                reader.add("tls.handshake.ciphersuite", suite, offset=message.offset - 2, length=2)
                if not is_grease(suite):
                    fingerprint.ciphers.append(suite)
            offset = message.offset
            methods = message.uint(1)
            reader.add("tls.handshake.comp_methods_length", methods, offset=offset, length=1)
            for _ in range(min(methods, message.remaining)):
                reader.add(
                    "tls.handshake.comp_method",
                    message.uint(1),
                    offset=message.offset - 1,
                    length=1,
                )
        else:
            suite = message.uint(2)
            reader.add("tls.handshake.ciphersuite", suite, offset=message.offset - 2, length=2)
            fingerprint.ciphers.append(suite)
            reader.add(
                "tls.handshake.comp_method", message.uint(1), offset=message.offset - 1, length=1
            )
        note = self._extensions(reader, message, kind, connection, fingerprint)
        self._fingerprint(reader, fingerprint, kind == CLIENT_HELLO)
        return note

    @staticmethod
    def _fingerprint(reader: Reader, fingerprint: Fingerprint, client: bool) -> None:
        """What this hello looks like, as one line and as a digest of it."""
        text = fingerprint.text(client)
        full, short = ("ja3_full", "ja3") if client else ("ja3s_full", "ja3s")
        reader.add(f"tls.handshake.{full}", text)
        reader.add(f"tls.handshake.{short}", md5(text.encode(), usedforsecurity=False).hexdigest())

    @staticmethod
    def _random(reader: Reader, message: Buffer) -> None:
        """The 32 bytes a hello starts with, whose first four were once a clock."""
        offset = message.offset
        random = message.read(32, "tls.handshake.random")
        reader.add("tls.handshake.random", bytes(random), offset=offset, length=32)
        with reader.inside():
            seconds = int.from_bytes(random[:4], "big")
            reader.add(
                "tls.handshake.random_time", seconds * 1_000_000_000, offset=offset, length=4
            )
            reader.add(
                "tls.handshake.random_bytes", bytes(random[4:]), offset=offset + 4, length=28
            )

    @staticmethod
    def _vector(
        reader: Reader, message: Buffer, size: int, length_field: str, data_field: str | None
    ) -> bytes:
        """A run of bytes with its length in front, which TLS is built out of."""
        offset = message.offset
        length = message.uint(size)
        reader.add(length_field, length, offset=offset, length=size)
        data = bytes(message.read(min(length, message.remaining), length_field))
        if data_field and data:
            reader.add(data_field, data, offset=offset + size, length=len(data))
        return data

    def _extensions(
        self,
        reader: Reader,
        message: Buffer,
        kind: int,
        connection: Connection,
        fingerprint: Fingerprint,
    ) -> str:
        """The extensions, where everything modern about TLS lives."""
        if message.remaining < 2:
            return ""
        offset = message.offset
        length = message.uint(2)
        reader.add("tls.handshake.extensions_length", length, offset=offset, length=2)
        note = ""
        while message.remaining >= 4:
            offset = message.offset
            extension = message.uint(2)
            size = message.uint(2)
            reader.add("tls.handshake.extension.type", extension, offset=offset, length=2)
            reader.add("tls.handshake.extension.len", size, offset=offset + 2, length=2)
            if not is_grease(extension):
                fingerprint.extensions.append(extension)
            data = message.take(min(size, message.remaining))
            with reader.inside():
                note += self._extension(reader, data, extension, kind, connection, fingerprint)
        return note

    def _extension(
        self,
        reader: Reader,
        data: Buffer,
        extension: int,
        kind: int,
        connection: Connection,
        fingerprint: Fingerprint,
    ) -> str:
        """One extension, for the ones worth reading."""
        if extension == SERVER_NAME and data.remaining >= 5:
            return self._server_name(reader, data)
        if extension == ALPN and data.remaining >= 2:
            self._alpn(reader, data)
        elif extension == SUPPORTED_VERSIONS:
            self._versions(reader, data, kind, connection)
        elif extension == KEY_SHARE:
            self._key_share(reader, data, kind)
        elif extension == SUPPORTED_GROUPS and data.remaining >= 2:
            fingerprint.groups.extend(
                each
                for each in self._list(
                    reader,
                    data,
                    "tls.handshake.extensions_supported_groups_length",
                    "tls.handshake.extensions_supported_group",
                    2,
                )
                if not is_grease(each)
            )
        elif extension == EC_POINT_FORMATS and data.remaining >= 1:
            fingerprint.formats.extend(
                self._list(
                    reader,
                    data,
                    "tls.handshake.extensions_ec_point_formats_length",
                    "tls.handshake.extensions_ec_point_format",
                    1,
                    size=1,
                )
            )
        elif extension == SIGNATURE_ALGORITHMS and data.remaining >= 2:
            self._signatures(reader, data)
        return ""

    @staticmethod
    def _server_name(reader: Reader, data: Buffer) -> str:
        """The name the client is asking for, in the clear."""
        offset = data.offset
        reader.add(
            "tls.handshake.extensions_server_name_list_len", data.uint(2), offset=offset, length=2
        )
        offset = data.offset
        reader.add(
            "tls.handshake.extensions_server_name_type", data.uint(1), offset=offset, length=1
        )
        offset = data.offset
        length = data.uint(2)
        reader.add("tls.handshake.extensions_server_name_len", length, offset=offset, length=2)
        name = bytes(data.read(min(length, data.remaining))).decode("ascii", "replace")
        reader.add(
            "tls.handshake.extensions_server_name", name, offset=offset + 2, length=len(name)
        )
        return f" (SNI={name})"

    @staticmethod
    def _alpn(reader: Reader, data: Buffer) -> None:
        """Which protocols the sender would speak over this connection."""
        offset = data.offset
        reader.add("tls.handshake.extensions_alpn_len", data.uint(2), offset=offset, length=2)
        while data.remaining >= 1:
            offset = data.offset
            length = data.uint(1)
            reader.add("tls.handshake.extensions_alpn_str_len", length, offset=offset, length=1)
            name = bytes(data.read(min(length, data.remaining))).decode("ascii", "replace")
            reader.add(
                "tls.handshake.extensions_alpn_str", name, offset=offset + 1, length=len(name)
            )

    @staticmethod
    def _versions(reader: Reader, data: Buffer, kind: int, connection: Connection) -> None:
        """Which versions the client offers, or the one the server chose."""
        if kind == CLIENT_HELLO:
            offset = data.offset
            reader.add(
                "tls.handshake.extensions.supported_versions_len",
                data.uint(1),
                offset=offset,
                length=1,
            )
        while data.remaining >= 2:
            offset = data.offset
            version = data.uint(2)
            reader.add(
                "tls.handshake.extensions.supported_version", version, offset=offset, length=2
            )
            if kind == SERVER_HELLO:
                # From here on the records are opaque, whatever they hold.
                connection.version = version

    @staticmethod
    def _key_share(reader: Reader, data: Buffer, kind: int) -> None:
        """The public halves of the key agreement, offered or answered."""
        if kind == CLIENT_HELLO and data.remaining >= 2:
            offset = data.offset
            reader.add(
                "tls.handshake.extensions_key_share_client_length",
                data.uint(2),
                offset=offset,
                length=2,
            )
        while data.remaining >= 4:
            offset = data.offset
            reader.add(
                "tls.handshake.extensions_key_share_group", data.uint(2), offset=offset, length=2
            )
            offset = data.offset
            length = data.uint(2)
            reader.add(
                "tls.handshake.extensions_key_share_key_exchange_length",
                length,
                offset=offset,
                length=2,
            )
            share = bytes(data.read(min(length, data.remaining)))
            reader.add(
                "tls.handshake.extensions_key_share_key_exchange",
                share,
                offset=offset + 2,
                length=len(share),
            )

    @staticmethod
    def _list(
        reader: Reader,
        data: Buffer,
        length_field: str,
        item_field: str,
        item_size: int,
        size: int = 2,
    ) -> list[int]:
        """A list of fixed-size numbers with its length in front."""
        offset = data.offset
        reader.add(length_field, data.uint(size), offset=offset, length=size)
        items = []
        while data.remaining >= item_size:
            offset = data.offset
            value = data.uint(item_size)
            reader.add(item_field, value, offset=offset, length=item_size)
            items.append(value)
        return items

    @staticmethod
    def _signatures(reader: Reader, data: Buffer) -> None:
        """Which signature and hash pairs the sender will accept."""
        offset = data.offset
        reader.add("tls.handshake.sig_hash_alg_len", data.uint(2), offset=offset, length=2)
        while data.remaining >= 2:
            offset = data.offset
            algorithm = data.uint(2)
            reader.add("tls.handshake.sig_hash_alg", algorithm, offset=offset, length=2)
            with reader.inside():
                reader.add("tls.handshake.sig_hash_hash", algorithm >> 8, offset=offset, length=1)
                reader.add(
                    "tls.handshake.sig_hash_sig", algorithm & 0xFF, offset=offset + 1, length=1
                )

    @staticmethod
    def _certificates(reader: Reader, message: Buffer) -> None:
        """The chain a server sends to prove who it is, when it sends it in the clear."""
        if message.remaining < 3:
            return
        offset = message.offset
        reader.add("tls.handshake.certificates_length", message.uint(3), offset=offset, length=3)
        while message.remaining >= 3:
            offset = message.offset
            length = message.uint(3)
            reader.add("tls.handshake.certificate_length", length, offset=offset, length=3)
            certificate = bytes(message.read(min(length, message.remaining)))
            reader.add(
                "tls.handshake.certificate", certificate, offset=offset + 3, length=len(certificate)
            )

    def looks_like(self, payload: Buffer, context: Context) -> bool:
        """Whether a payload starts a TLS record.

        A record starts with a content type, a version that is one of a
        handful, and a length that fits in a record. That is enough to tell
        the start of a TLS connection from anything else on an odd port, and
        the start of a record from the middle of one.
        """
        if payload.remaining < 5:
            return False
        start = payload.peek(5)
        version = int.from_bytes(start[1:3], "big")
        length = int.from_bytes(start[3:5], "big")
        return (
            start[0] in CONTENT_TYPES
            and 0x0300 <= version <= 0x0304
            and 0 < length <= 0x4000 + 2048
        )
