"""HTTP/1.1: a start line, headers, a blank line, and whatever follows.

The protocol is text, which makes it the easiest one here to read and the
fussiest one to read *exactly*: every line ends CRLF, the header name is
case-insensitive, and a body may arrive in pieces whose sizes are written in
hexadecimal between them.

A message is rarely one segment. The headers say how long the body is, in one
of three ways, and until that much has arrived the dissector asks for more
rather than decoding half a message. A download is decoded once, whole, in
the packet that brings its last byte.

Reference: RFC 9112 for the syntax, RFC 9110 for what the headers mean.
"""

import zlib
from dataclasses import dataclass, field
from enum import Enum

from pilotfish.core.dissect import (
    Buffer,
    Context,
    DeclinedError,
    Dissector,
    Field,
    FieldType,
    Handoff,
    NeedMoreError,
    Reader,
    as_data,
    heuristic,
    register,
)
from pilotfish.core.protocols.tcp import HEURISTICS, TCP_PORT

PORTS = (80, 3128, 3132, 8080, 8088, 11371, 1900, 2869, 2710)
"""The ports Wireshark decodes as HTTP without being asked."""

METHODS = frozenset(
    {
        "GET",
        "HEAD",
        "POST",
        "PUT",
        "DELETE",
        "CONNECT",
        "OPTIONS",
        "TRACE",
        "PATCH",
        "NOTIFY",
        "SEARCH",
        "SUBSCRIBE",
        "UNSUBSCRIBE",
        "PROPFIND",
        "PROPPATCH",
        "MKCOL",
        "COPY",
        "MOVE",
        "LOCK",
        "UNLOCK",
    }
)

METHOD_NAMES = frozenset(method.encode() for method in METHODS)
LONGEST_METHOD = max(METHOD_NAMES, key=len)

VERSIONS = ("HTTP/1.1", "HTTP/1.0", "HTTP/0.9")

MAX_HEAD = 64 * 1024
"""How long a start line and its headers may run before they stop being
waited for. Servers refuse far less."""

MAX_DECODED = 64 * 1024 * 1024
"""How much a compressed body may expand to. A few kilobytes of zeros
compress to almost nothing, and a body built that way is meant to exhaust
whoever unpacks it."""

LAST_CHUNK = b"0\r\n\r\n"
"""The shortest way a chunked body can end."""

HEX_DIGITS = b"0123456789abcdefABCDEF"
MAX_SIZE_DIGITS = 8
"""As many digits as a chunk's size is believed to have: four gigabytes."""

MAX_WAITING = 256
"""How many unanswered requests a connection is remembered to have."""

COMPRESSED = frozenset({"gzip", "x-gzip", "deflate", "x-deflate"})
"""The content encodings the standard library can undo."""


class Body(Enum):
    """How a message says where its body ends."""

    NONE = "none"
    LENGTH = "length"
    """A Content-Length header counts the bytes."""
    CHUNKED = "chunked"
    """It comes in chunks, each with its size in front, and a chunk of size
    zero ends it."""
    TO_END = "to the end"
    """It says nothing, so the body is whatever arrives before the
    connection closes."""


# The headers with a field of their own, by the name they are sent under.
HEADERS = {
    "accept": "http.accept",
    "accept-encoding": "http.accept_encoding",
    "accept-language": "http.accept_language",
    "authorization": "http.authorization",
    "cache-control": "http.cache_control",
    "connection": "http.connection",
    "content-encoding": "http.content_encoding",
    "content-type": "http.content_type",
    "cookie": "http.cookie",
    "date": "http.date",
    "host": "http.host",
    "last-modified": "http.last_modified",
    "location": "http.location",
    "referer": "http.referer",
    "server": "http.server",
    "set-cookie": "http.set_cookie",
    "transfer-encoding": "http.transfer_encoding",
    "user-agent": "http.user_agent",
    "www-authenticate": "http.www_authenticate",
}

REASONS = {
    200: "OK",
    201: "Created",
    204: "No Content",
    301: "Moved Permanently",
    302: "Found",
    304: "Not Modified",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
}


@dataclass(slots=True)
class Requested:
    """A request this capture has seen, waiting for its answer."""

    frame: int
    time: int
    uri: str = ""
    full_uri: str = ""
    method: str = ""


@dataclass(slots=True)
class Exchanges:
    """What each connection has asked, so an answer can point back at it."""

    pending: dict[int, list[Requested]] = field(default_factory=dict)


@heuristic(HEURISTICS)
@register(TCP_PORT, *PORTS)
class Http(Dissector):
    name = "http"
    title = "Hypertext Transfer Protocol"
    fields = (
        Field("http.request", FieldType.BOOL, "Request"),
        Field("http.response", FieldType.BOOL, "Response"),
        Field("http.request.method", FieldType.STRING, "Request Method"),
        Field("http.request.uri", FieldType.STRING, "Request URI"),
        Field("http.request.uri.path", FieldType.STRING, "Request URI Path"),
        Field("http.request.uri.query", FieldType.STRING, "Request URI Query"),
        Field("http.request.uri.query.parameter", FieldType.STRING, "Query parameter"),
        Field("http.request.version", FieldType.STRING, "Request Version"),
        Field("http.request.full_uri", FieldType.STRING, "Full request URI"),
        Field("http.request.line", FieldType.STRING, "Request line"),
        Field("http.response.version", FieldType.STRING, "Response Version"),
        Field("http.response.code", FieldType.UINT, "Status Code"),
        Field("http.response.code.desc", FieldType.STRING, "Status Code Description"),
        Field("http.response.phrase", FieldType.STRING, "Response Phrase"),
        Field("http.response.line", FieldType.STRING, "Response line"),
        Field("http.content_length_header", FieldType.STRING, "Content length"),
        Field("http.content_length", FieldType.UINT, "Content length"),
        Field("http.file_data", FieldType.BYTES, "File Data"),
        Field("http.chunk_size", FieldType.UINT, "Chunk size"),
        Field("http.chunk_data", FieldType.BYTES, "Chunk data"),
        Field("http.chunk_boundary", FieldType.BYTES, "Chunk boundary"),
        Field("http.request_in", FieldType.UINT, "Request in frame"),
        Field("http.time", FieldType.TIME, "Time since request"),
        *(Field(name, FieldType.STRING, name.removeprefix("http.")) for name in HEADERS.values()),
    )

    def dissect(self, reader: Reader, context: Context) -> Handoff | None:
        message = reader.buffer.peek(reader.remaining)
        if context.can_wait and _starting(message):
            # A start line that hasn't reached its end yet, as one with a
            # long address in it won't have.
            raise NeedMoreError
        if not self.looks_like(reader.buffer, context):
            # Bytes from the middle of a message whose start the capture
            # never saw.
            raise DeclinedError
        head, blank, _ = message.partition(b"\r\n\r\n")
        if not blank and context.can_wait and len(message) <= MAX_HEAD:
            # The headers themselves carry on in the next segment.
            raise NeedMoreError
        lines = head.split(b"\r\n")
        first = lines[0].decode("latin-1")
        request = not first.startswith("HTTP/")
        named = _named(lines[1:])
        kind = self._kind(context, first, request, named)
        start = len(head) + len(blank)
        # Raises when the body isn't all here, so nothing is recorded for a
        # message until every byte of it has arrived.
        end = _measure(message, start, kind, named, context.can_wait)

        self._first_line(reader, first)
        headers = self._headers(reader, lines[1:], request)
        if blank:
            # The blank line that ends the headers, which belongs to neither.
            reader.skip(2, "http")
        reader.summarize(self.title)
        if request:
            self._describe_request(reader, context, first, headers)
        else:
            self._describe_response(reader, context, first, headers)
        return self._body(reader, context, headers, kind, end - start)

    def _kind(self, context: Context, first: str, request: bool, headers: dict[str, str]) -> Body:
        """How this message's body is delimited, which RFC 9112 settles in
        this order."""
        if not request and self._has_no_body(context, first):
            return Body.NONE
        if "chunked" in headers.get("transfer-encoding", "").lower():
            return Body.CHUNKED
        if headers.get("content-length", "").isdigit():
            return Body.LENGTH
        # A request with no length has no body. A response with none has one
        # that lasts until the server hangs up.
        return Body.NONE if request else Body.TO_END

    def _has_no_body(self, context: Context, first: str) -> bool:
        """Whether a response is one of those that never carry a body,
        whatever its headers say."""
        words = first.split(" ")
        code = int(words[1]) if len(words) > 1 and words[1].isdigit() else 0
        if code // 100 == 1 or code in (204, 304):
            return True
        waiting = self._waiting(context)
        method = waiting[0].method if waiting else ""
        # The answer to HEAD describes a body it doesn't send, and a
        # successful CONNECT turns the connection into a tunnel.
        return method == "HEAD" or (method == "CONNECT" and code // 100 == 2)

    def _waiting(self, context: Context) -> list[Requested]:
        """The requests on this connection that haven't been answered yet."""
        stream = _stream(context)
        if stream is None:
            return []
        return context.session.store(self.name, Exchanges).pending.setdefault(stream, [])

    def _first_line(self, reader: Reader, first: str) -> bool:
        """The start line, which says whether this is a request or an answer.

        A request names a method and what it wants; a response names the
        version it speaks and how the request went.
        """
        words = first.split(" ")
        if words[0].startswith("HTTP/"):
            reader.skip(len(first) + 2, "http.response.line")
            reader.add("http.response.version", words[0])
            code = int(words[1]) if len(words) > 1 and words[1].isdigit() else 0
            reader.add("http.response.code", code)
            with reader.inside():
                reader.add("http.response.code.desc", REASONS.get(code, "Unknown"))
            reader.add("http.response.phrase", " ".join(words[2:]))
            reader.add("http.response", True)
            return False
        reader.skip(len(first) + 2, "http.request.line")
        reader.add("http.request.method", words[0])
        if len(words) > 1:
            self._uri(reader, words[1])
        if len(words) > 2:
            reader.add("http.request.version", words[2])
        reader.add("http.request", True)
        return True

    @staticmethod
    def _uri(reader: Reader, uri: str) -> None:
        """What the request asked for, and the query string if it has one."""
        reader.add("http.request.uri", uri)
        path, mark, query = uri.partition("?")
        if not mark:
            return
        with reader.inside():
            reader.add("http.request.uri.path", path)
            reader.add("http.request.uri.query", query)
            for parameter in query.split("&"):
                reader.add("http.request.uri.query.parameter", parameter)

    @staticmethod
    def _headers(reader: Reader, lines: list[bytes], request: bool) -> dict[str, str]:
        """Every header line, as a line of its own and as what it says."""
        line_field = "http.request.line" if request else "http.response.line"
        headers: dict[str, str] = {}
        for raw in lines:
            line = raw.decode("latin-1")
            reader.skip(len(raw) + 2, line_field)
            reader.add(line_field, f"{line}\r\n")
            name, mark, value = line.partition(":")
            if not mark:
                continue
            name, value = name.strip().lower(), value.strip()
            headers[name] = value
            with reader.inside():
                if name in HEADERS:
                    reader.add(HEADERS[name], value)
                if name == "content-length":
                    reader.add("http.content_length_header", value)
                    with reader.inside():
                        reader.add("http.content_length", int(value) if value.isdigit() else 0)
        return headers

    def _describe_request(
        self, reader: Reader, context: Context, first: str, headers: dict[str, str]
    ) -> None:
        """What the packet list says about a request, and where to answer it."""
        words = first.split(" ")
        uri = words[1] if len(words) > 1 else ""
        host = headers.get("host", "")
        full = f"http://{host}{uri}" if host and uri.startswith("/") else uri
        if full:
            reader.add("http.request.full_uri", full)
        context.describe(f"{first} ")
        if _stream(context) is None:
            return
        when = context.packet.timestamp_ns or 0
        waiting = self._waiting(context)
        if len(waiting) >= MAX_WAITING:
            # Requests nobody is answering, or answers the capture never saw.
            del waiting[0]
        waiting.append(Requested(context.number, when, uri, full, words[0]))

    def _describe_response(
        self, reader: Reader, context: Context, first: str, headers: dict[str, str]
    ) -> None:
        """The same for an answer, which points back at what it answers."""
        context.describe(f"{first} ")
        waiting = self._waiting(context)
        if not waiting:
            return
        words = first.split(" ")
        # An interim answer, such as 100 Continue, leaves the request waiting
        # for its real one.
        interim = len(words) > 1 and words[1].startswith("1")
        request = waiting[0] if interim else waiting.pop(0)
        reader.add("http.request_in", request.frame)
        reader.add("http.time", (context.packet.timestamp_ns or 0) - request.time)
        # Wireshark shows what was asked for alongside the answer, so an
        # answer can be read without hunting for the question.
        if request.uri:
            reader.add("http.request.uri", request.uri)
        if request.full_uri:
            reader.add("http.request.full_uri", request.full_uri)

    def _body(
        self, reader: Reader, context: Context, headers: dict[str, str], kind: Body, length: int
    ) -> Handoff | None:
        """The body, and the file it carries once its encodings are undone.

        Two encodings can wrap it. Chunking is how it was sent, and is always
        undone. Compression is how it was stored, and is undone when the
        standard library knows the format.
        """
        if not length:
            return None
        offset = reader.buffer.offset
        payload = reader.payload(length)
        sent = payload.peek(payload.remaining)
        if kind is Body.CHUNKED:
            sent, whole = self._chunks(reader, payload)
        else:
            whole = kind is not Body.LENGTH or length >= int(headers["content-length"])
        encoding = headers.get("content-encoding", "").lower()
        file = _unpacked(sent, encoding) if encoding and encoding != "identity" else sent
        if file is not None:
            reader.add("http.file_data", file, offset=offset, length=length)
        media = headers.get("content-type", "").split(";")[0].strip()
        if media and whole and not context.in_error:
            # Wireshark names what a body turned out to be once it has all
            # of it.
            context.info += f" ({media})"
        return None if kind is Body.CHUNKED else as_data(payload)

    @staticmethod
    def _chunks(reader: Reader, body: Buffer) -> tuple[bytes, bool]:
        """The chunks of a body that was sent with their sizes in front.

        Returns the body with the chunking taken away, and whether the chunk
        that ends it was reached.
        """
        pieces: list[bytes] = []
        while body.remaining:
            line, mark, _ = body.peek(body.remaining).partition(b"\r\n")
            size = _chunk_size(line)
            if not mark or size is None:
                return b"".join(pieces), False
            offset = body.offset
            body.skip(len(line) + 2)
            reader.add("http.chunk_size", size, offset=offset, length=len(line))
            if not size:
                return b"".join(pieces), True
            with reader.inside():
                offset = body.offset
                data = bytes(body.read(min(size, body.remaining)))
                reader.add("http.chunk_data", data, offset=offset, length=len(data))
                pieces.append(data)
                if body.remaining >= 2:
                    offset = body.offset
                    boundary = bytes(body.read(2))
                    reader.add("http.chunk_boundary", boundary, offset=offset, length=2)
        return b"".join(pieces), False

    def looks_like(self, payload: Buffer, context: Context) -> bool:
        """Whether a payload on any port at all starts an HTTP message.

        A server on a port nobody registered is still an HTTP server if it
        answers like one, which is how Wireshark finds them too.
        """
        start = payload.peek(min(payload.remaining, len(LONGEST_METHOD) + 1))
        if start.startswith(b"HTTP/"):
            return True
        method, space, _ = start.partition(b" ")
        if not space or method not in METHOD_NAMES:
            return False
        # A request line is a method, what it wants, and the version, and
        # what it wants can be long.
        line, _, _ = payload.peek(min(payload.remaining, MAX_HEAD)).partition(b"\r\n")
        return b" HTTP/" in line


def _starting(message: bytes) -> bool:
    """Whether these bytes could be a start line that isn't finished.

    They are when no line has ended yet and what there is reads like the
    beginning of a request or a response: a method, or as much of one as has
    arrived.
    """
    if not message or b"\n" in message or len(message) > MAX_HEAD:
        return False
    word, space, _ = message.partition(b" ")
    if space:
        return word in METHOD_NAMES or word.startswith(b"HTTP/")
    return any(name.startswith(word) for name in (*METHOD_NAMES, b"HTTP/1.1", b"HTTP/1.0"))


def _named(lines: list[bytes]) -> dict[str, str]:
    """The headers by name, lower-cased, without recording anything."""
    headers: dict[str, str] = {}
    for raw in lines:
        name, mark, value = raw.decode("latin-1").partition(":")
        if mark:
            headers[name.strip().lower()] = value.strip()
    return headers


def _chunk_size(line: bytes) -> int | None:
    """The size a chunk's first line gives, in hexadecimal, or ``None`` when
    the line isn't one.

    Only digits count. ``int`` would also take a sign, and a chunk of minus
    two bytes is one that never ends.
    """
    digits = line.split(b";")[0].strip()
    if not digits or len(digits) > MAX_SIZE_DIGITS or digits.strip(HEX_DIGITS):
        return None
    return int(digits, 16)


def _measure(message: bytes, start: int, kind: Body, headers: dict[str, str], wait: bool) -> int:
    """Where the message ends, given that its body starts at ``start``.

    Raises :class:`NeedMoreError` when the end hasn't arrived and ``wait``
    says it still can. Otherwise a message that is cut short ends where the
    bytes do.
    """
    here = len(message) - start
    if kind is Body.NONE:
        return start
    if kind is Body.LENGTH:
        declared = int(headers["content-length"])
        if here < declared and wait:
            raise NeedMoreError(declared - here)
        return start + min(declared, here)
    if kind is Body.TO_END:
        if wait:
            raise NeedMoreError(to_end=True)
        return len(message)
    at = start
    while True:
        line_end = message.find(b"\r\n", at)
        size = None if line_end < 0 else _chunk_size(message[at:line_end])
        if line_end < 0 and wait and len(message) - at <= MAX_HEAD:
            raise NeedMoreError
        if size is None:
            # Not a chunk at all, so there is no telling where this ends.
            return len(message)
        at = line_end + 2
        if not size:
            break
        missing = at + size + 2 - len(message)
        if missing > 0:
            if wait:
                # The rest of this chunk, and at the very least the chunk
                # of size zero that ends the body.
                raise NeedMoreError(missing + len(LAST_CHUNK))
            return len(message)
        at += size + 2
    # After the last chunk come any trailing headers, and a blank line.
    while True:
        line_end = message.find(b"\r\n", at)
        if line_end < 0:
            if wait and len(message) - at <= MAX_HEAD:
                raise NeedMoreError
            return len(message)
        at, blank = line_end + 2, line_end == at
        if blank:
            return at


def _unpacked(body: bytes, encoding: str) -> bytes | None:
    """A compressed body as the file it holds, or ``None`` if it won't unpack."""
    if encoding not in COMPRESSED:
        return None
    # 47 tells zlib to work out for itself whether the wrapper is gzip's or
    # its own. Some servers send "deflate" with no wrapper at all.
    for bits in (47, -zlib.MAX_WBITS):
        try:
            return zlib.decompressobj(bits).decompress(body, MAX_DECODED)
        except zlib.error:
            continue
    return None


def _stream(context: Context) -> int | None:
    """Which connection this is, so a request and its answer can be paired."""
    if context.source is None or context.destination is None:
        return None
    ends = {
        (str(context.source), context.source_port),
        (str(context.destination), context.destination_port),
    }
    return hash(frozenset(ends))
