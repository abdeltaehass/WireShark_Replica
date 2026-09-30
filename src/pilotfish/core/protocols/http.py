"""HTTP/1.1: a start line, headers, a blank line, and whatever follows.

The protocol is text, which makes it the easiest one here to read and the
fussiest one to read *exactly*: every line ends CRLF, the header name is
case-insensitive, and a body may arrive in pieces whose sizes are written in
hexadecimal between them.

A message can span several TCP segments, and until reassembly arrives in the
next phase this decodes what one segment holds: the messages that fit are
decoded in full, and the rest give up what they can.

Reference: RFC 9112 for the syntax, RFC 9110 for what the headers mean.
"""

from dataclasses import dataclass, field

from pilotfish.core.dissect import (
    Buffer,
    Context,
    DeclinedError,
    Dissector,
    Field,
    FieldType,
    Handoff,
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

VERSIONS = ("HTTP/1.1", "HTTP/1.0", "HTTP/0.9")

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


@dataclass(slots=True)
class Exchanges:
    """What each connection has asked, so an answer can point back at it."""

    pending: dict[int, list[Requested]] = field(default_factory=dict)
    answered: dict[int, Requested] = field(default_factory=dict)


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
        message = bytes(reader.buffer.peek(reader.remaining))
        if not self.looks_like(reader.buffer, context):
            # The middle of a message that started in an earlier packet. It
            # takes reassembly to say what it holds, which is the next phase.
            raise DeclinedError
        head, _, _ = message.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        first = lines[0].decode("latin-1")
        request = self._first_line(reader, first)
        headers = self._headers(reader, lines[1:], request)
        if len(head) < len(message):
            # The blank line that ends the headers, which belongs to neither.
            reader.skip(2, "http")
        reader.summarize(self.title)
        if request:
            self._describe_request(reader, context, first, headers)
        else:
            self._describe_response(reader, context, first, headers)
        return self._body(reader, context, headers)

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
        uri = first.split(" ")[1] if " " in first else ""
        host = headers.get("host", "")
        full = f"http://{host}{uri}" if host and uri.startswith("/") else uri
        if full:
            reader.add("http.request.full_uri", full)
        context.describe(f"{first} ")
        stream = _stream(context)
        if stream is None:
            return
        exchanges = context.session.store(self.name, Exchanges)
        when = context.packet.timestamp_ns or 0
        waiting = Requested(context.number, when, uri, full)
        exchanges.pending.setdefault(stream, []).append(waiting)

    def _describe_response(
        self, reader: Reader, context: Context, first: str, headers: dict[str, str]
    ) -> None:
        """The same for an answer, which points back at what it answers."""
        context.describe(f"{first} ")
        stream = _stream(context)
        if stream is None:
            return
        exchanges = context.session.store(self.name, Exchanges)
        request = exchanges.answered.get(context.number)
        if request is None:
            waiting = exchanges.pending.get(stream) or []
            if not waiting:
                return
            request = waiting.pop(0)
            exchanges.answered[context.number] = request
        reader.add("http.request_in", request.frame)
        reader.add("http.time", (context.packet.timestamp_ns or 0) - request.time)
        # Wireshark shows what was asked for alongside the answer, so an
        # answer can be read without hunting for the question.
        if request.uri:
            reader.add("http.request.uri", request.uri)
        if request.full_uri:
            reader.add("http.request.full_uri", request.full_uri)

    def _body(self, reader: Reader, context: Context, headers: dict[str, str]) -> Handoff | None:
        """Whatever follows the headers in this segment.

        A body sent in chunks writes each chunk's size in hexadecimal on a
        line of its own, so the pieces can be read even when the whole isn't
        there yet.
        """
        if not reader.remaining:
            return None
        if "chunked" in headers.get("transfer-encoding", "").lower():
            self._chunks(reader)
            return None
        declared = headers.get("content-length", "")
        whole = declared.isdigit() and int(declared) <= reader.remaining
        payload = reader.payload()
        reader.add(
            "http.file_data",
            payload.peek(payload.remaining),
            offset=payload.offset,
            length=payload.remaining,
        )
        kind = headers.get("content-type", "").split(";")[0].strip()
        if kind and whole:
            # Wireshark names what a body turned out to be once it has all of
            # it, which for a body split across packets is the packet that
            # completes it rather than this one.
            context.describe(f"{context.info} ({kind})")
        return as_data(payload)

    @staticmethod
    def _chunks(reader: Reader) -> None:
        """The chunks of a body that were sent with their sizes in front."""
        while reader.remaining:
            rest = bytes(reader.buffer.peek(reader.remaining))
            line, mark, _ = rest.partition(b"\r\n")
            if not mark:
                reader.skip(reader.remaining, "http.chunk_data")
                return
            size = int(line.split(b";")[0] or b"0", 16)
            reader.skip(len(line) + 2, "http.chunk_size")
            reader.add("http.chunk_size", size)
            if not size:
                return
            with reader.inside():
                reader.bytes("http.chunk_data", min(size, reader.remaining))
                if reader.remaining >= 2:
                    reader.bytes("http.chunk_boundary", 2)

    def looks_like(self, payload: Buffer, context: Context) -> bool:
        """Whether a payload on any port at all starts an HTTP message.

        A server on a port nobody registered is still an HTTP server if it
        answers like one, which is how Wireshark finds them too.
        """
        # Long enough for any first line worth the name: a request line is a
        # method, what it wants, and the version, and a URI can be long.
        start = bytes(payload.peek(min(payload.remaining, 1024)))
        line = start.split(b"\r\n")[0].decode("latin-1", "replace")
        words = line.split(" ")
        if words[0].startswith("HTTP/"):
            return True
        return words[0] in METHODS and " HTTP/" in line


def _stream(context: Context) -> int | None:
    """Which connection this is, so a request and its answer can be paired."""
    if context.source is None or context.destination is None:
        return None
    ends = {
        (str(context.source), context.source_port),
        (str(context.destination), context.destination_port),
    }
    return hash(frozenset(ends))
