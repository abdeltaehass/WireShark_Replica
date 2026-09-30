"""DNS, and the multicast version of it a Mac never stops sending.

The format is from 1987 and shows it: names are stored as a run of
length-prefixed labels, and any label may be replaced by a pointer to a name
earlier in the same message. Following those pointers is where a careless
parser dies, because nothing stops a message from pointing a name at itself.

References: RFC 1035 for the format and the compression, RFC 3596 for AAAA,
RFC 2782 for SRV, and RFC 6762 for multicast DNS.
"""

from dataclasses import dataclass, field

from pilotfish.core.dissect import (
    Context,
    Dissector,
    Field,
    FieldType,
    MalformedError,
    Reader,
    register,
)
from pilotfish.core.protocols.udp import UDP_PORT

PORT = 53
MDNS_PORT = 5353

HEADER_SIZE = 12

POINTER = 0xC0
"""The two top bits of a label length, saying the rest is a pointer."""
POINTER_MASK = 0x3FFF
MAX_NAME = 255
"""The longest a name can be, which is also what stops a pointer loop."""

ROOT = "<Root>"
"""What Wireshark calls the name with no labels at all."""

SRV = 33
"""The one record type whose owner name Wireshark splits into its pieces."""

CACHE_FLUSH = 0x8000
"""In multicast DNS, the top bit of a record's class."""
UNICAST_RESPONSE = 0x8000
"""And of a question's class: answer me directly rather than to the group."""

# The record types these samples carry, by the names Wireshark prints.
TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    13: "HINFO",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    29: "LOC",
    33: "SRV",
    35: "NAPTR",
    41: "OPT",
    43: "DS",
    46: "RRSIG",
    47: "NSEC",
    48: "DNSKEY",
    52: "TLSA",
    64: "SVCB",
    65: "HTTPS",
    99: "SPF",
    251: "IXFR",
    252: "AXFR",
    255: "ANY",
    257: "CAA",
}

OPCODES = {
    0: "Standard query",
    1: "Inverse query",
    2: "Server status request",
    4: "Zone change notification",
    5: "Dynamic update",
    6: "DNS Stateful operations (DSO)",
}

RESPONSE = 0x8000
OPCODE = 0x7800
AUTHORITATIVE = 0x0400
TRUNCATED = 0x0200
RECURSION_DESIRED = 0x0100
RECURSION_AVAILABLE = 0x0080
Z = 0x0040
AUTHENTICATED = 0x0020
CHECKING_DISABLED = 0x0010
RCODE = 0x000F


@dataclass(slots=True)
class Asked:
    """A question this capture has seen, waiting for its answer."""

    frame: int
    time: int


@dataclass(slots=True)
class Questions:
    """The questions of one capture, by transaction number and the two ends."""

    asked: dict[tuple[int, str, str], Asked] = field(default_factory=dict)


def read_name(message: bytes, at: int) -> tuple[str, int]:
    """The name at ``at``, and how many bytes of it are there to step over.

    A name is a run of length-prefixed labels ending in a zero length, except
    that a label may instead be a pointer to a name earlier in the message,
    which is how a message repeats a name without writing it twice. Only the
    bytes before the first pointer count towards the length: the rest of the
    name lives somewhere else.

    A message may point a name at itself, or at a chain of pointers that comes
    back round, and a parser that follows pointers wherever they lead never
    returns. A pointer is only ever meant to name something written earlier,
    so every one of them here has to point strictly backwards: each jump then
    lands nearer the start of the message than the last, and a chain of them
    has to end. The 255-byte limit on a name stops the other runaway, a chain
    of backward pointers that each add a label.
    """
    labels: list[str] = []
    position = at
    length = 0
    followed = False
    while True:
        if position >= len(message):
            raise MalformedError(f"a name at offset {at} runs past the end of the message")
        size = message[position]
        if size & POINTER == POINTER:
            if position + 1 >= len(message):
                raise MalformedError(f"a compression pointer at offset {position} is cut short")
            target = int.from_bytes(message[position : position + 2], "big") & POINTER_MASK
            if target >= position:
                raise MalformedError(
                    f"a compression pointer at offset {position} points to {target}, "
                    "which is not before it"
                )
            if not followed:
                length = position + 2 - at
                followed = True
            position = target
            continue
        if size & POINTER:
            raise MalformedError(f"a label at offset {position} has a length of {size:#04x}")
        position += 1
        if size == 0:
            if not followed:
                length = position - at
            break
        label = message[position : position + size]
        if len(label) < size:
            raise MalformedError(f"a label at offset {position} runs past the end of the message")
        labels.append(label.decode("ascii", "replace"))
        position += size
        if sum(len(each) + 1 for each in labels) > MAX_NAME:
            raise MalformedError(f"a name at offset {at} is longer than {MAX_NAME} bytes")
    return ".".join(labels), length


@register(UDP_PORT, PORT)
class Dns(Dissector):
    name = "dns"
    title = "Domain Name System"
    fields = (
        Field("dns.id", FieldType.UINT, "Transaction ID", hex=True),
        Field("dns.flags", FieldType.UINT, "Flags", hex=True),
        Field("dns.flags.response", FieldType.BOOL, "Response"),
        Field("dns.flags.opcode", FieldType.UINT, "Opcode"),
        Field("dns.flags.authoritative", FieldType.BOOL, "Authoritative"),
        Field("dns.flags.truncated", FieldType.BOOL, "Truncated"),
        Field("dns.flags.recdesired", FieldType.BOOL, "Recursion desired"),
        Field("dns.flags.recavail", FieldType.BOOL, "Recursion available"),
        Field("dns.flags.z", FieldType.BOOL, "Z"),
        Field("dns.flags.authenticated", FieldType.BOOL, "Answer authenticated"),
        Field("dns.flags.ad", FieldType.BOOL, "AD bit"),
        Field("dns.flags.checkdisable", FieldType.BOOL, "Non-authenticated data"),
        Field("dns.flags.rcode", FieldType.UINT, "Reply code"),
        Field("dns.count.queries", FieldType.UINT, "Questions"),
        Field("dns.count.answers", FieldType.UINT, "Answer RRs"),
        Field("dns.count.auth_rr", FieldType.UINT, "Authority RRs"),
        Field("dns.count.add_rr", FieldType.UINT, "Additional RRs"),
        Field("dns.qry.name", FieldType.STRING, "Name"),
        Field("dns.qry.name.len", FieldType.UINT, "Name Length"),
        Field("dns.count.labels", FieldType.UINT, "Label Count"),
        Field("dns.qry.type", FieldType.UINT, "Type"),
        Field("dns.qry.class", FieldType.UINT, "Class", hex=True),
        Field("dns.qry.qu", FieldType.BOOL, '"QU" question'),
        Field("dns.resp.name", FieldType.STRING, "Name"),
        Field("dns.resp.type", FieldType.UINT, "Type"),
        Field("dns.resp.class", FieldType.UINT, "Class", hex=True),
        Field("dns.resp.cache_flush", FieldType.BOOL, "Cache flush"),
        Field("dns.resp.ttl", FieldType.UINT, "Time to live"),
        Field("dns.resp.len", FieldType.UINT, "Data length"),
        Field("dns.a", FieldType.IPV4, "Address"),
        Field("dns.aaaa", FieldType.IPV6, "AAAA Address"),
        Field("dns.cname", FieldType.STRING, "CNAME"),
        Field("dns.ns", FieldType.STRING, "Name Server"),
        Field("dns.ptr.domain_name", FieldType.STRING, "Domain Name"),
        Field("dns.mx.preference", FieldType.UINT, "Preference"),
        Field("dns.mx.mail_exchange", FieldType.STRING, "Mail Exchange"),
        Field("dns.txt.length", FieldType.UINT, "TXT Length"),
        Field("dns.txt", FieldType.STRING, "TXT"),
        Field("dns.srv.instance", FieldType.STRING, "Instance"),
        Field("dns.srv.service", FieldType.STRING, "Service"),
        Field("dns.srv.proto", FieldType.STRING, "Protocol"),
        Field("dns.srv.name", FieldType.STRING, "Name"),
        Field("dns.srv.priority", FieldType.UINT, "Priority"),
        Field("dns.srv.weight", FieldType.UINT, "Weight"),
        Field("dns.srv.port", FieldType.UINT, "Port"),
        Field("dns.srv.target", FieldType.STRING, "Target"),
        Field("dns.soa.mname", FieldType.STRING, "Primary name server"),
        Field("dns.soa.rname", FieldType.STRING, "Responsible authority's mailbox"),
        Field("dns.soa.serial_number", FieldType.UINT, "Serial Number"),
        Field("dns.soa.refresh_interval", FieldType.UINT, "Refresh Interval"),
        Field("dns.soa.retry_interval", FieldType.UINT, "Retry Interval"),
        Field("dns.soa.expire_limit", FieldType.UINT, "Expire limit"),
        Field("dns.soa.minimum_ttl", FieldType.UINT, "Minimum TTL"),
        Field("dns.unsolicited", FieldType.BOOL, "Unsolicited"),
        Field("dns.response_to", FieldType.UINT, "Request In"),
        Field("dns.time", FieldType.TIME, "Time"),
    )

    multicast = False
    """Whether this is the multicast version, which uses two of the class bits."""

    def dissect(self, reader: Reader, context: Context) -> None:
        message = reader.buffer.peek(reader.remaining)
        start = reader.buffer.offset
        identifier = reader.uint16("dns.id")
        flags = reader.uint16("dns.flags")
        self._flags(reader, flags)
        counts = [reader.uint16(name) for name in _COUNTS]

        # The packet list line is built as the message is read, in its own
        # order: what was asked, then every record of every section, which is
        # how Wireshark builds it too.
        number = (flags & OPCODE) >> 11
        opcode = OPCODES.get(number, f"Unknown operation ({number})")
        said = f"{opcode} response" if flags & RESPONSE else opcode
        described = f"{said} {identifier:#06x}"
        if flags & RESPONSE and flags & RCODE:
            described += f" {_RCODES.get(flags & RCODE, f'Unknown error ({flags & RCODE})')}"
        asked = self._questions(reader, message, start, counts[0])
        described += "".join(asked)
        for count in counts[1:]:
            described += "".join(self._records(reader, message, start, count))
        self._match(reader, context, identifier, bool(flags & RESPONSE))
        context.describe(described)
        reader.summarize(f"{self.title} ({'response' if flags & RESPONSE else 'query'})")
        return None

    def _flags(self, reader: Reader, flags: int) -> None:
        """The flags, which say what kind of message this is.

        Wireshark shows only the ones that mean anything for the message in
        hand: half of them are the server's answer to something, and a query
        hasn't been answered yet.
        """
        response = bool(flags & RESPONSE)
        with reader.inside():
            reader.add("dns.flags.response", response)
            reader.add("dns.flags.opcode", (flags & OPCODE) >> 11)
            if response:
                reader.add("dns.flags.authoritative", bool(flags & AUTHORITATIVE))
            reader.add("dns.flags.truncated", bool(flags & TRUNCATED))
            reader.add("dns.flags.recdesired", bool(flags & RECURSION_DESIRED))
            if response:
                reader.add("dns.flags.recavail", bool(flags & RECURSION_AVAILABLE))
            reader.add("dns.flags.z", bool(flags & Z))
            if response:
                reader.add("dns.flags.authenticated", bool(flags & AUTHENTICATED))
            elif flags & AUTHENTICATED:
                # In a question the same bit asks for authenticated data
                # rather than reporting it, which Wireshark names differently.
                reader.add("dns.flags.ad", True)
            reader.add("dns.flags.checkdisable", bool(flags & CHECKING_DISABLED))
            if response:
                reader.add("dns.flags.rcode", flags & RCODE)

    def _questions(self, reader: Reader, message: bytes, start: int, count: int) -> list[str]:
        """What was asked, and how the packet list describes it."""
        notes = []
        for _ in range(count):
            name, _ = self._name(reader, message, start, "dns.qry.name")
            with reader.inside():
                reader.add("dns.qry.name.len", len(name) if name != ROOT else 0)
                reader.add("dns.count.labels", name.count(".") + 1 if name != ROOT else 0)
            kind = reader.uint16("dns.qry.type")
            offset = reader.buffer.offset
            asked_class = reader.buffer.uint(2, name="dns.qry.class")
            if self.multicast:
                reader.add(
                    "dns.qry.class", asked_class & ~UNICAST_RESPONSE, offset=offset, length=2
                )
                with reader.inside():
                    reader.add("dns.qry.qu", bool(asked_class & UNICAST_RESPONSE))
            else:
                reader.add("dns.qry.class", asked_class, offset=offset, length=2)
            note = f" {_type_name(kind)} {name}"
            if self.multicast:
                # Whether the asker wants the answer sent to the whole group
                # or straight back to it.
                unicast = "QU" if asked_class & UNICAST_RESPONSE else "QM"
                note += f', "{unicast}" question'
            notes.append(note)
        return notes

    def _records(self, reader: Reader, message: bytes, start: int, count: int) -> list[str]:
        """One section of resource records, and what they say."""
        notes = []
        for _ in range(count):
            # Which fields the owner name goes in depends on the type that
            # follows it, so the type is looked at before the name is added.
            offset = reader.buffer.offset
            name, length = read_name(message, offset - start)
            reader.skip(length, "dns.resp.name")
            upcoming = int.from_bytes(reader.buffer.peek(2, "dns.resp.type"), "big")
            if upcoming == SRV and name:
                self._service(reader, name or ROOT, offset, length)
            else:
                reader.add("dns.resp.name", name or ROOT, offset=offset, length=length)
            kind = reader.uint16("dns.resp.type")
            offset = reader.buffer.offset
            record_class = reader.buffer.uint(2, name="dns.resp.class")
            if self.multicast:
                reader.add("dns.resp.class", record_class & ~CACHE_FLUSH, offset=offset, length=2)
                with reader.inside():
                    reader.add("dns.resp.cache_flush", bool(record_class & CACHE_FLUSH))
            else:
                reader.add("dns.resp.class", record_class, offset=offset, length=2)
            reader.uint32("dns.resp.ttl")
            length = reader.uint16("dns.resp.len")
            end = reader.buffer.offset + length
            said = self._data(reader, message, start, kind, length)
            # Whatever the data held, the next record starts after it.
            reader.skip(max(end - reader.buffer.offset, 0), "dns.resp")
            flush = ", cache flush" if self.multicast and record_class & CACHE_FLUSH else ""
            notes.append(f" {_type_name(kind)}{flush}{said}")
        return notes

    def _data(self, reader: Reader, message: bytes, start: int, kind: int, length: int) -> str:
        """One record's data, by type, and how the packet list says it."""
        if kind == 1 and length == 4:
            return f" {reader.ipv4('dns.a')}"
        if kind == 28 and length == 16:
            return f" {reader.ipv6('dns.aaaa')}"
        if kind in _NAMED:
            name, _ = self._name(reader, message, start, _NAMED[kind])
            return f" {name}"
        if kind == 15:
            preference = reader.uint16("dns.mx.preference")
            name, _ = self._name(reader, message, start, "dns.mx.mail_exchange")
            return f" {preference} {name}"
        if kind == 16:
            self._texts(reader, length)
            return ""
        if kind == SRV:
            numbers = [
                reader.uint16(each)
                for each in ("dns.srv.priority", "dns.srv.weight", "dns.srv.port")
            ]
            name, _ = self._name(reader, message, start, "dns.srv.target")
            return f" {numbers[0]} {numbers[1]} {numbers[2]} {name}"
        if kind == 6:
            self._name(reader, message, start, "dns.soa.mname")
            self._name(reader, message, start, "dns.soa.rname")
            for name in _SOA_TIMES:
                reader.uint32(name)
            return ""
        return ""

    @staticmethod
    def _service(reader: Reader, name: str, offset: int, length: int) -> None:
        """The owner name of an SRV record, which is really three or four names.

        A service that something can be found at is named
        ``_service._proto.where``, and a particular instance of one, the way
        Bonjour names them, puts the instance in front of that. Wireshark
        splits the name up either way, and names the pieces rather than the
        whole, which is what the fields below follow.
        """
        parts = name.split(".", 3)
        if len(parts) >= 3 and parts[2].startswith("_"):
            named = zip(
                ("dns.srv.instance", "dns.srv.service", "dns.srv.proto"), parts, strict=False
            )
            rest = parts[3:]
        else:
            named = zip(("dns.srv.service", "dns.srv.proto"), parts, strict=False)
            rest = [".".join(parts[2:])] if len(parts) > 2 else []
        for field_name, part in named:
            reader.add(field_name, part, offset=offset, length=length)
        for part in rest:
            reader.add("dns.srv.name", part, offset=offset, length=length)

    @staticmethod
    def _texts(reader: Reader, length: int) -> None:
        """A TXT record, which is one or more length-prefixed strings."""
        end = reader.buffer.offset + length
        while reader.buffer.offset < end:
            size = reader.uint8("dns.txt.length")
            reader.string("dns.txt", min(size, max(end - reader.buffer.offset, 0)))

    @staticmethod
    def _name(reader: Reader, message: bytes, start: int, field_name: str) -> tuple[str, int]:
        """Read one name, following its pointers but stepping over only its own bytes."""
        offset = reader.buffer.offset
        name, length = read_name(message, offset - start)
        reader.skip(length, field_name)
        shown = name or ROOT
        reader.add(field_name, shown, offset=offset, length=length)
        return shown, length

    def _match(self, reader: Reader, context: Context, identifier: int, response: bool) -> None:
        """Tie a response to the question it answers, as Wireshark does.

        The pair is found by the transaction number and the two ends, with the
        server end first so that a question and its answer come out the same
        way round. A response nobody asked for gets said so: multicast DNS is
        full of them, because a Mac announces what it has whether or not
        anything asked.
        """
        questions = context.session.store(self.name, Questions)
        ends = (context.source, context.destination)
        if not response:
            ends = (context.destination, context.source)
        key = (identifier, str(ends[0]), str(ends[1]))
        when = context.packet.timestamp_ns or 0
        if not response:
            questions.asked[key] = Asked(context.number, when)
            return
        question = questions.asked.get(key)
        if question is None:
            reader.add("dns.unsolicited", True)
            return
        reader.add("dns.response_to", question.frame)
        reader.add("dns.time", when - question.time)


@register(UDP_PORT, MDNS_PORT)
class Mdns(Dns):
    """The same messages, sent to a group address so everyone on the link hears.

    A Mac announces itself this way all day: printers, AirPlay targets and
    file shares all find each other with it. The format is DNS's, with two of
    the class bits taken over for the questions and answers of a protocol
    where nobody is in charge.
    """

    name = "mdns"
    title = "Multicast Domain Name System"
    multicast = True


_COUNTS = ("dns.count.queries", "dns.count.answers", "dns.count.auth_rr", "dns.count.add_rr")

# The record types whose data is one name, by the field that name goes in.
_NAMED = {2: "dns.ns", 5: "dns.cname", 12: "dns.ptr.domain_name"}

_SOA_TIMES = (
    "dns.soa.serial_number",
    "dns.soa.refresh_interval",
    "dns.soa.retry_interval",
    "dns.soa.expire_limit",
    "dns.soa.minimum_ttl",
)

_RCODES = {
    1: "Format error",
    2: "Server failure",
    3: "No such name",
    4: "Not implemented",
    5: "Refused",
    6: "Name exists",
    7: "RRset exists",
    8: "RRset does not exist",
    9: "Not authoritative",
    10: "Name out of zone",
    11: "DSO-Type not implemented",
}


def _type_name(kind: int) -> str:
    return TYPES.get(kind, f"Unknown ({kind})")
