"""Reading a literal as the kind of value it is compared with.

``80`` is a number beside ``tcp.port``, one byte beside ``eth.src[0]`` and
nothing at all beside ``ip.src``. So a literal is only read once the type
checker knows what it is being compared with, and that is what these
functions do: given the kind wanted, they return the value or say exactly
what is wrong with it.
"""

import re
from calendar import monthrange
from datetime import UTC, datetime, timedelta
from ipaddress import AddressValueError, IPv4Address, IPv6Address
from string import hexdigits, octdigits

from pilotfish.core.display.syntax import Character, Literal, String, Word
from pilotfish.core.display.typed import Block, Constant, Kind
from pilotfish.core.timestamps import NS_PER_SECOND

TRUE = frozenset({"true", "True", "TRUE"})
FALSE = frozenset({"false", "False", "FALSE"})

MAC_BYTES = 6

_DATE = re.compile(
    r"\s*(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?"
    r"\s*(Z|UTC|[+-]\d{2}:?\d{2})?\s*"
)

# The parts of a date in the order they are written, with what each is called
# and the most it can be. A day's limit depends on its month.
_DATE_PARTS = (
    ("a year", 1, 9999),
    ("a month", 1, 12),
    ("a day of that month", 1, 31),
    ("an hour", 0, 23),
    ("a minute", 0, 59),
    ("a second", 0, 59),
)
_SECONDS = re.compile(r"([+-]?)(\d+)(?:\.(\d{1,9}))?")


QUOTED = frozenset({Kind.TEXT, Kind.BYTES, Kind.TIME})
"""The kinds a quoted string can be read as. A date is written as one."""


class LiteralError(Exception):
    """A literal can't be read as the kind wanted.

    ``start`` and ``end`` say which part of it is wrong, counted from its
    first character, when it is narrower than the whole of it.
    """

    def __init__(self, message: str, start: int = 0, end: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.start = start
        self.end = end


def convert(literal: Literal, kind: Kind, subject: str) -> Constant | Block:
    """``literal`` as a value of ``kind``.

    ``subject`` is what it is being compared with, as the filter wrote it,
    for the message when it can't be.
    """
    if isinstance(literal, String) and kind not in QUOTED:
        raise _quoted(literal, kind, subject)
    match kind:
        case Kind.NUMBER:
            return Constant(_number(literal, subject), kind)
        case Kind.FLAG:
            return Constant(_flag(literal, subject), kind)
        case Kind.TIME:
            return Constant(_time(literal, subject), kind)
        case Kind.TEXT:
            return Constant(_text(literal, subject), kind)
        case Kind.BYTES:
            return Constant(_bytes(literal), kind)
        case Kind.ETHERNET:
            return Constant(_ethernet(literal, subject), kind)
        case Kind.IPV4:
            return _ipv4(literal, subject)
        case Kind.IPV6:
            return _ipv6(literal, subject)


def _quoted(literal: String, kind: Kind, subject: str) -> LiteralError:
    """A quoted string where the value is never written as one.

    Usually the value inside the quotes is right and only the quotes are
    wrong, so say so when that is the case.
    """
    message = f"{subject} is {kind}, and {_shown(literal)} is text"
    try:
        convert(Word(literal.value.decode(), literal.span), kind, subject)
    except (LiteralError, UnicodeDecodeError):
        return LiteralError(message)
    return LiteralError(f"{message}; write it without the quotes")


def integer(text: str) -> int | None:
    """A whole number as C writes one, or ``None`` if ``text`` isn't one.

    Decimal, ``0x`` hexadecimal, ``0b`` binary, and octal for anything else
    that starts with a zero, which is how Wireshark reads them too.
    """
    sign = -1 if text.startswith("-") else 1
    digits = text[1:] if text[:1] in {"+", "-"} else text
    prefix, body = digits[:2].lower(), digits[2:]
    if prefix == "0x":
        base, allowed = 16, hexdigits
    elif prefix == "0b":
        base, allowed = 2, "01"
    elif len(digits) > 1 and digits.startswith("0"):
        base, allowed, body = 8, octdigits, digits[1:]
    else:
        base, allowed, body = 10, "0123456789", digits
    if not body or any(digit not in allowed for digit in body):
        return None
    return sign * int(body, base)


def _number(literal: Literal, subject: str) -> int:
    match literal:
        case Character(value=value):
            return value
        case String():
            raise _quoted(literal, Kind.NUMBER, subject)
        case Word(text=text):
            number = integer(text)
            if number is not None:
                return number
            digits = text.lstrip("+-")
            if len(digits) > 1 and digits[0] == "0" and digits.isdecimal():
                # 080 looks like eighty and reads as octal, where 8 isn't a digit.
                bad = next(index for index, digit in enumerate(text) if digit in "89")
                raise LiteralError(
                    f'"{text}" starts with 0, which makes it octal, '
                    f"and {text[bad]} isn't an octal digit",
                    bad,
                    bad + 1,
                )
            if _SECONDS.fullmatch(text):
                raise LiteralError(f"{subject} is a whole number, and {text} isn't one")
            raise LiteralError(f'{subject} is a number, and "{text}" isn\'t one')


def _flag(literal: Literal, subject: str) -> bool:
    if isinstance(literal, Word):
        if literal.text in TRUE:
            return True
        if literal.text in FALSE:
            return False
        value = integer(literal.text)
        if value is not None:
            return value != 0
    raise LiteralError(
        f"{subject} is true or false; compare it with true, false, 1 or 0, not {_shown(literal)}"
    )


def _time(literal: Literal, subject: str) -> int:
    """Nanoseconds: seconds with a fraction, or a date and time, which is
    taken as UTC unless it says otherwise."""
    if not isinstance(literal, Character):
        text = _decoded(literal) if isinstance(literal, String) else literal.text
        seconds = _SECONDS.fullmatch(text)
        if seconds and isinstance(literal, Word):
            sign, whole, fraction = seconds.groups()
            value = int(whole) * NS_PER_SECOND + int((fraction or "").ljust(9, "0"))
            return -value if sign == "-" else value
        date = _DATE.fullmatch(text)
        if date:
            return _date(date)
    raise LiteralError(
        f"{subject} is a time; write seconds, such as 1700000000.5, "
        f'or a date, such as "2023-11-14 22:13:20", not {_shown(literal)}'
    )


def _date(match: re.Match[str]) -> int:
    """A date and time as nanoseconds, or which part of it there is no such thing as."""
    parts = [int(match.group(group)) for group in range(1, 7)]
    for group, (name, least, most) in enumerate(_DATE_PARTS, start=1):
        if group == 3:
            most = monthrange(parts[0], parts[1])[1]
        if not least <= parts[group - 1] <= most:
            raise LiteralError(f"{match.group(group)} isn't {name}", *match.span(group))
    year, month, day, hour, minute, second = parts
    moment = datetime(year, month, day, hour, minute, second, tzinfo=UTC)
    fraction, zone = match.group(7), match.group(8)
    if zone and zone[0] in "+-":
        hours, minutes = int(zone[1:3]), int(zone[-2:])
        if hours > 23 or minutes > 59:
            raise LiteralError(f"{zone} isn't a distance from UTC", *match.span(8))
        offset = timedelta(hours=hours, minutes=minutes)
        moment -= offset if zone[0] == "+" else -offset
    seconds = (moment - datetime(1970, 1, 1, tzinfo=UTC)) // timedelta(seconds=1)
    return seconds * NS_PER_SECOND + int((fraction or "").ljust(9, "0"))


def _text(literal: Literal, subject: str) -> str:
    match literal:
        case String():
            return _decoded(literal)
        case Character():
            raise LiteralError(
                f"{subject} is text, and single quotes spell a number; text goes in double quotes"
            )
        case Word(text=text):
            # Wireshark takes a bare word as text too, so `http.request.method
            # == GET` works, but not a bare number, which is likelier a slip.
            if integer(text) is not None or _SECONDS.fullmatch(text):
                raise LiteralError(
                    f'{subject} is text; to compare it with the text "{text}", write it in quotes'
                )
            return text


def _bytes(literal: Literal) -> bytes:
    """Bytes as they are written: ``00:1a:2b``, ``00-1a-2b``, ``001a2b``, a
    number that fits in one byte, or the bytes of a quoted string."""
    match literal:
        case String(value=value):
            return value
        case Character(value=value):
            return bytes([value])
        case Word(text=text):
            separator = next((each for each in ":-" if each in text.strip("+-")), None)
            if separator is not None:
                # 45: and :45 are how to write one byte in hexadecimal, since
                # 45 alone is the number forty-five.
                body = text.removeprefix(separator).removesuffix(separator)
                return _pairs(body.split(separator), text.index(body))
            number = integer(text)
            if number is not None:
                if not 0 <= number <= 0xFF:
                    raise LiteralError(f"{text} doesn't fit in one byte; write several as 00:1a:2b")
                return bytes([number])
            if len(text) % 2 == 0 and all(digit in hexdigits for digit in text):
                return bytes.fromhex(text)
            raise LiteralError(
                f'"{text}" isn\'t bytes; write them in hexadecimal, such as 00:1a:2b, '
                "or as text in quotes"
            )


def _pairs(parts: list[str], start: int) -> bytes:
    """Bytes from the pieces between separators, each two hexadecimal digits.

    ``start`` is where the first piece is in the literal, for pointing at
    the one that is wrong.
    """
    for part in parts:
        if len(part) != 2 or any(digit not in hexdigits for digit in part):
            raise LiteralError(
                f'"{part}" isn\'t a byte; each one is two hexadecimal digits, as in 00:1a:2b',
                start,
                start + max(len(part), 1),
            )
        start += len(part) + 1
    return bytes.fromhex("".join(parts))


def _ethernet(literal: Literal, subject: str) -> str:
    """An address as dissectors record one: ``00:1a:2b:3c:4d:5e``."""
    if not isinstance(literal, Word):
        raise LiteralError(
            f"{subject} is an Ethernet address, such as 00:1a:2b:3c:4d:5e, "
            f"and {_shown(literal)} isn't one"
        )
    text = literal.text
    if text.count(".") == 2 and all(len(part) == 4 for part in text.split(".")):
        # The way Cisco writes them: 001a.2b3c.4d5e.
        compact = text.replace(".", "")
        if all(digit in hexdigits for digit in compact):
            return bytes.fromhex(compact).hex(":")
    separator = "-" if "-" in text else ":"
    if separator not in text:
        raise LiteralError(
            f'{subject} is an Ethernet address, such as 00:1a:2b:3c:4d:5e, and "{text}" isn\'t one'
        )
    address = _pairs(text.split(separator), 0)
    if len(address) != MAC_BYTES:
        raise LiteralError(
            f"{subject} is an Ethernet address, which is six bytes, "
            f'and "{text}" is {len(address)}; '
            f"to compare part of it, slice it: {subject}[0:{len(address)}]"
        )
    return address.hex(":")


def _ipv4(literal: Literal, subject: str) -> Constant | Block:
    if not isinstance(literal, Word):
        raise LiteralError(f"{subject} is an IPv4 address, and {_shown(literal)} isn't one")
    text = literal.text
    address, slash, prefix = text.partition("/")
    parts = address.split(".")
    wrong = LiteralError(f'{subject} is an IPv4 address, and "{text}" isn\'t one')
    if len(parts) != 4:
        raise wrong
    value = 0
    position = 0
    for part in parts:
        if not (part.isascii() and part.isdecimal()) or (len(part) > 1 and part[0] == "0"):
            raise wrong
        if int(part) > 0xFF:
            raise LiteralError(
                f"{subject} is an IPv4 address, and {part} is too large for a part of one: "
                "each is 0 to 255",
                position,
                position + len(part),
            )
        value = value << 8 | int(part)
        position += len(part) + 1
    if not slash:
        return Constant(IPv4Address(value), Kind.IPV4)
    bits = _prefix(text, prefix, 32, "IPv4")
    span = (1 << (32 - bits)) - 1
    first = value & ~span
    if bits == 32:
        return Constant(IPv4Address(first), Kind.IPV4)
    return Block(IPv4Address(first), IPv4Address(first | span), Kind.IPV4)


def _ipv6(literal: Literal, subject: str) -> Constant | Block:
    if not isinstance(literal, Word):
        raise LiteralError(f"{subject} is an IPv6 address, and {_shown(literal)} isn't one")
    text = literal.text
    address, slash, prefix = text.partition("/")
    try:
        value = int(IPv6Address(address))
    except AddressValueError:
        raise LiteralError(f'{subject} is an IPv6 address, and "{text}" isn\'t one') from None
    if not slash:
        return Constant(IPv6Address(value), Kind.IPV6)
    bits = _prefix(text, prefix, 128, "IPv6")
    span = (1 << (128 - bits)) - 1
    first = value & ~span
    if bits == 128:
        return Constant(IPv6Address(first), Kind.IPV6)
    return Block(IPv6Address(first), IPv6Address(first | span), Kind.IPV6)


def _prefix(text: str, prefix: str, most: int, family: str) -> int:
    """How many bits of an address a subnet fixes: the number after the slash."""
    start = len(text) - len(prefix)
    if not prefix:
        raise LiteralError(
            f"a number of bits goes after this slash, from 0 to {most}", start - 1, start
        )
    if not (prefix.isascii() and prefix.isdecimal()) or int(prefix) > most:
        raise LiteralError(
            f'an {family} prefix is 0 to {most} bits, not "{prefix}"', start, len(text)
        )
    return int(prefix)


def _decoded(literal: String) -> str:
    try:
        return literal.value.decode()
    except UnicodeDecodeError:
        raise LiteralError("these escapes don't spell text: they aren't valid UTF-8") from None


def _shown(literal: Literal) -> str:
    """A literal as an error quotes it."""
    match literal:
        case Word(text=text):
            return f'"{text}"'
        case String(value=value):
            return '"' + value.decode(errors="replace") + '"'
        case Character(value=value):
            return f"'{chr(value)}'"
