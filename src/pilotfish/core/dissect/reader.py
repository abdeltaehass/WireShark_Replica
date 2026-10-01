"""Reading a header field by field, recording where each field came from."""

import contextlib
from collections.abc import Iterator
from ipaddress import IPv4Address, IPv6Address

from pilotfish.core.dissect.buffer import Buffer
from pilotfish.core.dissect.fields import Field, FieldRegistry, FieldType, Value
from pilotfish.core.dissect.tree import Node

_PYTHON_TYPES: dict[FieldType, type | tuple[type, ...]] = {
    # A layer has no value of its own, so nothing is a valid one.
    FieldType.PROTOCOL: (),
    FieldType.UINT: int,
    FieldType.INT: int,
    FieldType.BOOL: bool,
    FieldType.BYTES: (bytes, memoryview),
    FieldType.STRING: str,
    FieldType.IPV4: IPv4Address,
    FieldType.IPV6: IPv6Address,
    FieldType.ETHERNET: str,
    FieldType.TIME: int,
}


class Reader:
    """How a dissector reads its header.

    Each read names the field it is reading, so the tree ends up with the
    field's name, type and value, and the exact bytes behind it, without the
    dissector keeping track of offsets. The name must be one the dissector
    registered, and the read must match the type it registered, so a typo or
    a wrong type is a loud mistake rather than a quiet one.
    """

    __slots__ = ("_buffer", "_fields", "_last", "_length", "_node", "_parents")

    def __init__(self, protocol: Field, buffer: Buffer, fields: FieldRegistry) -> None:
        self._buffer = buffer
        self._fields = fields
        self._length: int | None = None
        self._node = Node(
            name=protocol.name,
            label=protocol.description,
            type=FieldType.PROTOCOL,
            offset=buffer.offset,
            length=0,
            source=buffer.source,
        )
        self._parents = [self._node]
        self._last: Node | None = None

    @property
    def buffer(self) -> Buffer:
        """The bytes this protocol is being read from."""
        return self._buffer

    @property
    def remaining(self) -> int:
        return self._buffer.remaining

    def uint(self, name: str, count: int, *, little: bool = False) -> int:
        """An unsigned integer of ``count`` bytes, big-endian unless ``little``."""
        offset = self._buffer.offset
        raw = self._buffer.read(count, name)
        value = int.from_bytes(raw, "little" if little else "big")
        self.add(name, value, offset=offset, length=count)
        return value

    def uint8(self, name: str) -> int:
        return self.uint(name, 1)

    def uint16(self, name: str, *, little: bool = False) -> int:
        return self.uint(name, 2, little=little)

    def uint32(self, name: str, *, little: bool = False) -> int:
        return self.uint(name, 4, little=little)

    def bytes(self, name: str, count: int) -> bytes:
        offset = self._buffer.offset
        value = bytes(self._buffer.read(count, name))
        self.add(name, value, offset=offset, length=count)
        return value

    def string(self, name: str, count: int, encoding: str = "ascii") -> str:
        offset = self._buffer.offset
        raw = self._buffer.read(count, name)
        value = bytes(raw).decode(encoding, errors="replace")
        self.add(name, value, offset=offset, length=count)
        return value

    def ipv4(self, name: str) -> IPv4Address:
        offset = self._buffer.offset
        value = IPv4Address(bytes(self._buffer.read(4, name)))
        self.add(name, value, offset=offset, length=4)
        return value

    def ipv6(self, name: str) -> IPv6Address:
        offset = self._buffer.offset
        value = IPv6Address(bytes(self._buffer.read(16, name)))
        self.add(name, value, offset=offset, length=16)
        return value

    def mac(self, name: str) -> str:
        offset = self._buffer.offset
        value = bytes(self._buffer.read(6, name)).hex(":")
        self.add(name, value, offset=offset, length=6)
        return value

    def add(
        self, name: str, value: Value, *, offset: int | None = None, length: int | None = None
    ) -> Node:
        """Record a field worked out rather than read straight from the packet.

        Without an offset and length, the field points at the same bytes as
        whatever it is inside: the byte of flags it came from, or, at the top
        of a layer, nothing at all, which is right for a field that isn't in
        the packet, such as the frame number.
        """
        parent = self._parents[-1]
        field = self._fields[name]
        expected = _PYTHON_TYPES[field.type]
        if not isinstance(value, expected):
            raise TypeError(f"{name} is a {field.type} field, not {type(value).__name__}")
        node = Node(
            name=field.name,
            label=field.description,
            type=field.type,
            offset=parent.offset if offset is None else offset,
            length=parent.length if length is None else length,
            value=value,
            hex=field.hex,
            digits=field.digits,
            source=self._buffer.source,
        )
        parent.children.append(node)
        self._last = node
        return node

    @contextlib.contextmanager
    def inside(self) -> Iterator[None]:
        """Hang the fields added in this block under the field just read.

        A byte of flags reads as one field, and each flag in it is added
        inside, pointing at the same byte.
        """
        if self._last is None:
            raise ValueError("nothing has been read for these fields to go inside")
        self._parents.append(self._last)
        try:
            yield
        finally:
            self._parents.pop()

    def skip(self, count: int, name: str = "") -> None:
        """Step over bytes this dissector doesn't decode."""
        self._buffer.skip(count, name)

    def payload(self, length: int | None = None) -> Buffer:
        """The bytes after this header, for whatever protocol carries on.

        Pass a ``length`` when the header says how much of what follows
        belongs to it, as an IPv4 total length does; a length past the end of
        what was captured gives what there is, which is what a capture cut
        short by a snapshot length looks like. This also ends the header: the
        layer covers the bytes read up to here.
        """
        if self._length is None:
            self._length = self._buffer.offset - self._node.offset
        remaining = self._buffer.remaining if length is None else length
        return self._buffer.take(min(remaining, self._buffer.remaining))

    def summarize(self, text: str) -> None:
        """Describe the layer in one line, the way Wireshark labels it."""
        self._node.summary = text

    def set_length(self, length: int) -> None:
        """Say how many bytes the layer covers, when it isn't what was read."""
        self._length = length

    def node(self) -> Node:
        """The finished layer, with everything read under it."""
        read = self._buffer.offset - self._node.offset
        self._node.length = read if self._length is None else self._length
        return self._node
