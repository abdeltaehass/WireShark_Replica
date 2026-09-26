"""A bounds-checked view of a packet's bytes."""

from collections.abc import Buffer as BytesLike

from pilotfish.core.dissect.errors import MalformedError


class Buffer:
    """The bytes of one packet, read from front to back.

    Every read moves a cursor and raises :class:`MalformedError` rather than
    returning less than was asked for, so a dissector can read a header
    field by field without checking the length at every step.

    Offsets count from the first byte of the packet even for a buffer holding
    a later part of it, so a field always knows where its bytes are in the
    packet. Reading copies nothing: the bytes stay in the capture file's
    mapping or the capture thread's buffer until a dissector asks for them.
    """

    __slots__ = ("_position", "_start", "_view")

    def __init__(self, data: BytesLike, start: int = 0) -> None:
        self._view = memoryview(data)
        self._start = start
        self._position = 0

    @property
    def offset(self) -> int:
        """Where the cursor is, counting from the packet's first byte."""
        return self._start + self._position

    @property
    def remaining(self) -> int:
        return len(self._view) - self._position

    @property
    def at_end(self) -> bool:
        return self._position >= len(self._view)

    def read(self, count: int, name: str = "") -> memoryview:
        """The next ``count`` bytes, or :class:`MalformedError` if they aren't there."""
        what = f"{name} needs" if name else "needed"
        if count < 0:
            # A header whose lengths don't add up can ask for this.
            raise MalformedError(f"{what} {count} bytes, which is not a length")
        end = self._position + count
        if end > len(self._view):
            raise MalformedError(
                f"{what} {count} bytes at offset {self.offset}, but the packet has {self.remaining}"
            )
        chunk = self._view[self._position : end]
        self._position = end
        return chunk

    def peek(self, count: int, name: str = "") -> bytes:
        """The next ``count`` bytes without moving the cursor.

        A dissector that has to look before it reads uses this: a checksum
        over a whole message, or a guess at what a payload holds.
        """
        chunk = bytes(self.read(count, name))
        self._position -= count
        return chunk

    def uint(self, count: int, *, little: bool = False, name: str = "") -> int:
        """An unsigned integer of ``count`` bytes, big-endian unless ``little``."""
        return int.from_bytes(self.read(count, name), "little" if little else "big")

    def skip(self, count: int, name: str = "") -> None:
        self.read(count, name)

    def take(self, count: int, name: str = "") -> "Buffer":
        """A buffer over the next ``count`` bytes, moving this one past them."""
        chunk = self.read(count, name)
        return Buffer(chunk, self.offset - count)

    def rest(self) -> "Buffer":
        """A buffer over everything left, moving this one to the end."""
        return self.take(self.remaining)

    def __repr__(self) -> str:
        return f"Buffer(offset={self.offset}, remaining={self.remaining})"
