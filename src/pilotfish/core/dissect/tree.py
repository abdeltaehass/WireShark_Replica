"""The protocol tree: what one packet decoded into."""

from collections.abc import Iterator
from dataclasses import dataclass, field

from pilotfish.core.dissect.fields import FieldType, Value


@dataclass(slots=True)
class Node:
    """One row of the tree: a protocol layer, or a field inside one.

    Every node knows the bytes it came from, which is what lets the detail
    view highlight them in the hex dump and lets a filter point at them.
    ``length`` is 0 for a field worked out from the capture rather than read
    from the packet, such as the frame number.
    """

    name: str
    """The registered field name, such as ``ip.src``, or a protocol's name."""
    label: str
    type: FieldType
    offset: int
    """Where the field's bytes start in the packet."""
    length: int
    value: Value | None = None
    """``None`` for a protocol layer, which is its fields rather than a value."""
    summary: str = ""
    """A layer's one-line description, such as ``Frame 1: 70 bytes captured``."""
    hex: bool = False
    """Whether to show the value in hexadecimal."""
    children: list["Node"] = field(default_factory=list)

    def walk(self) -> Iterator["Node"]:
        """This node, then everything under it."""
        yield self
        for child in self.children:
            yield from child.walk()


@dataclass(slots=True)
class ProtocolTree:
    """The layers one packet decoded into, outermost first."""

    layers: list[Node] = field(default_factory=list)
    info: str = ""
    """The one-line summary for the packet list."""
    protocol: str = ""
    """The protocol the packet is, for the packet list's column: the
    innermost one decoded, not counting a packet quoted inside an error."""
    error: str | None = None
    """Why decoding stopped early, if it did. The packet is marked malformed."""

    @property
    def protocols(self) -> tuple[str, ...]:
        """The layers' names, such as ``("frame", "eth", "ip", "udp")``."""
        return tuple(layer.name for layer in self.layers)

    def walk(self) -> Iterator[Node]:
        """Every node in the tree, depth first."""
        for layer in self.layers:
            yield from layer.walk()

    def find(self, name: str) -> Node | None:
        """The first node with this field name."""
        return next((node for node in self.walk() if node.name == name), None)

    def get(self, name: str) -> Value | None:
        """The first value of this field, or ``None`` if the packet has none."""
        node = self.find(name)
        return None if node is None else node.value

    def values(self, name: str) -> list[Value]:
        """Every value of this field, for one that can appear more than once."""
        return [node.value for node in self.walk() if node.name == name and node.value is not None]

    def __contains__(self, name: object) -> bool:
        return any(node.name == name for node in self.walk())
