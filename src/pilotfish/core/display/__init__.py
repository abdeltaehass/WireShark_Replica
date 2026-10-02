"""Display filters: picking packets by what they decoded into.

A display filter is an expression over field names, such as
``tcp.port == 443 and not ip.addr == 10.0.0.0/8``, in Wireshark's syntax. It
is compiled once and then asked about each packet's protocol tree, which
makes this a small compiler in four stages, one module each:

- :mod:`lexer` cuts the text into tokens;
- :mod:`parser` builds a syntax tree from them;
- :mod:`checker` resolves every word against the field registry and checks
  the types, giving a typed tree;
- :mod:`evaluate` walks that tree for each packet, and :mod:`codegen` turns
  it into a Python function that does the same thing faster.

Whatever is wrong with a filter is a :class:`DisplayFilterError` that says
which characters it is about.

A capture filter, in :mod:`pilotfish.core.filters`, decides what is captured
at all and runs in the kernel on raw bytes. A display filter runs here, on
packets that have already been decoded, so it can ask about anything a
dissector worked out.
"""

from pilotfish.core.display import syntax, typed
from pilotfish.core.display.checker import check
from pilotfish.core.display.codegen import Compiled, compile_test
from pilotfish.core.display.errors import DisplayFilterError
from pilotfish.core.display.evaluate import test
from pilotfish.core.display.parser import parse
from pilotfish.core.display.runtime import gather
from pilotfish.core.dissect import REGISTRY, FieldRegistry, ProtocolTree

__all__ = ["DisplayFilter", "DisplayFilterError", "compile_display_filter"]


class DisplayFilter:
    """A compiled display filter.

    Ask it about a packet with :meth:`matches`, passing the packet's tree and
    its bytes. The bytes are what a filter on a protocol's contents looks
    through, such as ``frame contains "password"``.
    """

    __slots__ = ("_compiled", "constants", "names", "source", "syntax", "text", "typed")

    def __init__(
        self,
        text: str,
        tree: syntax.Expression | None,
        test: typed.Test | None,
        names: frozenset[str],
    ) -> None:
        self.text = text
        self.syntax = tree
        """The syntax tree, or ``None`` for a filter with nothing in it."""
        self.typed = test
        self.names = names
        """Every field name the filter looks up in a tree."""
        self._compiled: Compiled | None = None
        self.source = ""
        """The Python the filter was compiled to."""
        self.constants: dict[str, object] = {}
        """The values that Python refers to by name: addresses, patterns, sets."""
        if test is not None:
            self._compiled, self.source, self.constants = compile_test(test)

    def matches(self, tree: ProtocolTree, data: bytes | memoryview = b"") -> bool:
        """Whether the packet passes, by running the generated function."""
        if self._compiled is None:
            return True
        return self._compiled(gather(tree, self.names), data)

    def walk(self, tree: ProtocolTree, data: bytes | memoryview = b"") -> bool:
        """Whether the packet passes, by walking the typed tree.

        The answer is always the one :meth:`matches` gives. This is the
        slower way, kept as the reference the generated code is tested
        against.
        """
        if self.typed is None:
            return True
        return test(self.typed, gather(tree, self.names), data)

    def __repr__(self) -> str:
        return f"DisplayFilter({self.text!r})"


def compile_display_filter(text: str, fields: FieldRegistry | None = None) -> DisplayFilter:
    """Compile a filter, or raise :class:`DisplayFilterError` saying where it is wrong.

    The fields it may name are those in ``fields``, which is every field
    pilotfish decodes unless another registry is given. A filter with nothing
    in it passes every packet.
    """
    if fields is None:
        # The dissectors register their fields as they are imported.
        import pilotfish.core.protocols  # noqa: F401

        fields = REGISTRY.fields
    tree = parse(text)
    if tree is None:
        return DisplayFilter(text, None, None, frozenset())
    checked, names = check(tree, text, fields)
    return DisplayFilter(text, tree, checked, names)
