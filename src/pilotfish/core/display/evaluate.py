"""Running a filter by walking its typed tree.

This is the plain way to do it: for every packet, start at the root, work out
what kind of node it is, and recurse into its children. It is easy to read
and to trust, and it is what the generated code in
:mod:`pilotfish.core.display.codegen` is checked against, packet for packet.

Nothing here can fail on a filter that passed the type checker. The values
are ``Any`` to the static checker because the kinds were settled there, by
the same tree this walks.
"""

import operator
from collections.abc import Callable
from typing import Any

from pilotfish.core.display import typed
from pilotfish.core.display.runtime import Found, cut, every, layer, mac
from pilotfish.core.display.typed import Kind

COMPARISONS: dict[str, Callable[[Any, Any], bool]] = {
    "==": operator.eq,
    "!=": operator.ne,
    "<": operator.lt,
    "<=": operator.le,
    ">": operator.gt,
    ">=": operator.ge,
    "contains": operator.contains,
}

AS_BYTES: dict[Kind, Callable[[Any], bytes]] = {
    Kind.ETHERNET: mac,
    Kind.IPV4: lambda address: address.packed,
    Kind.IPV6: lambda address: address.packed,
    Kind.TEXT: str.encode,
}


def test(node: typed.Test, found: Found, data: bytes | memoryview) -> bool:
    """Whether a packet passes: ``found`` is its fields, ``data`` its bytes."""
    match node:
        case typed.And(tests=tests):
            return all(test(each, found, data) for each in tests)
        case typed.Or(tests=tests):
            return any(test(each, found, data) for each in tests)
        case typed.Xor(left=left, right=right):
            return test(left, found, data) != test(right, found, data)
        case typed.Not(test=inner):
            return not test(inner, found, data)
        case typed.Exists(names=names):
            return any(found[name] for name in names)
        case typed.Present(operand=operand):
            return bool(values(operand, found, data))
        case typed.NonZero(operand=operand):
            return any(value != 0 for value in values(operand, found, data))
        case typed.Compare(operator=name, left=left, right=right, every=all_of):
            compare = COMPARISONS[name]
            lefts = values(left, found, data)
            rights = values(right, found, data)
            results = (compare(a, b) for a in lefts for b in rights)
            return every(results) if all_of else any(results)
        case typed.Matches(operand=operand, pattern=pattern, every=all_of):
            results = (pattern.search(each) is not None for each in values(operand, found, data))
            return every(results) if all_of else any(results)
        case typed.InSet(operand=operand, every=all_of):
            results = (_inside(each, node) for each in values(operand, found, data))
            return every(results) if all_of else any(results)


def _inside(value: Any, node: typed.InSet) -> bool:
    """Whether one value is in the set, or isn't, if that is what was asked."""
    inside = value in node.values or any(low <= value <= high for low, high in node.ranges)
    return inside != node.negated


def values(node: typed.Operand, found: Found, data: bytes | memoryview) -> list[Any]:
    """Every value an operand has in this packet, which can be none."""
    match node:
        case typed.Constant(value=value):
            return [value]
        case typed.FieldValues(names=names):
            return [each.value for name in names for each in found[name]]
        case typed.LayerBytes(names=names):
            return [layer(each, data) for name in names for each in found[name]]
        case typed.AsBytes(operand=operand):
            convert = AS_BYTES[operand.kind]
            return [convert(each) for each in values(operand, found, data)]
        case typed.Sliced(operand=operand, ranges=ranges):
            return [piece for each in values(operand, found, data) for piece in cut(each, ranges)]
        case typed.Length(operand=operand):
            if operand.kind is Kind.TEXT:
                return [len(each.encode()) for each in values(operand, found, data)]
            return [len(each) for each in values(operand, found, data)]
        case typed.Count(names=names):
            return [sum(len(found[name]) for name in names)]
        case typed.Cased(operand=operand, upper=upper):
            change = str.upper if upper else str.lower
            return [change(each) for each in values(operand, found, data)]
        case typed.BitAnd(left=left, right=right):
            return [a & b for a in values(left, found, data) for b in values(right, found, data)]
