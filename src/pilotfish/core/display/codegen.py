"""Compiling a filter to a Python function.

Walking the typed tree asks the same questions of every packet: what kind of
node is this, which operator, any value or every value. The answers never
change, so this module asks them once and writes down what is left. The
filter ``tcp.port == 80 and not dns`` becomes::

    lambda found, data: (
        any(n0.value == 80 for n0 in found['tcp.srcport'] + found['tcp.dstport'])
        and not found['dns'] != []
    )

It is built as a Python syntax tree with the :mod:`ast` module, not as text,
and handed to :func:`compile`. Nothing from the filter is ever spliced into
source code, so there is nothing in a filter that can run as Python: its
values go in as constants, and its field names only as dictionary keys.
"""

import ast
from collections.abc import Callable

from pilotfish.core.display import typed
from pilotfish.core.display.runtime import Found, Ranges, cut, every, layer, mac
from pilotfish.core.display.typed import Kind

type Compiled = Callable[[Found, bytes | memoryview], bool]

type Stream = tuple[ast.expr, list[ast.comprehension]]
"""An operand's values, as code: an expression for one value, and the loops
that have to run around it to produce them all. A constant has no loops."""

OPERATORS: dict[str, ast.cmpop] = {
    "==": ast.Eq(),
    "!=": ast.NotEq(),
    "<": ast.Lt(),
    "<=": ast.LtE(),
    ">": ast.Gt(),
    ">=": ast.GtE(),
}

HELPERS: dict[str, object] = {"_layer": layer, "_mac": mac, "_cut": cut, "_every": every}
"""What the generated code calls, besides the two builtins it is given."""


def compile_test(test: typed.Test) -> tuple[Compiled, str, dict[str, object]]:
    """The filter as a function of a packet's fields and bytes.

    With it come its source, and the values the source refers to by name
    because Python has no way to write them in place.
    """
    generator = Generator()
    function = ast.Lambda(
        args=ast.arguments(
            posonlyargs=[],
            args=[ast.arg(arg="found"), ast.arg(arg="data")],
            kwonlyargs=[],
            kw_defaults=[],
            defaults=[],
        ),
        body=generator.test(test),
    )
    tree = ast.fix_missing_locations(ast.Expression(body=function))
    namespace = {"__builtins__": {"any": any, "len": len}, **HELPERS, **generator.constants}
    compiled: Compiled = eval(compile(tree, "<display filter>", "eval"), namespace)
    return compiled, ast.unparse(tree), generator.constants


class Generator:
    def __init__(self) -> None:
        self.constants: dict[str, object] = {}
        """Values that can't be written as a literal, by the name the code
        refers to them by: addresses, compiled patterns, sets."""
        self._variables = 0

    def test(self, node: typed.Test) -> ast.expr:
        """An expression that is ``True`` or ``False``, and exactly that."""
        match node:
            case typed.And(tests=tests):
                return ast.BoolOp(op=ast.And(), values=[self.test(each) for each in tests])
            case typed.Or(tests=tests):
                return ast.BoolOp(op=ast.Or(), values=[self.test(each) for each in tests])
            case typed.Xor(left=left, right=right):
                # Both sides are booleans, and two booleans differ exactly
                # when one of them is true.
                return _compare(self.test(left), ast.NotEq(), self.test(right))
            case typed.Not(test=inner):
                return ast.UnaryOp(op=ast.Not(), operand=self.test(inner))
            case typed.Exists(names=names):
                present = [
                    _compare(_nodes((name,)), ast.NotEq(), ast.List(elts=[], ctx=ast.Load()))
                    for name in names
                ]
                return present[0] if len(present) == 1 else ast.BoolOp(op=ast.Or(), values=present)
            case typed.Present(operand=operand):
                _, loops = self.operand(operand)
                return _quantified(ast.Constant(value=True), loops, all_of=False)
            case typed.NonZero(operand=operand):
                value, loops = self.operand(operand)
                return _quantified(
                    _compare(value, ast.NotEq(), ast.Constant(value=0)), loops, all_of=False
                )
            case typed.Compare(operator=operator, left=left, right=right, every=all_of):
                left_value, left_loops = self.operand(left)
                right_value, right_loops = self.operand(right)
                if operator == "contains":
                    condition = _compare(right_value, ast.In(), left_value)
                else:
                    condition = _compare(left_value, OPERATORS[operator], right_value)
                return _quantified(condition, left_loops + right_loops, all_of)
            case typed.Matches(operand=operand, pattern=pattern, every=all_of):
                value, loops = self.operand(operand)
                search = ast.Attribute(value=self._constant(pattern), attr="search", ctx=ast.Load())
                found = ast.Call(func=search, args=[value], keywords=[])
                condition = _compare(found, ast.IsNot(), ast.Constant(value=None))
                return _quantified(condition, loops, all_of)
            case typed.InSet(operand=operand, every=all_of):
                value, loops = self.operand(operand)
                return _quantified(self._inside(value, loops, node), loops, all_of)

    def _inside(
        self, value: ast.expr, loops: list[ast.comprehension], node: typed.InSet
    ) -> ast.expr:
        """Whether ``value`` is in the set: one of its values, or within a range."""
        if not isinstance(value, ast.Name) and bool(node.values) + len(node.ranges) > 1:
            # The value is asked about more than once, so work it out once.
            name = self._variable("v")
            loops.append(_loop(name, ast.Tuple(elts=[value], ctx=ast.Load())))
            value = _name(name)
        parts: list[ast.expr] = []
        if len(node.values) == 1:
            (only,) = node.values
            parts.append(_compare(value, ast.Eq(), self._constant(only)))
        elif node.values:
            parts.append(_compare(value, ast.In(), self._constant(node.values)))
        for low, high in node.ranges:
            parts.append(
                ast.Compare(
                    left=self._constant(low),
                    ops=[ast.LtE(), ast.LtE()],
                    comparators=[value, self._constant(high)],
                )
            )
        inside = parts[0] if len(parts) == 1 else ast.BoolOp(op=ast.Or(), values=parts)
        return ast.UnaryOp(op=ast.Not(), operand=inside) if node.negated else inside

    def operand(self, node: typed.Operand) -> Stream:
        match node:
            case typed.Constant(value=value):
                return self._constant(value), []
            case typed.FieldValues(names=names):
                name = self._variable("n")
                return _attribute(_name(name), "value"), [_loop(name, _nodes(names))]
            case typed.LayerBytes(names=names):
                name = self._variable("n")
                return _call("_layer", _name(name), _name("data")), [_loop(name, _nodes(names))]
            case typed.AsBytes(operand=operand):
                inner, loops = self.operand(operand)
                if operand.kind is Kind.ETHERNET:
                    return _call("_mac", inner), loops
                if operand.kind is Kind.TEXT:
                    return _method(inner, "encode"), loops
                return _attribute(inner, "packed"), loops
            case typed.Sliced(operand=operand, ranges=ranges):
                inner, loops = self.operand(operand)
                name = self._variable("s")
                # The slice gives one value or none, so looping over what it
                # gives is how a slice that doesn't fit drops out.
                pieces = _call("_cut", inner, _ranges(ranges))
                return _name(name), [*loops, _loop(name, pieces)]
            case typed.Length(operand=operand):
                inner, loops = self.operand(operand)
                if operand.kind is Kind.TEXT:
                    inner = _method(inner, "encode")
                return _call("len", inner), loops
            case typed.Count(names=names):
                counts: list[ast.expr] = [_call("len", _nodes((name,))) for name in names]
                total = counts[0]
                for count in counts[1:]:
                    total = ast.BinOp(left=total, op=ast.Add(), right=count)
                return total, []
            case typed.Cased(operand=operand, upper=upper):
                inner, loops = self.operand(operand)
                return _method(inner, "upper" if upper else "lower"), loops
            case typed.BitAnd(left=left, right=right):
                left_value, left_loops = self.operand(left)
                right_value, right_loops = self.operand(right)
                both = ast.BinOp(left=left_value, op=ast.BitAnd(), right=right_value)
                return both, left_loops + right_loops

    def _constant(self, value: object) -> ast.expr:
        """A value from the filter: written in place if Python can spell it,
        and otherwise kept beside the code under a name."""
        if isinstance(value, int | str | bytes):
            return ast.Constant(value=value)
        # An address, a compiled pattern or a set.
        name = f"_k{len(self.constants)}"
        self.constants[name] = value
        return _name(name)

    def _variable(self, prefix: str) -> str:
        self._variables += 1
        return f"{prefix}{self._variables - 1}"


def _quantified(condition: ast.expr, loops: list[ast.comprehension], all_of: bool) -> ast.expr:
    """``condition`` asked of any of the values the loops produce, or of all of them."""
    if not loops:
        # Nothing varies, as in count(ip.addr) == 2, so there is one answer.
        return condition
    results = ast.GeneratorExp(elt=condition, generators=loops)
    return _call("_every" if all_of else "any", results)


def _nodes(names: tuple[str, ...]) -> ast.expr:
    """The packet's nodes for a field: ``found['tcp.srcport'] + found['tcp.dstport']``."""
    lists: list[ast.expr] = [
        ast.Subscript(value=_name("found"), slice=ast.Constant(value=name), ctx=ast.Load())
        for name in names
    ]
    together = lists[0]
    for each in lists[1:]:
        together = ast.BinOp(left=together, op=ast.Add(), right=each)
    return together


def _ranges(ranges: Ranges) -> ast.expr:
    """A slice's ranges, written out as the tuple of pairs they are."""
    pairs: list[ast.expr] = [
        ast.Tuple(elts=[ast.Constant(value=offset), ast.Constant(value=length)], ctx=ast.Load())
        for offset, length in ranges
    ]
    return ast.Tuple(elts=pairs, ctx=ast.Load())


def _loop(variable: str, over: ast.expr) -> ast.comprehension:
    target = ast.Name(id=variable, ctx=ast.Store())
    return ast.comprehension(target=target, iter=over, ifs=[], is_async=0)


def _compare(left: ast.expr, operator: ast.cmpop, right: ast.expr) -> ast.expr:
    return ast.Compare(left=left, ops=[operator], comparators=[right])


def _name(name: str) -> ast.expr:
    return ast.Name(id=name, ctx=ast.Load())


def _attribute(value: ast.expr, name: str) -> ast.expr:
    return ast.Attribute(value=value, attr=name, ctx=ast.Load())


def _call(function: str, *arguments: ast.expr) -> ast.expr:
    return ast.Call(func=_name(function), args=list(arguments), keywords=[])


def _method(value: ast.expr, name: str) -> ast.expr:
    return ast.Call(func=_attribute(value, name), args=[], keywords=[])
