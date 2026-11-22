"""Constant-expression evaluation for array dimensions and alignment."""

from .errors import LayoutUnsupportedError, Location


class ConstantEvaluator:
    """Evaluates integer constant expressions using enum constants.

    Only constant folding is supported; identifiers that are not enum
    enumerators raise LayoutUnsupportedError so the caller can treat the
    declaration as needing manual review rather than guessing a size.
    """

    def __init__(self, enum_constants):
        self._enums = dict(enum_constants)

    def evaluate(self, node):
        if node is None:
            raise LayoutUnsupportedError(
                "unsized array has no constant dimension", None)
        try:
            handler = getattr(self, "_" + type(node).__name__)
        except AttributeError:
            raise LayoutUnsupportedError(
                "non-constant expression in size/dimension",
                Location.from_coord(node.coord, "<input>"))
        return handler(node)

    def _Constant(self, node):
        text = node.value
        try:
            return int(text.rstrip("lLuU"), 0)
        except ValueError:
            raise LayoutUnsupportedError(
                "unsupported constant %r" % text,
                Location.from_coord(node.coord, "<input>"))

    def _Identifier(self, node):
        if node.name in self._enums:
            return self._enums[node.name]
        raise LayoutUnsupportedError(
            "non-constant identifier %r in size/dimension" % node.name,
            Location.from_coord(node.coord, "<input>"))

    def _ID(self, node):
        return self._Identifier(node)

    def _UnaryOp(self, node):
        value = self.evaluate(node.expr)
        if node.op == "-":
            return -value
        if node.op == "+":
            return value
        if node.op == "~":
            return ~value
        if node.op == "!":
            return int(not value)
        raise LayoutUnsupportedError(
            "operator %r not allowed in constant size" % node.op,
            Location.from_coord(node.coord, "<input>"))

    def _BinaryOp(self, node):
        left = self.evaluate(node.left)
        right = self.evaluate(node.right)
        op = node.op
        arithmetic = {
            "+": left + right, "-": left - right, "*": left * right,
            "/": left // right, "%": left % right, "&": left & right,
            "|": left | right, "^": left ^ right,
            "<<": left << right, ">>": left >> right,
            "&&": int(bool(left) and bool(right)),
            "||": int(bool(left) or bool(right)),
        }
        if op not in arithmetic:
            raise LayoutUnsupportedError(
                "operator %r not allowed in constant size" % op,
                Location.from_coord(node.coord, "<input>"))
        return arithmetic[op]

    def _Assignment(self, node):
        raise LayoutUnsupportedError(
            "assignment in constant size",
            Location.from_coord(node.coord, "<input>"))

    def _TernaryOp(self, node):
        cond = self.evaluate(node.cond)
        return self.evaluate(node.iftrue if cond else node.iffalse)

    def _Cast(self, node):
        return self.evaluate(node.expr)
