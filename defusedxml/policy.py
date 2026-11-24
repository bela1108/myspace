"""Document-wide XML parsing policy and cumulative resource budgets."""
from __future__ import absolute_import, division, print_function

import re

from .common import DefusedXmlException


BACKEND_ELEMENTTREE = "ElementTree"
BACKEND_SAX = "SAX"
BACKEND_PULLDOM = "pulldom"
BACKEND_MINIDOM = "minidom"
BACKEND_EXPATBUILDER = "expatbuilder"


class RejectionReason(object):
    """Stable machine-readable rejection reasons."""

    EXPANSION = "entity_expansion_limit_exceeded"
    DEPTH = "depth_limit_exceeded"
    BYTES = "byte_limit_exceeded"
    UNPARSED_ENTITY = "unparsed_entity_limit_exceeded"
    BACKEND = "backend_parser_rejected_document"


REASON_BY_METRIC = {
    "expansions": RejectionReason.EXPANSION,
    "depth": RejectionReason.DEPTH,
    "bytes": RejectionReason.BYTES,
    "unparsed_entities": RejectionReason.UNPARSED_ENTITY,
}


class PolicyRejected(DefusedXmlException):
    """A document was rejected by the shared parsing policy."""

    def __init__(
        self,
        reason,
        backend=None,
        metric=None,
        limit=None,
        used=None,
        detail=None,
        native_error=None,
        counts=None,
    ):
        super(PolicyRejected, self).__init__(reason)
        self.reason = reason
        self.backend = backend
        self.metric = metric
        self.limit = limit
        self.used = used
        self.detail = detail
        self.counts = dict(counts or {})
        if native_error is None:
            self.native_type = None
            self.native_message = None
        else:
            self.native_type = type(native_error).__name__
            self.native_message = str(native_error)

    @property
    def controlled_reason(self):
        parts = [self.reason]
        if self.backend:
            parts.append("backend=" + self.backend)
        if self.metric:
            parts.append("metric=" + self.metric)
        if self.limit is not None:
            parts.append("limit=" + repr(self.limit))
        if self.used is not None:
            parts.append("used=" + repr(self.used))
        if self.native_type:
            parts.append("native=" + self.native_type + ":" + (self.native_message or ""))
        if self.detail:
            parts.append("detail=" + self.detail)
        return "; ".join(parts)

    def to_dict(self):
        return {
            "reason": self.reason,
            "controlled_reason": self.controlled_reason,
            "backend": self.backend,
            "metric": self.metric,
            "limit": self.limit,
            "used": self.used,
            "detail": self.detail,
            "native_type": self.native_type,
            "native_message": self.native_message,
            "counts": dict(self.counts),
        }

    def __str__(self):
        return self.controlled_reason


class BudgetExceeded(PolicyRejected):
    """A cumulative budget was exceeded."""

    def __init__(self, metric, used, limit, backend=None, detail=None, counts=None):
        reason = REASON_BY_METRIC.get(metric, metric + "_limit_exceeded")
        super(BudgetExceeded, self).__init__(
            reason,
            backend=backend,
            metric=metric,
            limit=limit,
            used=used,
            detail=detail,
            counts=counts,
        )


EntityBudgetExceeded = BudgetExceeded
BudgetLimitExceeded = BudgetExceeded
BudgetExceededError = BudgetExceeded
EntityBudgetExceededError = BudgetExceeded
PolicyViolation = PolicyRejected
ControlledRejection = PolicyRejected
PolicyRejectionError = PolicyRejected
SecurityPolicyRejected = PolicyRejected


_LIMIT_ALIASES = {
    "max_expansions": "expansions",
    "max_expansion_count": "expansions",
    "expansion_limit": "expansions",
    "expansion_budget": "expansions",
    "entity_expansion_limit": "expansions",
    "max_entity_expansions": "expansions",
    "expansions_limit": "expansions",
    "max_depth": "depth",
    "depth_limit": "depth",
    "depth_budget": "depth",
    "max_element_depth": "depth",
    "max_xml_depth": "depth",
    "max_bytes": "bytes",
    "byte_limit": "bytes",
    "byte_budget": "bytes",
    "bytes_limit": "bytes",
    "max_document_bytes": "bytes",
    "max_input_bytes": "bytes",
    "max_unparsed_entities": "unparsed_entities",
    "unparsed_entity_limit": "unparsed_entities",
    "unparsed_entity_budget": "unparsed_entities",
    "max_unparsed_entity_count": "unparsed_entities",
}


_ENTITY_REFERENCE_RE = re.compile(r"&([A-Za-z_][A-Za-z0-9_.-]*);")


class _ReferenceScanner(object):
    """Incrementally collect general-entity references outside DTD/CDATA."""

    def __init__(self):
        self.state = "text"
        self.return_state = "text"
        self.buffer = ""

    def feed(self, text):
        self.buffer += text
        references = []
        i = 0
        n = len(self.buffer)

        while i < n:
            if self.state == "comment":
                end = self.buffer.find("-->", i)
                if end < 0:
                    self.buffer = self.buffer[i:]
                    return references
                i = end + 3
                self.state = self.return_state
                continue

            if self.state == "cdata":
                end = self.buffer.find("]]>", i)
                if end < 0:
                    self.buffer = self.buffer[i:]
                    return references
                i = end + 3
                self.state = "text"
                continue

            if self.state == "pi":
                end = self.buffer.find("?>", i)
                if end < 0:
                    self.buffer = self.buffer[i:]
                    return references
                i = end + 2
                self.state = self.return_state
                continue

            if self.state in ("dtd_sq", "dtd_dq"):
                quote = "'" if self.state == "dtd_sq" else '"'
                end = self.buffer.find(quote, i)
                if end < 0:
                    self.buffer = self.buffer[i:]
                    return references
                i = end + 1
                self.state = "dtd"
                continue

            amp = self.buffer.find("&", i)
            next_lt = self.buffer.find("<", i)
            dtd_close = -1
            next_quote = -1
            if self.state == "dtd":
                dtd_close = self.buffer.find("]>", i)
                single_quote = self.buffer.find("'", i)
                double_quote = self.buffer.find('"', i)
                quote_positions = [
                    pos for pos in (single_quote, double_quote) if pos >= 0
                ]
                if quote_positions:
                    next_quote = min(quote_positions)

            candidates = [
                pos
                for pos in (amp, next_lt, dtd_close, next_quote)
                if pos >= 0
            ]
            if not candidates:
                if self.state == "dtd":
                    last_close_bracket = self.buffer.rfind("]", i)
                    if last_close_bracket >= 0:
                        self.buffer = self.buffer[last_close_bracket:]
                        return references
                self.buffer = ""
                return references

            event = min(candidates)
            if event == dtd_close:
                self.state = "text"
                i = dtd_close + 2
                continue

            if event == next_quote:
                self.state = (
                    "dtd_sq" if self.buffer[next_quote] == "'" else "dtd_dq"
                )
                i = next_quote + 1
                continue

            if amp >= 0 and amp == event:
                semi = self.buffer.find(";", amp + 1)
                if semi < 0:
                    self.buffer = self.buffer[amp:]
                    return references
                match = _ENTITY_REFERENCE_RE.match(self.buffer, amp)
                if match and match.end() == semi + 1 and self.state == "text":
                    references.append(match.group(1))
                i = semi + 1
                continue

            if next_lt < 0 or next_lt != event:
                self.buffer = self.buffer[i:]
                return references

            if self.buffer.startswith("<!--", next_lt):
                self.return_state = self.state if self.state in ("text", "dtd") else "text"
                self.state = "comment"
                i = next_lt + 4
                continue
            if self.buffer.startswith("<![CDATA[", next_lt):
                self.state = "cdata"
                i = next_lt + 9
                continue
            if self.buffer.startswith("<?", next_lt):
                self.return_state = self.state if self.state in ("text", "dtd") else "text"
                self.state = "pi"
                i = next_lt + 2
                continue

            if self.state == "dtd":
                i = next_lt + 1
                continue

            fragment = self.buffer[next_lt:].upper()
            for opener in ("<!--", "<![CDATA[", "<?", "<!DOCTYPE"):
                if len(fragment) < len(opener) and opener.startswith(fragment):
                    self.buffer = self.buffer[next_lt:]
                    return references

            doctype_end = self.buffer.find(">", next_lt)
            if self.buffer[next_lt:next_lt + 9].upper() == "<!DOCTYPE":
                bracket = self.buffer.find("[", next_lt + 9)
                if bracket < 0 or (doctype_end >= 0 and bracket > doctype_end):
                    if doctype_end < 0:
                        self.buffer = self.buffer[next_lt:]
                        return references
                    i = doctype_end + 1
                    continue
                self.state = "dtd"
                i = bracket + 1
                continue

            # Do not jump over a normal tag: entity references in its
            # attributes are still document-level entity expansions.
            i = next_lt + 1

        self.buffer = ""
        return references


class BudgetPolicy(object):
    """Shared, document-scoped budget state used by every XML backend."""

    def __init__(
        self,
        max_expansions=None,
        max_depth=None,
        max_bytes=None,
        max_unparsed_entities=None,
        limits=None,
        backend=None,
        **aliases
    ):
        self.limits = {
            "expansions": max_expansions,
            "depth": max_depth,
            "bytes": max_bytes,
            "unparsed_entities": max_unparsed_entities,
        }
        if limits:
            self.update_limits(limits)
        if aliases:
            self.update_limits(aliases)
        self.backend = backend
        self.reset()

    @classmethod
    def from_value(cls, policy=None, budget=None, **kwargs):
        if isinstance(policy, BudgetPolicy):
            return policy
        if isinstance(budget, BudgetPolicy):
            return budget
        limits = {}
        if isinstance(policy, dict):
            limits.update(policy)
        if isinstance(budget, dict):
            limits.update(budget)
        limits.update({key: value for key, value in kwargs.items() if value is not None})
        limits = {key: value for key, value in limits.items() if value is not None}
        if not limits:
            return None
        return cls(limits=limits)

    def update_limits(self, values):
        for key, value in values.items():
            metric = _LIMIT_ALIASES.get(key, key)
            if metric not in self.limits:
                raise TypeError("Unknown policy limit: " + str(key))
            self.limits[metric] = value

    def reset(self):
        """Reset document counters only; parser backend resets must not call this."""
        self.expansions = 0
        self.manual_expansions = 0
        self.entity_references = 0
        self.reference_counts = {}
        self.depth = 0
        self.max_depth_seen = 0
        self.bytes = 0
        self.unparsed_entities = 0
        self.entity_declarations = 0
        self.entities = {}
        self._weights = {}
        self.reference_counts = {}
        self.manual_expansions = 0
        self._scanner = _ReferenceScanner()
        return self

    def start_document(self, backend=None):
        self.reset()
        if backend is not None:
            self.backend = backend
        return self

    def clone(self, backend=None):
        clone = type(self)(limits=dict(self.limits), backend=backend or self.backend)
        return clone

    def snapshot(self):
        return {
            "backend": self.backend,
            "limits": dict(self.limits),
            "used": {
                "expansions": self.expansions,
                "entity_references": self.entity_references,
                "depth": self.depth,
                "max_depth_seen": self.max_depth_seen,
                "bytes": self.bytes,
                "unparsed_entities": self.unparsed_entities,
                "entity_declarations": self.entity_declarations,
            },
        }

    def to_dict(self):
        return self.snapshot()

    @property
    def expansion_count(self):
        return self.expansions

    @property
    def byte_count(self):
        return self.bytes

    @property
    def current_depth(self):
        return self.depth

    @property
    def unparsed_entity_count(self):
        return self.unparsed_entities

    def _counts(self):
        return {
            "expansions": self.expansions,
            "depth": self.depth,
            "bytes": self.bytes,
            "unparsed_entities": self.unparsed_entities,
        }

    def check(self, metric, backend=None):
        limit = self.limits.get(metric)
        used = getattr(self, metric)
        if limit is not None and used > limit:
            raise BudgetExceeded(
                metric,
                used,
                limit,
                backend=backend or self.backend,
                counts=self._counts(),
            )
        return True

    check_limit = check

    def _recompute_expansions(self, backend=None):
        total = self.manual_expansions
        for name, count in self.reference_counts.items():
            total += int(count) * self.expansion_weight(name)
        self.expansions = total
        self.check("expansions", backend=backend)
        return self.expansions

    def add_bytes(self, data_or_count, backend=None):
        if isinstance(data_or_count, int):
            size = data_or_count
        elif isinstance(data_or_count, str):
            size = len(data_or_count.encode("utf-8"))
        else:
            size = len(data_or_count)
        self.bytes += size
        self.check("bytes", backend=backend)
        return size

    record_bytes = add_bytes

    def observe_data(self, data, backend=None):
        size = self.add_bytes(data, backend=backend)
        if isinstance(data, int):
            return size
        text = _as_ascii_text(data)
        for name in self._scanner.feed(text):
            self.record_entity_reference(name, backend=backend)
        return size

    def enter_element(self, name=None, backend=None):
        self.depth += 1
        if self.depth > self.max_depth_seen:
            self.max_depth_seen = self.depth
        self.check("depth", backend=backend)
        return self.depth

    def leave_element(self, name=None, backend=None):
        if self.depth > 0:
            self.depth -= 1
        return self.depth

    start_element = enter_element
    end_element = leave_element
    push_depth = enter_element
    pop_depth = leave_element

    def record_expansion(self, count=1, name=None, backend=None):
        if isinstance(count, str) and name is None:
            name = count
            count = 1
        if name is not None:
            return self.record_entity_reference(name, backend=backend)
        self.manual_expansions += int(count)
        self._recompute_expansions(backend)
        return self.expansions

    add_expansion = record_expansion
    increment_expansions = record_expansion

    def record_entity_reference(self, name, backend=None):
        self.entity_references += 1
        self.reference_counts[name] = self.reference_counts.get(name, 0) + 1
        self._recompute_expansions(backend)
        return self.expansions

    def record_entity_declaration(
        self,
        name=None,
        is_parameter_entity=False,
        value=None,
        base=None,
        sysid=None,
        pubid=None,
        notation_name=None,
        backend=None,
    ):
        self.entity_declarations += 1
        if name is not None and value is not None and not is_parameter_entity:
            self.entities[name] = value
            self._weights.clear()
            self._recompute_expansions(backend)
        return None

    def record_unparsed_entity(
        self,
        name=None,
        base=None,
        sysid=None,
        pubid=None,
        notation_name=None,
        backend=None,
    ):
        self.unparsed_entities += 1
        self.check("unparsed_entities", backend=backend)
        return self.unparsed_entities

    add_unparsed_entity = record_unparsed_entity

    def expansion_weight(self, name, _stack=None):
        if name in self._weights and _stack is None:
            return self._weights[name]
        if _stack is None:
            _stack = set()
        if name in _stack:
            return 0
        value = self.entities.get(name)
        if value is None:
            return 1
        _stack.add(name)
        total = 1
        for reference in _ENTITY_REFERENCE_RE.findall(value):
            total += self.expansion_weight(reference, _stack)
        _stack.remove(name)
        if not _stack:
            self._weights[name] = total
        return total


EntityBudget = BudgetPolicy
CommonPolicy = BudgetPolicy
XMLBudgetPolicy = BudgetPolicy
DocumentBudget = BudgetPolicy
Budget = BudgetPolicy
SharedBudgetPolicy = BudgetPolicy
SharedEntityBudget = BudgetPolicy
XMLSecurityPolicy = BudgetPolicy
PolicySet = BudgetPolicy

PolicyRejection = PolicyRejected
Rejected = PolicyRejected
ControlledRejectionReason = RejectionReason


def _as_ascii_text(data):
    if isinstance(data, str):
        return data
    try:
        text = bytes(data).decode("ascii", "ignore")
    except TypeError:
        text = str(data)
    # UTF-16 leaves NUL bytes between ASCII code units. Removing NULs lets
    # the ASCII entity scanner work without claiming full encoding support.
    return text.replace(chr(0), "")


def annotate_backend_error(exc, backend, policy=None):
    """Ensure a controlled rejection records which backend observed it."""
    if isinstance(exc, PolicyRejected):
        if exc.backend is None:
            exc.backend = backend
        if policy is not None and not exc.counts:
            exc.counts = policy._counts()
        return exc
    rejection = PolicyRejected(
        RejectionReason.BACKEND,
        backend=backend,
        detail="backend raised a non-policy parser error",
        native_error=exc,
        counts=policy._counts() if policy is not None else None,
    )
    return rejection


def install_expat_policy(parser, policy, backend):
    """Wrap an expat parser's handlers so one policy works for all backends."""
    if policy is None:
        return None

    original_start = getattr(parser, "StartElementHandler", None)
    original_end = getattr(parser, "EndElementHandler", None)

    def start_element(*args):
        name = args[0] if args else None
        policy.enter_element(name, backend=backend)
        if original_start is not None:
            try:
                return original_start(*args)
            except BaseException:
                policy.leave_element(name, backend=backend)
                raise
        return None

    def end_element(*args):
        name = args[0] if args else None
        try:
            if original_end is not None:
                return original_end(*args)
            return None
        finally:
            policy.leave_element(name, backend=backend)

    parser.StartElementHandler = start_element
    parser.EndElementHandler = end_element

    original_entity = getattr(parser, "EntityDeclHandler", None)

    def entity_decl(*args):
        policy.record_entity_declaration(*args, backend=backend)
        if original_entity is not None:
            return original_entity(*args)
        return None

    parser.EntityDeclHandler = entity_decl

    original_unparsed = getattr(parser, "UnparsedEntityDeclHandler", None)

    def unparsed_entity(*args):
        name = args[0] if args else None
        policy.record_unparsed_entity(name, backend=backend)
        if original_unparsed is not None:
            return original_unparsed(*args)
        return None

    parser.UnparsedEntityDeclHandler = unparsed_entity
    return policy


__all__ = [
    "BACKEND_ELEMENTTREE",
    "BACKEND_PULLDOM",
    "BACKEND_SAX",
    "BudgetExceeded",
    "BudgetPolicy",
    "CommonPolicy",
    "ControlledRejection",
    "DocumentBudget",
    "EntityBudget",
    "EntityBudgetExceeded",
    "PolicyRejected",
    "PolicyViolation",
    "RejectionReason",
    "XMLBudgetPolicy",
    "annotate_backend_error",
    "install_expat_policy",
]
