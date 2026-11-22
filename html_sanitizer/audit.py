"""
Offline change ledger for :class:`~html_sanitizer.sanitizer.Sanitizer`.

The ledger is optional and never part of the sanitized output. It records
the three kinds of decisions made while processing a document:

* ``parse`` -- decisions taken while parsing the document or by the first
  lxml cleaner (comment removal, ``style``/``script`` tags, fallback to the
  BeautifulSoup parser);
* ``structure`` -- structural tidying performed by the sanitizer itself
  (tag rewrites, merges, empty/whitespace element removal, list markers,
  control characters);
* ``policy`` -- explicit allowlist policy decisions (disallowed tags and
  attributes, blocked embedded content, sanitized hrefs).

Two views on the recorded data exist:

* :meth:`ChangeLedger.public_entries` only exposes *structural aliases*
  (stable, content-free node paths) and reason codes. This view is safe to
  hand to editors or suppliers because it never contains document text.
* The internal entries additionally keep a fingerprint and the original
  node (and its serialized form) so that an auditor can navigate back to
  the source of a decision.

Nodes whose disappearance cannot be attributed to a known decision are not
silently dropped: they are kept with the ``pending`` status until a human
confirms them.

Repeatedly processing the same original fragment with the same reason is
idempotent -- a later, stricter run does not turn an earlier decision into
a new one as long as the earlier ledger (or a ledger seeded from it) is
supplied.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum


class Category(str, Enum):
    """The three places where a decision can originate."""

    PARSE = "parse"
    STRUCTURE = "structure"
    POLICY = "policy"


class Status(str, Enum):
    """Lifecycle of a recorded decision."""

    # A decision recorded during the current run.
    NEW = "new"
    # The decision was already present in a ledger supplied up-front.
    REPEATED = "repeated"
    # The node could not be aligned with any known decision; human review.
    PENDING = "pending"


class Reason(str, Enum):
    """Machine-readable, stable reason codes."""

    # parse
    PARSER_FALLBACK = "parser-fallback"
    COMMENT_REMOVED = "comment-removed"
    STYLE_TAG_REMOVED = "style-tag-removed"
    SCRIPT_TAG_REMOVED = "script-tag-removed"

    # structure
    TAG_REWRITTEN = "tag-rewritten"
    EMPTY_ELEMENT_REMOVED = "empty-element-removed"
    WHITESPACE_ELEMENT_REMOVED = "whitespace-element-removed"
    NESTED_PARAGRAPH_UNWRAPPED = "nested-paragraph-unwrapped"
    LIST_MARKER_REMOVED = "list-marker-removed"
    DUPLICATE_WHITESPACE_TAG = "duplicate-whitespace-tag"
    LEADING_WHITESPACE_TAG = "leading-whitespace-tag"
    ELEMENTS_MERGED = "elements-merged"
    CONTROL_CHARACTERS_FILTERED = "control-characters-filtered"

    # policy
    DISALLOWED_TAG_UNWRAPPED = "disallowed-tag-unwrapped"
    DISALLOWED_TAG_REMOVED = "disallowed-tag-removed"
    DISALLOWED_ATTRIBUTE_REMOVED = "disallowed-attribute-removed"
    HREF_SANITIZED = "href-sanitized"
    EMBEDDED_HOST_NOT_ALLOWED = "embedded-host-not-allowed"

    # unattributed
    UNALIGNED_NODE = "unaligned-node"


def _node_fragment(node):
    """Serialize a node; never raises, so ledgering cannot break sanitizing."""
    try:
        import lxml.html  # noqa: PLC0415

        return lxml.html.tostring(node, encoding="unicode")
    except Exception:  # noqa: BLE001 -- ledgering must stay best-effort
        try:
            return str(node)
        except Exception:  # noqa: BLE001
            return ""


def fingerprint_for(fragment):
    """Content-based identity of an original fragment."""
    return hashlib.sha256(fragment.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class ChangeDecision:
    """A single, auditable decision.

    ``alias`` is the content-free structural alias, ``reason`` the stable
    reason code. The remaining fields are internal audit data (fingerprint,
    original serialized node and, while the tree is alive, the node itself).
    """

    alias: str
    category: Category
    reason: Reason
    fingerprint: str
    detail: str = ""
    status: Status = Status.NEW
    original: object = field(default=None, repr=False, compare=False)

    @property
    def key(self):
        """Identity used to suppress duplicate decisions across runs."""
        return self.fingerprint, self.reason

    def public(self):
        """The only view which may leave the trust boundary."""
        return {
            "alias": self.alias,
            "category": self.category.value,
            "reason": self.reason.value,
        }


class ChangeLedger:
    """Collects decisions for one or several sanitization runs.

    Pass an existing ledger (or a ledger built from an exported one via
    :meth:`from_public_entries`) to make later runs idempotent: fragments
    already accounted for are marked ``repeated`` instead of producing new
    decisions.
    """

    def __init__(self, previous=None):
        self._decisions = []
        self._seen = set()
        # alias -> node, the bridge back to the original tree
        self._nodes = {}
        if previous is not None:
            for decision in previous._decisions:  # noqa: SLF001
                if decision.status is Status.PENDING:
                    # Pending items are not known decisions; carry them
                    # forward unchanged so they remain open for review.
                    self._decisions.append(decision)
                    if decision.original is not None:
                        self._nodes[decision.alias] = decision.original
                    continue
                self._seen.add(decision.key)
                repeated = ChangeDecision(
                    alias=decision.alias,
                    category=decision.category,
                    reason=decision.reason,
                    fingerprint=decision.fingerprint,
                    detail=decision.detail,
                    status=Status.REPEATED,
                    original=decision.original,
                )
                self._decisions.append(repeated)
                if decision.original is not None:
                    self._nodes[decision.alias] = decision.original
    # -- node addressing --------------------------------------------------

    def assign_aliases(self, root):
        """Assign stable structural aliases to every element in ``root``."""
        root_alias = "/"
        self._nodes[root_alias] = root
        self._walk_aliases(root, root_alias)

    @staticmethod
    def _tag_label(tag):
        # Comment/PI nodes expose a function object as tag; never let such
        # non-string, instance-specific labels leak into a structural alias.
        return tag if isinstance(tag, str) else "#non-element"

    def _walk_aliases(self, element, prefix):
        counts = {}
        for child in element:
            label = self._tag_label(child.tag)
            index = counts.get(label, 0)
            counts[label] = index + 1
            alias = f"{prefix}{label}[{index}]"
            if not prefix.endswith("/"):
                alias = f"{prefix}/{label}[{index}]"
            self._nodes[alias] = child
            self._walk_aliases(child, alias)

    def alias_of(self, node):
        for alias, candidate in self._nodes.items():
            if candidate is node:
                return alias
        return None

    # -- recording --------------------------------------------------------

    def was_seen(self, node, reason):
        """Whether node already has a non-pending decision of reason."""
        for decision in self._decisions:
            if decision.original is node and decision.reason is reason:
                return True
        return False

    def record(
        self,
        node,
        category,
        reason,
        *,
        detail="",
        fragment=None,
        status=Status.NEW,
        alias=None,
    ):
        """Record a decision. Returns the (possibly pre-existing) decision."""
        if fragment is None:
            fragment = _node_fragment(node) if node is not None else detail
        fingerprint = fingerprint_for(fragment)
        key = (fingerprint, reason)
        if alias is None:
            alias = self.alias_of(node) or "/unassigned"
        if status is Status.NEW and key in self._seen:
            status = Status.REPEATED
        decision = ChangeDecision(
            alias=alias,
            category=category,
            reason=reason,
            fingerprint=fingerprint,
            detail=detail,
            status=status,
            original=node,
        )
        if status is not Status.PENDING and key not in self._seen:
            self._seen.add(key)
        self._decisions.append(decision)
        return decision

    def reconcile(self, root):
        """Keep nodes that vanished without a known decision as pending.

        Compares the aliased nodes with the live tree. Elements that have
        been detached and were never the subject of a decision are recorded
        with :data:`Status.PENDING` so they can be confirmed manually.
        """
        live = set(root.iter())
        accounted = {
            decision.original
            for decision in self._decisions
            if decision.original is not None
        }
        for alias, node in list(self._nodes.items()):
            if node in live or node in accounted or node is root:
                continue
            if self._has_recorded_ancestor(node, accounted):
                continue
            self.record(
                node,
                Category.PARSE,
                Reason.UNALIGNED_NODE,
                detail="node removed by an unattributed pipeline step",
                status=Status.PENDING,
                alias=alias,
            )

    @staticmethod
    def _has_recorded_ancestor(node, recorded):
        parent = node.getparent()
        while parent is not None:
            if parent in recorded:
                return True
            parent = parent.getparent()
        return False

    # -- views ------------------------------------------------------------

    def decisions(self, *, include_repeated=True):
        """Internal view: full decisions including the original nodes."""
        if include_repeated:
            return list(self._decisions)
        return [
            decision
            for decision in self._decisions
            if decision.status is not Status.REPEATED
        ]

    def public_entries(self, *, include_repeated=False):
        """Content-free view: structural aliases and reason codes only."""
        return [
            decision.public()
            for decision in self._decisions
            if include_repeated or decision.status is not Status.REPEATED
        ]

    def pending(self):
        """Decisions that still need human confirmation."""
        return [
            decision
            for decision in self._decisions
            if decision.status is Status.PENDING
        ]

    def original_for(self, alias):
        """Resolve a structural alias back to the original node."""
        return self._nodes.get(alias)

    @classmethod
    def from_public_entries(cls, entries, *, fragments=None):
        """Rebuild a ledger from an exported public view.

        ``fragments`` optionally maps aliases to the original fragments so
        that the content-based dedup identities can be restored across
        processes. Without it only structural aliases are carried forward.
        """
        ledger = cls()
        fragments = fragments or {}
        for entry in entries:
            alias = entry["alias"]
            reason = Reason(entry["reason"])
            category = Category(entry.get("category", "policy"))
            fragment = fragments.get(alias, alias)
            decision = ChangeDecision(
                alias=alias,
                category=category,
                reason=reason,
                fingerprint=fingerprint_for(fragment),
                status=Status.NEW,
            )
            ledger._decisions.append(decision)  # noqa: SLF001
            ledger._seen.add(decision.key)  # noqa: SLF001
        return ledger

    def __len__(self):
        return len(self._decisions)

    def __iter__(self):
        return iter(self._decisions)
