"""Optional, offline change ledger for :class:`html_sanitizer.Sanitizer`.

The ledger is deliberately split into two views:

* :meth:`ChangeLedger.public` exposes only a structural alias and a human
  readable reason. It never contains source XPaths, serialized fragments or
  text from the document.
* :meth:`ChangeLedger.internal` keeps the traceability data needed by an
  administrator: the original XPath, a snapshot of the affected node and the
  document the decision was made against.

Decisions are grouped by the three places where the sanitizer can change a
document: parsing, structural clean-up and explicit policy.  A decision that
cannot be tied back to a node is retained with status ``"pending"`` instead of
being silently omitted.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


__all__ = (
    "STAGE_EXPLICIT_POLICY",
    "STAGE_PARSE",
    "STAGE_PARSING",
    "STAGE_POLICY",
    "STAGE_STRUCTURAL",
    "STAGE_STRUCTURE",
    "STAGES",
    "STATUS_APPLIED",
    "STATUS_PENDING",
    "STATUS_UNALIGNED",
    "ChangeLedger",
    "InternalChange",
    "PublicChange",
)


STAGE_PARSE = "parse"
STAGE_STRUCTURE = "structure"
STAGE_POLICY = "policy"

STAGES = (STAGE_PARSE, STAGE_STRUCTURE, STAGE_POLICY)

# Descriptive aliases for callers which prefer the longer names.
STAGE_PARSING = STAGE_PARSE
STAGE_STRUCTURAL = STAGE_STRUCTURE
STAGE_EXPLICIT_POLICY = STAGE_POLICY

STATUS_APPLIED = "applied"
STATUS_PENDING = "pending"
STATUS_UNALIGNED = STATUS_PENDING


class PublicChange(dict):
    """The only information which may leave the trusted/offline boundary.

    It behaves like a plain ``{"alias": ..., "reason": ...}`` mapping so it
    can be JSON-serialized directly, while the attributes are available for
    callers which prefer record-style access.
    """

    def __init__(self, alias: str, reason: str):
        super().__init__(alias=alias, reason=reason)

    @property
    def alias(self) -> str:
        return self["alias"]

    @property
    def reason(self) -> str:
        return self["reason"]

    def as_dict(self) -> dict[str, str]:
        return dict(self)

    def __hash__(self) -> int:
        return hash((self["alias"], self["reason"]))


@dataclass(frozen=True)
class InternalChange:
    """A decision with enough context to return to the original node."""

    alias: str
    stage: str
    status: str
    round: int
    policy: str | None
    document_id: str
    operation: str
    reason: str
    source_xpath: str | None = None
    fragment: str | None = None
    tag: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    source_node: Any = field(default=None, repr=False, compare=False)

    @property
    def public(self) -> PublicChange:
        return PublicChange(alias=self.alias, reason=self.reason)

    def as_dict(self, *, include_fragment: bool = True) -> dict[str, Any]:
        data = {
            "alias": self.alias,
            "reason": self.reason,
            "stage": self.stage,
            "status": self.status,
            "round": self.round,
            "policy": self.policy,
            "document_id": self.document_id,
            "operation": self.operation,
            "source_xpath": self.source_xpath,
            "tag": self.tag,
            "details": self.details,
        }
        if include_fragment:
            data["fragment"] = self.fragment
        return data

    def __getitem__(self, key: str):
        return self.as_dict()[key]


class ChangeLedger:
    """Collect sanitizer decisions over one or more rounds.

    The same ledger may be passed to consecutive sanitize calls.  An
    identical decision against an identical input document is recorded only
    once, so tightening a policy in a later round does not turn content which
    was already removed in an earlier round into a new decision.
    """

    def __init__(self, *, policy: str | None = None):
        self._entries: list[InternalChange] = []
        self._index: dict[tuple[str, str, str], InternalChange] = {}
        self._dispositions: set[tuple[str, str]] = set()
        self._documents: dict[str, str] = {}
        self._round = 0
        self._policy = policy

    # -- round handling -------------------------------------------------

    def begin_round(
        self, *, policy: str | None = None, document_id: str
    ) -> tuple[int, str | None]:
        self._round += 1
        if policy is not None:
            self._policy = policy
        self._documents.setdefault(document_id, "")
        return self._round, self._policy

    def remember_document(self, document_id: str, html: str) -> None:
        self._documents[document_id] = html

    @property
    def rounds(self) -> int:
        return self._round

    @property
    def policy(self) -> str | None:
        return self._policy

    # -- recording ------------------------------------------------------

    def record(
        self,
        *,
        alias: str,
        stage: str,
        status: str,
        round: int,
        policy: str | None,
        document_id: str,
        operation: str,
        reason: str,
        source_xpath: str | None = None,
        fragment: str | None = None,
        tag: str | None = None,
        details: dict[str, Any] | None = None,
        source_node: Any = None,
    ) -> tuple[InternalChange, bool]:
        """Record one decision, returning ``(entry, was_new)``.

        ``operation`` and the document digest are part of the identity.  This
        keeps a repeat pass over the same source from recording the same
        removal twice, while still allowing a different document which happens
        to reuse an alias to produce its own decision.
        """

        if stage not in STAGES:
            raise ValueError(f"Unknown ledger stage {stage!r}")
        if status not in {STATUS_APPLIED, STATUS_PENDING}:
            raise ValueError(f"Unknown ledger status {status!r}")

        identity = (document_id, alias, operation)
        existing = self._index.get(identity)
        if existing is not None:
            return existing, False

        reason = self._format_reason(stage, status, round, reason)
        entry = InternalChange(
            alias=alias,
            stage=stage,
            status=status,
            round=round,
            policy=policy,
            document_id=document_id,
            operation=operation,
            reason=reason,
            source_xpath=source_xpath,
            fragment=fragment,
            tag=tag,
            details=details or {},
            source_node=source_node,
        )
        self._entries.append(entry)
        self._index[identity] = entry
        if operation == "node-removal" or operation.startswith("rewrite:replacement"):
            self._dispositions.add((document_id, alias))
        return entry, True

    @staticmethod
    def _format_reason(stage: str, status: str, round: int, reason: str) -> str:
        if status == STATUS_PENDING:
            prefix = f"{stage} (round {round}, pending confirmation)"
        else:
            prefix = f"{stage} (round {round})"
        return f"{prefix}: {reason}"

    def has_node_decision(self, document_id: str, alias: str) -> bool:
        return (document_id, alias, "node-removal") in self._index

    def has_node_disposition(self, document_id: str, alias: str) -> bool:
        """Whether a node-removal or replacement was already recorded."""

        return (document_id, alias) in self._dispositions

    # -- public view ----------------------------------------------------

    @property
    def entries(self) -> tuple[InternalChange, ...]:
        """The internal entries; use :meth:`public` for the redacted view."""

        return tuple(self._entries)

    def public(self) -> tuple[PublicChange, ...]:
        return tuple(entry.public for entry in self._entries)

    def public_entries(self) -> tuple[PublicChange, ...]:
        return self.public()

    def public_records(self) -> tuple[PublicChange, ...]:
        return self.public()

    def public_dicts(self) -> list[dict[str, str]]:
        return [entry.as_dict() for entry in self.public()]

    def public_view(self) -> list[dict[str, str]]:
        """Alias for :meth:`public_dicts`, the JSON-ready redacted view."""

        return self.public_dicts()

    def public_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.public_dicts(), ensure_ascii=False, indent=indent)

    def pending_public(self) -> tuple[PublicChange, ...]:
        return tuple(
            entry.public for entry in self._entries if entry.status == STATUS_PENDING
        )

    # -- internal view --------------------------------------------------

    def internal(self) -> tuple[InternalChange, ...]:
        return tuple(self._entries)

    def internal_entries(self) -> tuple[InternalChange, ...]:
        return self.internal()

    def for_round(self, round_number: int) -> tuple[InternalChange, ...]:
        return tuple(entry for entry in self._entries if entry.round == round_number)

    def decisions_for_round(self, round_number: int) -> tuple[InternalChange, ...]:
        return self.for_round(round_number)

    def pending(self) -> tuple[InternalChange, ...]:
        return tuple(entry for entry in self._entries if entry.status == STATUS_PENDING)

    def resolve(self, alias: str) -> tuple[InternalChange, ...]:
        """Return internal entries for a public structural alias."""

        return tuple(entry for entry in self._entries if entry.alias == alias)

    def resolve_one(self, alias: str) -> InternalChange | None:
        entries = self.resolve(alias)
        return entries[0] if entries else None

    def original_document(self, document_id: str) -> str | None:
        return self._documents.get(document_id)

    def locate(self, entry: InternalChange | str) -> list[Any]:
        """Locate the original node(s) for an entry or alias.

        Source nodes are preferred because they remain available while the
        ledger is in memory.  For a serialized/offline ledger the original
        document is reparsed and the stored XPath is used instead.
        """

        entries = self.resolve(entry) if isinstance(entry, str) else (entry,)

        found = []
        for item in entries:
            if item.source_node is not None:
                found.append(item.source_node)
                continue
            html = self.original_document(item.document_id)
            if html is None or item.source_xpath is None:
                continue
            try:
                import lxml.html  # noqa: PLC0415 - optional at import time

                doc = lxml.html.fromstring(f"<div>{html}</div>")
                found.extend(doc.xpath(item.source_xpath))
            except Exception:
                continue
        return found

    def original_node(self, alias: str):
        """Return the first original node for an alias, if it is available."""

        entry = self.resolve_one(alias)
        if entry is None:
            return None
        nodes = self.locate(entry)
        return nodes[0] if nodes else None

    def internal_dicts(self, *, include_fragment: bool = True) -> list[dict[str, Any]]:
        return [
            entry.as_dict(include_fragment=include_fragment) for entry in self._entries
        ]

    # -- persistence ----------------------------------------------------

    def merge(self, other: ChangeLedger) -> None:
        for entry in other._entries:
            identity = (entry.document_id, entry.alias, entry.operation)
            if identity in self._index:
                continue
            self._entries.append(entry)
            self._index[identity] = entry
            if entry.operation == "node-removal" or entry.operation.startswith(
                "rewrite:replacement"
            ):
                self._dispositions.add((entry.document_id, entry.alias))
        for document_id, html in other._documents.items():
            self._documents.setdefault(document_id, html)
        if self._policy is None:
            self._policy = other._policy
        self._round = max(self._round, other._round)

    def to_json(
        self, *, internal: bool = False, include_fragment: bool = True, indent: int = 2
    ) -> str:
        if internal:
            data = self.internal_dicts(include_fragment=include_fragment)
        else:
            data = self.public_dicts()
        return json.dumps(data, ensure_ascii=False, default=str, indent=indent)

    def dumps(
        self, *, internal: bool = False, include_fragment: bool = True, indent: int = 2
    ) -> str:
        return self.to_json(
            internal=internal,
            include_fragment=include_fragment,
            indent=indent,
        )

    def save(
        self,
        path: str,
        *,
        internal: bool = False,
        include_fragment: bool = True,
        indent: int = 2,
    ) -> None:
        """Write the ledger to a local JSON file.

        The public export contains only aliases and reasons.  Pass
        ``internal=True`` to write the traceability view for administrators.
        """

        from pathlib import Path  # noqa: PLC0415 - only needed for persistence

        Path(path).write_text(
            self.to_json(
                internal=internal,
                include_fragment=include_fragment,
                indent=indent,
            ),
            encoding="utf-8",
        )

    # -- dunder helpers -------------------------------------------------

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self):
        return iter(self.public())

    def __bool__(self) -> bool:
        return bool(self._entries)


def document_digest(html: str) -> str:
    return hashlib.sha256(html.encode("utf-8", errors="surrogatepass")).hexdigest()
