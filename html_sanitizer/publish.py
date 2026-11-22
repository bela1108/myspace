"""
Block-level publish interface between the sanitizer core and host
integrations (such as the Django glue in ``html_sanitizer.django``).

The editing platform reuses sanitized rich-text blocks across documents.
Legal attachments and knowledge base articles may reference the very same
block, but each document family is published under its own set of
retention rules, and each document inherits the rule version pinned by
its ancestor (section).  This module provides a cache which binds all of
that context into the cache key so that:

* unchanged blocks which are still authorized are reused (cache hit),
* blocks cached under a revoked historical rule version are invalidated,
* a block whose ancestor moved to a different rule version is recomputed.
"""

import hashlib
from dataclasses import dataclass, field

from .sanitizer import Sanitizer


__all__ = (
    "Block",
    "BlockPublishCache",
    "Document",
    "RuleRegistry",
    "Section",
)

#: The two document families known to the platform.  Legal attachments and
#: knowledge base articles publish under different retention rule sets.
LEGAL_ATTACHMENT = "legal_attachment"
KNOWLEDGE_BASE = "knowledge_base"


def _fingerprint(html):
    return hashlib.sha256(html.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Block:
    """A reusable rich-text block as stored by the editing platform."""

    block_id: str
    html: str

    @property
    def fingerprint(self):
        return _fingerprint(self.html)


@dataclass(frozen=True)
class Section:
    """An ancestor node pinning the rule version its descendants use."""

    section_id: str
    rule_version: str


@dataclass(frozen=True)
class Document:
    """A document being published; inherits rules from its section."""

    doc_id: str
    kind: str
    section: Section


@dataclass
class PublishEvent:
    """One cache-hit record produced while publishing a block."""

    seq: int
    doc_id: str
    block_id: str
    kind: str
    rule_version: str
    outcome: str  # "hit" or "recompute"
    reason: str  # "unchanged", "cold", "ancestor_changed" or "revoked"

    def as_dict(self):
        return {
            "seq": self.seq,
            "doc_id": self.doc_id,
            "block_id": self.block_id,
            "kind": self.kind,
            "rule_version": self.rule_version,
            "outcome": self.outcome,
            "reason": self.reason,
        }


class RuleRegistry:
    """
    Tracks the known rule versions per document kind, which of them have
    been revoked, and hands out sanitizer instances for authorized
    versions.
    """

    def __init__(self):
        self._rules = {}  # kind -> {version: sanitizer settings}
        self._revoked = set()  # (kind, version)
        self._sanitizers = {}  # (kind, version) -> Sanitizer
        self._caches = []

    def register(self, kind, version, sanitizer_settings=None):
        self._rules.setdefault(kind, {})[version] = sanitizer_settings or {}
        self._sanitizers.pop((kind, version), None)

    def revoke(self, kind, version):
        """Withdraw a historical rule version and invalidate its caches."""
        if (kind, version) not in self._known():
            raise LookupError(f"Unknown rule version {kind}/{version}")
        self._revoked.add((kind, version))
        self._sanitizers.pop((kind, version), None)
        for cache in self._caches:
            cache._purge(kind, version)

    def _known(self):
        return {
            (kind, version)
            for kind, versions in self._rules.items()
            for version in versions
        }

    def is_authorized(self, kind, version):
        known = (kind, version) in self._known()
        return known and (kind, version) not in self._revoked

    def current_version(self, kind):
        """The most recently registered, still authorized version."""
        for version in reversed(list(self._rules.get(kind, {}))):
            if self.is_authorized(kind, version):
                return version
        raise LookupError(f"No authorized rule version for kind {kind!r}")

    def sanitizer_for(self, kind, version):
        if not self.is_authorized(kind, version):
            raise LookupError(f"Rule version {kind}/{version} is revoked or unknown")
        key = (kind, version)
        if key not in self._sanitizers:
            self._sanitizers[key] = Sanitizer(self._rules[kind][version])
        return self._sanitizers[key]

    def _attach(self, cache):
        self._caches.append(cache)


@dataclass
class BlockPublishCache:
    """
    Sanitized-block cache keyed by (block fingerprint, document kind,
    ancestor rule version).  Records a :class:`PublishEvent` for every
    publish call so cache hits stay auditable.
    """

    registry: RuleRegistry
    _entries: dict = field(default_factory=dict, init=False)
    records: list = field(default_factory=list, init=False)

    def __post_init__(self):
        self.registry._attach(self)

    def _purge(self, kind, version):
        """Drop every entry produced under a revoked rule version."""
        doomed = [
            key for key in self._entries if key[1] == kind and key[2] == version
        ]
        for key in doomed:
            del self._entries[key]

    def _effective_version(self, document):
        pinned = document.section.rule_version
        if self.registry.is_authorized(document.kind, pinned):
            return pinned, False
        return self.registry.current_version(document.kind), True

    def publish(self, document, block):
        """
        Return the sanitized HTML for ``block`` in the context of
        ``document``, reusing a cached result when the block is unchanged
        and its rule version is still authorized.
        """
        kind = document.kind
        version, was_revoked = self._effective_version(document)
        key = (block.fingerprint, kind, version)

        if not was_revoked and key in self._entries:
            event = self._record(document, block, version, "hit", "unchanged")
            return self._entries[key], event

        if was_revoked:
            reason = "revoked"
        elif any(
            fp == block.fingerprint and k == kind for fp, k, _ in self._entries
        ):
            reason = "ancestor_changed"
        else:
            reason = "cold"

        html = self.registry.sanitizer_for(kind, version).sanitize(block.html)
        self._entries[key] = html
        event = self._record(document, block, version, "recompute", reason)
        return html, event

    def _record(self, document, block, version, outcome, reason):
        event = PublishEvent(
            seq=len(self.records) + 1,
            doc_id=document.doc_id,
            block_id=block.block_id,
            kind=document.kind,
            rule_version=version,
            outcome=outcome,
            reason=reason,
        )
        self.records.append(event)
        return event
