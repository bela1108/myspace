"""Verify which earlier approvals still apply to a sanitized document.

The verification API is intentionally built around *structural summaries*.
Summaries contain tag paths, section identifiers and one-way fingerprints, but
never the reviewed document's text.  This makes it possible to store a review
alongside a document without keeping another copy of the approved source.

Approvals are bound to three caller supplied pieces of information:

* a :class:`StructuralSummary` of the reviewed document,
* an :class:`ApprovalScope` naming the approved sections or elements, and
* the sanitizer policy version under which the review was made.

Running :func:`verify` against the final sanitized document then reports, for
every approved scope item, whether it is still unchanged, was edited in place,
moved to another location, or disappeared during sanitization.
"""

import hashlib
import json
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass

import lxml.html


__all__ = (
    "ALGORITHM",
    "ApprovalScope",
    "NodeSummary",
    "ReviewRecord",
    "ScopeItem",
    "SectionSummary",
    "StructuralSummary",
    "VerificationEntry",
    "VerificationReport",
    "verify",
)


ALGORITHM = "html-sanitizer.verification.v1"

UNCHANGED = "unchanged"
EDITED = "edited"
MOVED = "moved"
MISSING = "missing"

STATUSES = (UNCHANGED, EDITED, MOVED, MISSING)

HEADING_TAGS = {"h1", "h2", "h3", "h4", "h5", "h6"}
INVISIBLE_TEXT_TAGS = {"script", "style", "template", "noscript"}

_CONTROL_CHARACTERS_RE = re.compile(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]")
_WHITESPACE_RE = re.compile(r"\s+")
_TOKEN_RE = re.compile(r"[^\W_]+", re.UNICODE)
_CJK_RE = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff]")

# Keeping a bounded sketch makes summaries predictable in size.  The sketch is
# only used for fuzzy matching; exact comparisons use full digests.
_TOKEN_SKETCH_SIZE = 512


def _normalize_text(value):
    value = _CONTROL_CHARACTERS_RE.sub("", value or "")
    value = unicodedata.normalize("NFKC", value)
    return _WHITESPACE_RE.sub(" ", value).strip()


def _digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _tokens(value):
    """Tokenize without retaining the source text.

    CJK text is split into individual characters so that a small edit does not
    make the whole run look like a different document.
    """

    result = []
    for chunk in _TOKEN_RE.findall((value or "").casefold()):
        cjk = _CJK_RE.findall(chunk)
        if not cjk:
            result.append(chunk)
            continue
        result.extend(cjk)
        result.extend(_TOKEN_RE.findall(_CJK_RE.sub(" ", chunk)))
    return result


def _token_sketch(value):
    hashes = sorted(
        {
            hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]
            for token in _tokens(value)
        }
    )
    return tuple(hashes[:_TOKEN_SKETCH_SIZE])


def _jaccard(left, right):
    left = set(left)
    right = set(right)
    union = left | right
    if not union:
        return 1.0
    return len(left & right) / len(union)


def _element_children(element):
    return [child for child in element if isinstance(child.tag, str)]


def _collect_text(element, parts):
    tag = element.tag.lower()
    if tag in INVISIBLE_TEXT_TAGS:
        return
    if element.text:
        parts.append(element.text)
    for child in element:
        if isinstance(child.tag, str):
            _collect_text(child, parts)
        if child.tail:
            parts.append(child.tail)


def _element_text(element):
    parts = []
    _collect_text(element, parts)
    return "".join(parts)


def _canonical_element(element):
    attributes = sorted(
        (key.lower(), _normalize_text(value or ""))
        for key, value in element.attrib.items()
    )
    parts = [
        element.tag.lower(),
        json.dumps(attributes, ensure_ascii=False, separators=(",", ":")),
        _normalize_text(element.text or ""),
    ]
    for child in element:
        if isinstance(child.tag, str):
            parts.append(_canonical_element(child))
        parts.append(_normalize_text(child.tail or ""))
    return "\x1f".join(parts)


def _structure_element(element):
    parts = [
        element.tag.lower(),
        "|".join(sorted(key.lower() for key in element.attrib)),
    ]
    for child in element:
        if isinstance(child.tag, str):
            parts.append(_structure_element(child))
    return "\x1e".join(parts)


def _label_text(element):
    if element.tag.lower() in HEADING_TAGS:
        return _normalize_text(_element_text(element))

    children = _element_children(element)
    if children and children[0].tag.lower() in HEADING_TAGS:
        return _normalize_text(_element_text(children[0]))
    return None


def _parse_fragment(html):
    wrapped = f"<div>{html}</div>"
    try:
        document = lxml.html.fromstring(wrapped)
        lxml.html.tostring(document, encoding="utf-8")
    except Exception:
        from lxml.html import soupparser  # noqa: PLC0415

        document = soupparser.fromstring(wrapped)
    return document


def _section_id(heading_path):
    return "section:" + ".".join(str(part) for part in heading_path)


@dataclass(frozen=True, kw_only=True)
class NodeSummary:
    """A text-free fingerprint of one element in a document."""

    path: tuple[int, ...]
    tag: str
    text_digest: str
    structure_digest: str
    content_digest: str
    tokens: tuple[str, ...]
    text_length: int
    label_digest: str | None = None

    def to_dict(self):
        return {
            "path": list(self.path),
            "tag": self.tag,
            "text_digest": self.text_digest,
            "structure_digest": self.structure_digest,
            "content_digest": self.content_digest,
            "tokens": list(self.tokens),
            "text_length": self.text_length,
            "label_digest": self.label_digest,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            path=tuple(data["path"]),
            tag=data["tag"],
            text_digest=data["text_digest"],
            structure_digest=data["structure_digest"],
            content_digest=data["content_digest"],
            tokens=tuple(data["tokens"]),
            text_length=int(data["text_length"]),
            label_digest=data.get("label_digest"),
        )


@dataclass(frozen=True, kw_only=True)
class SectionSummary:
    """A text-free fingerprint of an implicit heading-led section."""

    id: str
    order: int
    heading_path: tuple[int, ...]
    heading_level: int
    name_digest: str
    text_digest: str
    structure_digest: str
    content_digest: str
    tokens: tuple[str, ...]
    text_length: int

    def to_dict(self):
        return {
            "id": self.id,
            "order": self.order,
            "heading_path": list(self.heading_path),
            "heading_level": self.heading_level,
            "name_digest": self.name_digest,
            "text_digest": self.text_digest,
            "structure_digest": self.structure_digest,
            "content_digest": self.content_digest,
            "tokens": list(self.tokens),
            "text_length": self.text_length,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            id=data["id"],
            order=int(data["order"]),
            heading_path=tuple(data["heading_path"]),
            heading_level=int(data["heading_level"]),
            name_digest=data["name_digest"],
            text_digest=data["text_digest"],
            structure_digest=data["structure_digest"],
            content_digest=data["content_digest"],
            tokens=tuple(data["tokens"]),
            text_length=int(data["text_length"]),
        )


@dataclass(frozen=True, kw_only=True)
class StructuralSummary:
    """A serializable, text-free description of a document's structure.

    Sections model the implicit sections formed by headings: a heading and all
    following siblings up to the next heading of the same or a higher level.
    Two sections with the same heading therefore still receive different
    content digests when their bodies differ.
    """

    policy_version: str
    nodes: tuple[NodeSummary, ...]
    sections: tuple[SectionSummary, ...]
    digest: str
    algorithm: str = ALGORITHM

    @classmethod
    def from_html(cls, html, *, policy_version):
        document = _parse_fragment(html)
        nodes = _walk_nodes(document)
        sections = _build_sections(document)
        summary = cls(
            policy_version=str(policy_version),
            nodes=nodes,
            sections=sections,
            digest="",
        )
        return cls(
            policy_version=summary.policy_version,
            nodes=nodes,
            sections=sections,
            digest=summary.compute_digest(),
        )

    def _payload(self):
        return {
            "algorithm": self.algorithm,
            "policy_version": self.policy_version,
            "nodes": [node.to_dict() for node in self.nodes],
            "sections": [section.to_dict() for section in self.sections],
        }

    def compute_digest(self):
        return _digest(
            json.dumps(
                self._payload(),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )

    def to_dict(self):
        return {**self._payload(), "digest": self.digest}

    @classmethod
    def from_dict(cls, data):
        summary = cls(
            policy_version=data["policy_version"],
            nodes=tuple(NodeSummary.from_dict(item) for item in data["nodes"]),
            sections=tuple(SectionSummary.from_dict(item) for item in data["sections"]),
            digest=data.get("digest", ""),
            algorithm=data.get("algorithm", ALGORITHM),
        )
        if summary.algorithm != ALGORITHM:
            raise ValueError(
                f"Unsupported structural summary algorithm {summary.algorithm!r}"
            )
        if summary.digest and summary.digest != summary.compute_digest():
            raise ValueError("Structural summary digest does not match its contents")
        return summary

    def node_at(self, path):
        path = tuple(path)
        for node in self.nodes:
            if node.path == path:
                return node
        return None

    def section_by_id(self, section_id):
        for section in self.sections:
            if section.id == section_id:
                return section
        return None


def _walk_nodes(document):
    nodes = []

    def walk(element, path):
        text = _normalize_text(_element_text(element))
        label = _label_text(element)
        nodes.append(
            NodeSummary(
                path=path,
                tag=element.tag.lower(),
                text_digest=_digest(text),
                structure_digest=_digest(_structure_element(element)),
                content_digest=_digest(_canonical_element(element)),
                tokens=_token_sketch(text),
                text_length=len(text),
                label_digest=_digest(label) if label is not None else None,
            )
        )
        for index, child in enumerate(_element_children(element)):
            walk(child, path + (index,))

    for index, child in enumerate(_element_children(document)):
        walk(child, (index,))
    return tuple(nodes)


def _build_sections(document):
    children = _element_children(document)
    headings = [
        (index, child)
        for index, child in enumerate(children)
        if child.tag.lower() in HEADING_TAGS
    ]

    sections = []
    for position, (index, heading) in enumerate(headings):
        level = int(heading.tag[1])
        end = len(children)
        for next_index, next_heading in headings[position + 1 :]:
            if int(next_heading.tag[1]) <= level:
                end = next_index
                break

        span = children[index:end]
        text_parts = []
        for element in span:
            text_parts.append(_element_text(element))
            if element.tail:
                text_parts.append(element.tail)
        text = _normalize_text("".join(text_parts))
        heading_text = _normalize_text(_element_text(heading))
        heading_path = (index,)
        sections.append(
            SectionSummary(
                id=_section_id(heading_path),
                order=len(sections),
                heading_path=heading_path,
                heading_level=level,
                name_digest=_digest(heading_text),
                text_digest=_digest(text),
                structure_digest=_digest(
                    "\x1d".join(_structure_element(element) for element in span)
                ),
                content_digest=_digest(
                    "\x1d".join(
                        item
                        for element in span
                        for item in (
                            _canonical_element(element),
                            _normalize_text(element.tail or ""),
                        )
                    )
                ),
                tokens=_token_sketch(text),
                text_length=len(text),
            )
        )
    return tuple(sections)


def _pairs(values):
    return values.items() if isinstance(values, Mapping) else values


@dataclass(frozen=True, kw_only=True)
class ScopeItem:
    """One caller-named item in an approval scope."""

    key: str
    kind: str
    locator: tuple[int, ...] | str

    def __post_init__(self):
        if not self.key:
            raise ValueError("Approval scope keys must not be empty")
        if self.kind == "section":
            if not isinstance(self.locator, str):
                raise TypeError("Section scope locators must be section ids")
        elif self.kind == "element":
            if isinstance(self.locator, str):
                raise TypeError(
                    "Element scope locators must be sequences of child indexes"
                )
            object.__setattr__(
                self, "locator", tuple(int(part) for part in self.locator)
            )
        else:
            raise ValueError(f"Unknown approval scope kind {self.kind!r}")

    def to_dict(self):
        locator = list(self.locator) if self.kind == "element" else self.locator
        return {"key": self.key, "kind": self.kind, "locator": locator}

    @classmethod
    def from_dict(cls, data):
        return cls(key=data["key"], kind=data["kind"], locator=data["locator"])


@dataclass(frozen=True, kw_only=True)
class ApprovalScope:
    """The caller-specified set of sections or elements covered by a review."""

    items: tuple[ScopeItem, ...]

    def __post_init__(self):
        keys = [item.key for item in self.items]
        if len(keys) != len(set(keys)):
            raise ValueError("Approval scope keys must be unique")

    @classmethod
    def from_sections(cls, sections):
        return cls(
            items=tuple(
                ScopeItem(key=str(key), kind="section", locator=str(value))
                for key, value in _pairs(sections)
            )
        )

    @classmethod
    def from_elements(cls, elements):
        return cls(
            items=tuple(
                ScopeItem(key=str(key), kind="element", locator=value)
                for key, value in _pairs(elements)
            )
        )

    def __iter__(self):
        return iter(self.items)

    def __len__(self):
        return len(self.items)

    def __getitem__(self, key):
        for item in self.items:
            if item.key == key:
                return item
        raise KeyError(key)

    def by_key(self):
        return {item.key: item for item in self.items}

    def to_dict(self):
        return {
            "algorithm": ALGORITHM,
            "items": [item.to_dict() for item in self.items],
        }

    @classmethod
    def from_dict(cls, data):
        return cls(items=tuple(ScopeItem.from_dict(item) for item in data["items"]))


@dataclass(frozen=True, kw_only=True)
class VerificationEntry:
    """The outcome for one approved scope item.

    ``status`` is one of ``unchanged``, ``edited``, ``moved`` or ``missing``.
    ``claimable`` is only true for ``unchanged`` items; the others need a human
    to look at them again.  ``matched`` also covers moved and edited items so
    callers can distinguish "found but changed" from "gone".
    """

    key: str
    kind: str
    status: str
    original_path: tuple[int, ...]
    current_path: tuple[int, ...] | None
    matched: bool
    claimable: bool
    similarity: float | None

    def to_dict(self):
        return {
            "key": self.key,
            "kind": self.kind,
            "status": self.status,
            "original_path": list(self.original_path),
            "current_path": (
                list(self.current_path) if self.current_path is not None else None
            ),
            "matched": self.matched,
            "claimable": self.claimable,
            "similarity": (
                round(self.similarity, 4) if self.similarity is not None else None
            ),
        }


@dataclass(frozen=True, kw_only=True)
class VerificationReport:
    """Text-free report describing which approvals still apply."""

    policy_version: str
    current_policy_version: str
    summary_digest: str
    final_summary_digest: str
    entries: tuple[VerificationEntry, ...]
    similarity_threshold: float

    @property
    def policy_changed(self):
        return self.policy_version != self.current_policy_version

    def by_key(self):
        return {entry.key: entry for entry in self.entries}

    def __getitem__(self, key):
        try:
            return self.by_key()[key]
        except KeyError:
            raise KeyError(key) from None

    @property
    def matched_keys(self):
        return tuple(entry.key for entry in self.entries if entry.matched)

    @property
    def claimable_keys(self):
        return tuple(entry.key for entry in self.entries if entry.claimable)

    def with_status(self, status):
        if status not in STATUSES:
            raise ValueError(f"Unknown verification status {status!r}")
        return tuple(entry for entry in self.entries if entry.status == status)

    @property
    def counts(self):
        return {
            status: sum(entry.status == status for entry in self.entries)
            for status in STATUSES
        }

    def to_dict(self):
        return {
            "algorithm": ALGORITHM,
            "policy_version": self.policy_version,
            "current_policy_version": self.current_policy_version,
            "policy_changed": self.policy_changed,
            "summary_digest": self.summary_digest,
            "final_summary_digest": self.final_summary_digest,
            "similarity_threshold": self.similarity_threshold,
            "counts": self.counts,
            "entries": [entry.to_dict() for entry in self.entries],
        }


def _match_section(original, final_summary, similarity_threshold):
    candidates = final_summary.sections

    exact = [
        section
        for section in candidates
        if section.heading_level == original.heading_level
        and section.content_digest == original.content_digest
    ]
    if exact:
        at_path = [
            section
            for section in exact
            if section.heading_path == original.heading_path
        ]
        chosen = (
            at_path[0]
            if at_path
            else min(exact, key=lambda section: (section.order, section.heading_path))
        )
        status = UNCHANGED if chosen.heading_path == original.heading_path else MOVED
        return chosen, status, 1.0

    at_path = next(
        (
            section
            for section in candidates
            if section.heading_path == original.heading_path
        ),
        None,
    )
    at_similarity = (
        _jaccard(original.tokens, at_path.tokens) if at_path is not None else -1.0
    )

    similar = []
    for section in candidates:
        if section.heading_level != original.heading_level:
            continue
        if section.name_digest != original.name_digest:
            continue
        similarity = _jaccard(original.tokens, section.tokens)
        if (
            section.structure_digest == original.structure_digest
            or similarity >= similarity_threshold
        ):
            similar.append((similarity, section))

    if similar:
        best_similarity, best = max(similar, key=lambda item: (item[0], -item[1].order))
    else:
        best_similarity, best = -1.0, None

    if (
        best is not None
        and (at_path is None or best_similarity >= at_similarity + 0.10)
        and best_similarity >= similarity_threshold
    ):
        status = MOVED if best.heading_path != original.heading_path else EDITED
        return best, status, best_similarity

    if at_path is not None:
        return at_path, EDITED, max(at_similarity, 0.0)

    if best is not None and best_similarity >= similarity_threshold:
        return best, MOVED, best_similarity

    return None, MISSING, None


def _match_node(original, final_summary, similarity_threshold):
    candidates = final_summary.nodes

    exact = [
        node
        for node in candidates
        if node.tag == original.tag and node.content_digest == original.content_digest
    ]
    if exact:
        at_path = [node for node in exact if node.path == original.path]
        chosen = (
            at_path[0]
            if at_path
            else min(exact, key=lambda node: (len(node.path), node.path))
        )
        status = UNCHANGED if chosen.path == original.path else MOVED
        return chosen, status, 1.0

    at_path = next(
        (node for node in candidates if node.path == original.path),
        None,
    )
    at_similarity = (
        _jaccard(original.tokens, at_path.tokens) if at_path is not None else -1.0
    )

    similar = []
    for node in candidates:
        if node.tag != original.tag:
            continue
        if (
            original.label_digest is not None
            and node.label_digest != original.label_digest
        ):
            continue
        similarity = _jaccard(original.tokens, node.tokens)
        if (
            node.structure_digest == original.structure_digest
            or similarity >= similarity_threshold
        ):
            similar.append((similarity, node))

    if similar:
        best_similarity, best = max(
            similar,
            key=lambda item: (item[0], -len(item[1].path), item[1].path),
        )
    else:
        best_similarity, best = -1.0, None

    if (
        best is not None
        and (at_path is None or best_similarity >= at_similarity + 0.10)
        and best_similarity >= similarity_threshold
    ):
        status = MOVED if best.path != original.path else EDITED
        return best, status, best_similarity

    if at_path is not None:
        return at_path, EDITED, max(at_similarity, 0.0)

    if best is not None and best_similarity >= similarity_threshold:
        return best, MOVED, best_similarity

    return None, MISSING, None


def _verify_item(item, summary, final_summary, similarity_threshold):
    if item.kind == "section":
        original = summary.section_by_id(item.locator)
        if original is None:
            raise ValueError(
                f"Approval scope {item.key!r} references unknown section {item.locator!r}"
            )
        match, status, similarity = _match_section(
            original, final_summary, similarity_threshold
        )
        original_path = original.heading_path
        current_path = match.heading_path if match is not None else None
    else:
        original = summary.node_at(item.locator)
        if original is None:
            raise ValueError(
                f"Approval scope {item.key!r} references unknown element path"
                f" {tuple(item.locator)!r}"
            )
        match, status, similarity = _match_node(
            original, final_summary, similarity_threshold
        )
        original_path = original.path
        current_path = match.path if match is not None else None

    return VerificationEntry(
        key=item.key,
        kind=item.kind,
        status=status,
        original_path=original_path,
        current_path=current_path,
        matched=status != MISSING,
        claimable=status == UNCHANGED,
        similarity=similarity,
    )


def verify(
    final_html,
    *,
    summary,
    scope,
    policy_version,
    current_policy_version=None,
    similarity_threshold=0.6,
):
    """Report which approved parts of ``final_html`` still match the review.

    ``summary`` and ``scope`` describe the reviewed object.  ``policy_version``
    is the sanitizer policy under which that review was made and must match the
    version recorded in ``summary``.  ``current_policy_version`` names the
    policy which produced ``final_html``; it defaults to ``policy_version``.

    The returned report contains only paths, statuses and one-way fingerprints.
    It never contains text from the reviewed document.
    """

    if not isinstance(summary, StructuralSummary):
        raise TypeError("summary must be a StructuralSummary")
    if not isinstance(scope, ApprovalScope):
        raise TypeError("scope must be an ApprovalScope")
    if summary.policy_version != str(policy_version):
        raise ValueError(
            f"Structural summary was recorded for policy version"
            f" {summary.policy_version!r}, not {str(policy_version)!r}"
        )
    if not 0 <= similarity_threshold <= 1:
        raise ValueError("similarity_threshold must be between 0 and 1")

    current_policy_version = (
        str(policy_version)
        if current_policy_version is None
        else str(current_policy_version)
    )
    final_summary = StructuralSummary.from_html(
        final_html, policy_version=current_policy_version
    )
    entries = tuple(
        _verify_item(item, summary, final_summary, similarity_threshold)
        for item in scope
    )
    return VerificationReport(
        policy_version=str(policy_version),
        current_policy_version=current_policy_version,
        summary_digest=summary.digest,
        final_summary_digest=final_summary.digest,
        entries=entries,
        similarity_threshold=similarity_threshold,
    )


@dataclass(frozen=True, kw_only=True)
class ReviewRecord:
    """Persistable bundle of everything needed to re-verify an old review."""

    summary: StructuralSummary
    scope: ApprovalScope
    policy_version: str

    def __post_init__(self):
        if self.summary.policy_version != self.policy_version:
            raise ValueError(
                "Review policy version must match the structural summary's"
                " policy version"
            )

    def verify(
        self,
        final_html,
        *,
        current_policy_version=None,
        similarity_threshold=0.6,
    ):
        return verify(
            final_html,
            summary=self.summary,
            scope=self.scope,
            policy_version=self.policy_version,
            current_policy_version=current_policy_version,
            similarity_threshold=similarity_threshold,
        )

    def to_dict(self):
        return {
            "algorithm": ALGORITHM,
            "policy_version": self.policy_version,
            "summary": self.summary.to_dict(),
            "scope": self.scope.to_dict(),
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            summary=StructuralSummary.from_dict(data["summary"]),
            scope=ApprovalScope.from_dict(data["scope"]),
            policy_version=data["policy_version"],
        )
