"""Publication boundary checks for trusted, self-owned documents.

The ordinary :class:`html_sanitizer.Sanitizer` answers "is this HTML allowed?".
A publication boundary check answers a different question: "which pieces of
this document may be published, and which pieces became ambiguous while the
document was sanitized?"

Callers annotate source runs with a publication permission before cleaning::

    <p data-publish="public">Monday, maths</p>
    <p data-publish="public">Tuesday, Chinese
      <span data-publish="internal">Remember the dictionary.</span>
    </p>

Sanitizing can split, drop and merge nodes. In particular, adjacent nodes are
merged and their ``text``/``tail`` contents are concatenated. When a public and
an internal run end up in the same segment, the whole segment is ambiguous and
is returned for manual review. Public-only segments remain publishable.

This feature is **only for documents controlled by the application**. The
permission annotations are trusted metadata, not a security boundary. Do not
use it to make third-party HTML safe; pass untrusted input through
``Sanitizer.sanitize`` (or a stricter policy) first.
"""

from __future__ import annotations

import copy
import html as _html
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

import lxml.html

from .sanitizer import Sanitizer, filter_control_characters


__all__ = (
    "DROPPED",
    "INTERNAL",
    "MIXED",
    "NEUTRAL",
    "PUBLIC",
    "PUBLISHED",
    "PublishBoundary",
    "PublicationBoundary",
    "PublicationBoundaryCheck",
    "PublicationResult",
    "PublicationSegment",
    "REVIEW",
    "ReviewItem",
    "SourceRef",
    "TextRun",
    "WITHHELD",
    "check_publication",
    "check_publication_boundary",
    "check_publish_boundary",
    "publication_boundary",
    "publication_check",
    "publication_html",
    "sanitize_for_publication",
    "sanitize_with_provenance",
)


PUBLIC = "public"
INTERNAL = "internal"
MIXED = "mixed"
NEUTRAL = "neutral"

PUBLISHED = "published"
WITHHELD = "withheld"
REVIEW = "review"
DROPPED = "dropped"


BLOCK_TAGS = frozenset(
    {
        "address",
        "article",
        "aside",
        "blockquote",
        "dd",
        "details",
        "div",
        "dl",
        "dt",
        "fieldset",
        "figcaption",
        "figure",
        "footer",
        "form",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "header",
        "hr",
        "li",
        "main",
        "nav",
        "ol",
        "p",
        "pre",
        "section",
        "summary",
        "table",
        "tbody",
        "td",
        "tfoot",
        "th",
        "thead",
        "tr",
        "ul",
    }
)

VOID_TAGS = frozenset(
    {
        "area",
        "base",
        "br",
        "col",
        "embed",
        "hr",
        "img",
        "input",
        "link",
        "meta",
        "param",
        "source",
        "track",
        "wbr",
    }
)

DEFAULT_LABEL_ATTRIBUTES = (
    "data-publish",
    "data-publishable",
    "data-publication",
    "data-visibility",
    "data-audience",
    "data-access",
    "data-release",
    "data-permission",
    "data-classification",
    "data-public",
    "data-confidential",
    "data-private",
)

DEFAULT_CLASS_LABELS = {
    "public": PUBLIC,
    "publishable": PUBLIC,
    "公开": PUBLIC,
    "internal": INTERNAL,
    "private": INTERNAL,
    "restricted": INTERNAL,
    "confidential": INTERNAL,
    "teacher": INTERNAL,
    "teacher-only": INTERNAL,
    "annotation": INTERNAL,
    "note": INTERNAL,
    "lesson-note": INTERNAL,
    "lesson-plan": INTERNAL,
    "prep-note": INTERNAL,
    "course-note": INTERNAL,
    "draft": INTERNAL,
    "内部": INTERNAL,
    "备课": INTERNAL,
    "备课批注": INTERNAL,
    "批注": INTERNAL,
}

DEFAULT_TAG_LABELS = {
    "public": PUBLIC,
    "internal": INTERNAL,
    "private": INTERNAL,
    "restricted": INTERNAL,
    "confidential": INTERNAL,
    "teacher": INTERNAL,
    "teacher-note": INTERNAL,
    "teacher-only": INTERNAL,
    "lesson-note": INTERNAL,
    "prep-note": INTERNAL,
    "annotation": INTERNAL,
    "note": INTERNAL,
    "draft": INTERNAL,
}

IGNORED_TEXT_TAGS = frozenset({"script", "style"})

PUBLIC_VALUES = frozenset(
    {
        "1",
        "yes",
        "true",
        "y",
        "t",
        "public",
        "publish",
        "published",
        "publishable",
        "external",
        "公开",
        "对外",
        "可发布",
    }
)

INTERNAL_VALUES = frozenset(
    {
        "0",
        "no",
        "false",
        "n",
        "f",
        "private",
        "internal",
        "restricted",
        "confidential",
        "teacher",
        "teacher-only",
        "annotation",
        "note",
        "draft",
        "hidden",
        "内部",
        "私有",
        "草稿",
        "备课",
        "批注",
        "隐藏",
    }
)


@dataclass(frozen=True)
class SourceRef:
    """A text run in the trusted source document.

    ``kind`` is either ``"text"`` (the element's leading text) or ``"tail"``
    (the text following a child element). Tails matter because the sanitizer
    concatenates them while merging nodes.
    """

    id: str
    text: str
    visibility: str
    tag: str
    path: str
    kind: str
    offset: int
    status: str
    label: str | None = None
    segment_path: str = ""
    segment_tag: str = ""

    @property
    def source_id(self):
        return self.id

    @property
    def location(self):
        return self.path

    @property
    def origin(self):
        return self.label or self.path

    @property
    def is_public(self):
        return self.visibility == PUBLIC

    @property
    def is_internal(self):
        return self.visibility == INTERNAL

    @property
    def review_required(self):
        return self.status == REVIEW

    def to_dict(self):
        return {
            "id": self.id,
            "text": self.text,
            "visibility": self.visibility,
            "tag": self.tag,
            "path": self.path,
            "kind": self.kind,
            "offset": self.offset,
            "status": self.status,
            "label": self.label,
            "segment_path": self.segment_path,
            "segment_tag": self.segment_tag,
        }


@dataclass(frozen=True)
class TextRun:
    """A text or tail run in the sanitized output, with its sources."""

    text: str
    visibility: str
    sources: tuple[SourceRef, ...]
    kind: str
    tag: str
    path: str
    start: int
    end: int
    merged: bool

    @property
    def source_ids(self):
        return tuple(source.id for source in self.sources)

    @property
    def is_tail(self):
        return self.kind == "tail"

    @property
    def needs_review(self):
        return self.visibility == MIXED

    @property
    def review_required(self):
        return self.needs_review

    def to_dict(self):
        return {
            "text": self.text,
            "visibility": self.visibility,
            "review_required": self.review_required,
            "sources": [source.id for source in self.sources],
            "kind": self.kind,
            "tag": self.tag,
            "path": self.path,
            "start": self.start,
            "end": self.end,
            "merged": self.merged,
        }

    def __str__(self):
        return self.text


@dataclass(frozen=True)
class PublicationSegment:
    """One block-sized piece of the publication decision."""

    html: str
    text: str
    visibility: str
    status: str
    sources: tuple[SourceRef, ...]
    runs: tuple[TextRun, ...]
    tag: str
    path: str

    @property
    def published(self):
        return self.status == PUBLISHED

    @property
    def withheld(self):
        return self.status == WITHHELD

    @property
    def needs_review(self):
        return self.status == REVIEW

    @property
    def review_required(self):
        return self.needs_review

    @property
    def source_ids(self):
        return tuple(source.id for source in self.sources)

    def to_dict(self):
        return {
            "html": self.html,
            "text": self.text,
            "visibility": self.visibility,
            "status": self.status,
            "published": self.published,
            "review_required": self.review_required,
            "sources": [source.id for source in self.sources],
            "runs": [run.to_dict() for run in self.runs],
            "tag": self.tag,
            "path": self.path,
        }

    def __str__(self):
        return self.html


@dataclass(frozen=True)
class ReviewItem:
    """A sanitized segment which mixes public and internal source runs."""

    html: str
    text: str
    sources: tuple[SourceRef, ...]
    runs: tuple[TextRun, ...]
    tag: str
    path: str
    reason: str = "mixed_visibility"

    @property
    def visibility(self):
        return MIXED

    @property
    def needs_review(self):
        return True

    @property
    def review_required(self):
        return True

    @property
    def source_ids(self):
        return tuple(source.id for source in self.sources)

    def to_dict(self):
        return {
            "html": self.html,
            "text": self.text,
            "sources": [source.id for source in self.sources],
            "runs": [run.to_dict() for run in self.runs],
            "tag": self.tag,
            "path": self.path,
            "reason": self.reason,
            "visibility": MIXED,
            "review_required": True,
        }

    def __str__(self):
        return self.html


@dataclass(frozen=True)
class PublicationResult:
    """The publication artifact returned by a boundary check."""

    public_html: str
    segments: tuple[PublicationSegment, ...]
    text_runs: tuple[TextRun, ...]
    review: tuple[ReviewItem, ...]
    withheld: tuple[PublicationSegment, ...]
    sources: tuple[SourceRef, ...]

    @property
    def html(self):
        return self.public_html

    @property
    def published(self):
        return self.public_html

    @property
    def public(self):
        return self.public_html

    @property
    def published_html(self):
        return self.public_html

    @property
    def output(self):
        return self.public_html

    @property
    def needs_review(self):
        return bool(self.review)

    @property
    def review_required(self):
        return self.needs_review

    @property
    def has_review(self):
        return bool(self.review)

    @property
    def needs_manual_review(self):
        return bool(self.review)

    @property
    def review_count(self):
        return len(self.review)

    @property
    def ok(self):
        return not self.review

    @property
    def review_items(self):
        return self.review

    @property
    def review_segments(self):
        return self.review

    @property
    def manual_review(self):
        return self.review

    @property
    def internal(self):
        return self.withheld

    @property
    def review_html(self):
        return "".join(item.html for item in self.review)

    @property
    def withheld_html(self):
        return "".join(segment.html for segment in self.withheld)

    @property
    def internal_html(self):
        return self.withheld_html

    @property
    def public_segments(self):
        return tuple(segment for segment in self.segments if segment.published)

    @property
    def provenance(self):
        return self.text_runs

    @property
    def runs(self):
        return self.text_runs

    @property
    def review_queue(self):
        return self.review

    @property
    def source_map(self):
        return {source.id: source for source in self.sources}

    def to_dict(self):
        return {
            "public_html": self.public_html,
            "published": self.public_html,
            "review_required": self.needs_review,
            "review": [item.to_dict() for item in self.review],
            "review_html": self.review_html,
            "withheld": [segment.to_dict() for segment in self.withheld],
            "withheld_html": self.withheld_html,
            "segments": [segment.to_dict() for segment in self.segments],
            "text_runs": [run.to_dict() for run in self.text_runs],
            "sources": [source.to_dict() for source in self.sources],
        }


@dataclass(frozen=True)
class _Markers:
    start: str = "\ue000"
    sep: str = "\ue001"
    end: str = "\ue002"
    escape: str = "\ue003"

    def wrap(self, source_id, text):
        escaped = (
            text.replace(self.escape, self.escape + self.escape)
            .replace(self.start, self.escape + self.start)
            .replace(self.sep, self.escape + self.sep)
            .replace(self.end, self.escape + self.end)
        )
        return f"{self.start}{source_id}{self.sep}{escaped}{self.end}"


@dataclass
class _SourceRecord:
    sid: int
    text: str
    visibility: str
    tag: str
    path: str
    kind: str
    label: str | None
    offset: int
    segment_path: str
    segment_tag: str
    status: str = DROPPED


@dataclass
class _MarkedRange:
    sid: int
    clean_start: int
    clean_end: int
    text: str


@dataclass
class _Chunk:
    element: Any
    owner: Any
    kind: str
    raw_text: str
    clean_text: str = ""
    clean_start: int = 0
    clean_end: int = 0
    source_ids: tuple[int, ...] = ()
    visibility: str = NEUTRAL
    merged: bool = False


@dataclass
class _BlockRecord:
    element: Any
    tag: str
    path: str
    chunks: list[_Chunk] = field(default_factory=list)
    source_ids: tuple[int, ...] = ()
    visibility: str = PUBLIC
    status: str = PUBLISHED
    text: str = ""
    html: str = ""
    runs: tuple[TextRun, ...] = ()
    group_key: str | None = None
    flat_group: bool = False
    container: Any = None


def _parse_fragment(html):
    source = "<div>%s</div>" % html
    try:
        doc = lxml.html.fromstring(source)
        lxml.html.tostring(doc, encoding="utf-8")
    except Exception:
        from lxml.html import soupparser  # noqa: PLC0415

        doc = soupparser.fromstring(source)
    return doc


def _path(element):
    try:
        return element.getroottree().getpath(element)
    except (AttributeError, ValueError):
        return ""


def _normalize_visibility(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return PUBLIC if value else INTERNAL

    normalized = str(value).strip().lower()
    if normalized in PUBLIC_VALUES:
        return PUBLIC
    if normalized in INTERNAL_VALUES:
        return INTERNAL
    if normalized:
        # An unknown explicit permission fails closed.
        return INTERNAL
    return None


def _truthy_label(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return PUBLIC if value else INTERNAL
    normalized = str(value).strip().lower()
    if not normalized:
        return PUBLIC
    return _normalize_visibility(normalized)


def _confidential_label(value):
    if value is None:
        return None
    if isinstance(value, bool):
        return INTERNAL if value else PUBLIC
    normalized = str(value).strip().lower()
    if not normalized:
        return INTERNAL
    if normalized in {"0", "false", "no", "n", "f"}:
        return PUBLIC
    if normalized in {"public", "publish", "published", "external"}:
        return PUBLIC
    return INTERNAL


def _is_block(element):
    return isinstance(element.tag, str) and element.tag.lower() in BLOCK_TAGS


def _is_void_or_empty_allowed(element, empty):
    if not isinstance(element.tag, str):
        return False
    tag = element.tag.lower()
    return tag in VOID_TAGS or tag in empty


def _unique(values):
    seen = set()
    result = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return tuple(result)


def _parse_markers(flat, markers):
    """Remove provenance markers and return clean text plus source ranges."""

    clean_chars = []
    clean_raw = []
    ranges = []
    index = 0
    length = len(flat)

    while index < length:
        char = flat[index]
        if char == markers.escape:
            if index + 1 < length:
                clean_chars.append(flat[index + 1])
                clean_raw.append(index + 1)
                index += 2
            else:
                index += 1
            continue

        if char == markers.end:
            # A stray end marker can only be ours.
            index += 1
            continue

        if char != markers.start:
            clean_chars.append(char)
            clean_raw.append(index)
            index += 1
            continue

        digits_end = index + 1
        while digits_end < length and flat[digits_end].isdigit():
            digits_end += 1
        if (
            digits_end == index + 1
            or digits_end >= length
            or flat[digits_end] != markers.sep
        ):
            clean_chars.append(char)
            clean_raw.append(index)
            index += 1
            continue

        sid = int(flat[index + 1 : digits_end])
        content_index = digits_end + 1
        content_chars = []
        content_raw = []
        while content_index < length:
            char = flat[content_index]
            if char == markers.escape:
                if content_index + 1 < length:
                    content_chars.append(flat[content_index + 1])
                    content_raw.append(content_index + 1)
                    content_index += 2
                else:
                    content_index += 1
                continue
            if char == markers.end:
                break
            content_chars.append(char)
            content_raw.append(content_index)
            content_index += 1

        clean_start = len(clean_chars)
        clean_chars.extend(content_chars)
        clean_raw.extend(content_raw)
        ranges.append(
            _MarkedRange(
                sid=sid,
                clean_start=clean_start,
                clean_end=len(clean_chars),
                text="".join(content_chars),
            )
        )
        if content_index < length and flat[content_index] == markers.end:
            content_index += 1
        index = content_index

    return "".join(clean_chars), clean_raw, ranges


def _strip_markers(text, markers):
    if not text:
        return text
    return _parse_markers(text, markers)[0]


def _strip_markers_from_html(html, markers):
    return re.sub(
        rf"{re.escape(markers.start)}\d+{re.escape(markers.sep)}|{re.escape(markers.end)}",
        "",
        html,
    )


def _remove_keep_tail(element):
    parent = element.getparent()
    if parent is None:
        return
    tail = element.tail
    previous = element.getprevious()
    if tail:
        if previous is not None:
            previous.tail = (previous.tail or "") + tail
        else:
            parent.text = (parent.text or "") + tail
    parent.remove(element)


def _topmost_block_descendants(element):
    descendants = []
    for descendant in element.iterdescendants():
        if not _is_block(descendant):
            continue
        ancestor = descendant.getparent()
        topmost = True
        while ancestor is not None and ancestor is not element:
            if _is_block(ancestor):
                topmost = False
                break
            ancestor = ancestor.getparent()
        if topmost and ancestor is element:
            descendants.append(descendant)
    return descendants


def _depth(element):
    depth = 0
    while element.getparent() is not None:
        depth += 1
        element = element.getparent()
    return depth


class PublicationBoundary:
    """Check where public content ends in a trusted, cleaned document.

    ``sanitizer_or_settings`` may be a :class:`Sanitizer` instance or a
    settings mapping suitable for ``Sanitizer(...)``. The local configuration
    is used unchanged for the actual cleaning step. Set group_rows=True
    to treat complete table rows as atomic publication units.
    """

    def __init__(
        self,
        sanitizer_or_settings=None,
        *,
        sanitizer=None,
        settings=None,
        config=None,
        default_visibility=PUBLIC,
        label_attributes=None,
        class_labels=None,
        tag_labels=None,
        group_rows=False,
        group_by_rows=None,
    ):
        if (
            sum(
                value is not None
                for value in (sanitizer_or_settings, sanitizer, settings, config)
            )
            > 1
        ):
            raise TypeError(
                "Pass only one of sanitizer_or_settings, sanitizer, settings or config"
            )

        candidate = sanitizer_or_settings
        if candidate is None:
            candidate = sanitizer
        if candidate is None:
            candidate = settings if settings is not None else config

        if isinstance(candidate, Sanitizer):
            self.sanitizer = candidate
        else:
            self.sanitizer = Sanitizer(candidate)

        normalized_default = _normalize_visibility(default_visibility)
        if normalized_default not in {PUBLIC, INTERNAL}:
            raise ValueError("default_visibility must be 'public' or 'internal'")
        self.default_visibility = normalized_default
        if group_by_rows is not None:
            group_rows = group_by_rows
        self.group_rows = bool(group_rows)
        if label_attributes is None:
            label_attributes = DEFAULT_LABEL_ATTRIBUTES
        elif isinstance(label_attributes, str):
            label_attributes = (label_attributes,)
        self.label_attributes = tuple(label_attributes)
        self.class_labels = {
            key.lower(): value
            for key, value in (
                DEFAULT_CLASS_LABELS if class_labels is None else class_labels
            ).items()
        }
        self.tag_labels = {
            key.lower(): value
            for key, value in (
                DEFAULT_TAG_LABELS if tag_labels is None else tag_labels
            ).items()
        }

    def __call__(self, document):
        return self.check(document)

    def check(self, document):
        """Return a :class:`PublicationResult` for ``document``."""

        html = self._coerce_document(document)
        sources = []
        source_by_id = {}
        markers = _Markers()
        sanitized_html = self.sanitizer.sanitize(
            html,
            annotate=lambda doc: self._annotate_tree(
                doc, markers, sources, source_by_id
            ),
        )
        doc = _parse_fragment(sanitized_html)
        chunks, ranges = self._collect_chunks(doc, source_by_id, markers)
        blocks = self._collect_blocks(doc, chunks, source_by_id, markers, ranges)
        self._finalize_source_status(sources, ranges, blocks)

        final_sources = self._final_source_refs(sources)
        runs, run_by_chunk = self._build_runs(chunks, final_sources)
        group_runs = []
        for block in blocks:
            if block.flat_group:
                block_ranges = [
                    marked_range
                    for marked_range in ranges
                    if marked_range.sid in set(block.source_ids)
                ]
                run = TextRun(
                    text=block.text,
                    visibility=block.visibility,
                    sources=tuple(
                        final_sources[sid]
                        for sid in block.source_ids
                        if sid in final_sources
                    ),
                    kind="text",
                    tag=block.tag,
                    path=block.path,
                    start=min((item.clean_start for item in block_ranges), default=0),
                    end=max((item.clean_end for item in block_ranges), default=0),
                    merged=len(block.source_ids) > 1,
                )
                block.runs = (run,)
                group_runs.append(run)
            else:
                block.runs = tuple(
                    run_by_chunk[id(chunk)]
                    for chunk in block.chunks
                    if id(chunk) in run_by_chunk
                )

        if group_runs:
            root_chunk_ids = {
                id(chunk)
                for chunk in chunks
                if self._nearest_block(
                    chunk.element if chunk.kind == "text" else chunk.owner, doc
                )
                is doc
            }
            runs = tuple(
                run_by_chunk[id(chunk)]
                for chunk in chunks
                if id(chunk) in run_by_chunk and id(chunk) not in root_chunk_ids
            ) + tuple(group_runs)

        segments = self._build_segments(blocks, final_sources)
        review = tuple(
            ReviewItem(
                html=block.html,
                text=block.text.strip(),
                sources=tuple(final_sources[sid] for sid in block.source_ids),
                runs=block.runs,
                tag=block.tag,
                path=block.path,
            )
            for block in blocks
            if block.status == REVIEW
        )
        withheld = tuple(segment for segment in segments if segment.status == WITHHELD)

        if all(source.visibility == PUBLIC for source in sources):
            public_html = _strip_markers_from_html(sanitized_html, markers)
        else:
            public_html = self._render_public_html(doc, blocks, chunks, markers, ranges)

        return PublicationResult(
            public_html=public_html,
            segments=segments,
            text_runs=runs,
            review=review,
            withheld=withheld,
            sources=tuple(final_sources[sid] for sid in sorted(final_sources)),
        )

    publish = check
    check_document = check
    publication_result = check

    def _coerce_document(self, document):
        if isinstance(document, bytes):
            return document.decode("utf-8")
        if isinstance(document, str):
            return document
        if isinstance(document, Mapping):
            if "segments" in document:
                return self._segments_to_html(document["segments"])
            if any(
                key in document
                for key in (
                    "visibility",
                    "publish",
                    "publication",
                    "audience",
                    "access",
                    "permission",
                    "release",
                    "tag",
                )
            ):
                return self._segments_to_html([document])
            if "html" in document:
                return str(document["html"])
            if "content" in document:
                return str(document["content"])
            if "text" in document:
                return _html.escape(str(document["text"]), quote=False)
        if isinstance(document, (list, tuple)):
            return self._segments_to_html(document)
        if isinstance(document, Iterable) and not isinstance(
            document, (str, bytes, Mapping)
        ):
            return self._segments_to_html(document)
        if hasattr(document, "text"):
            return self._segments_to_html([document])
        raise TypeError(
            "Expected an HTML string or a sequence of annotated text segments"
        )

    def _segments_to_html(self, segments):
        parts = []
        for segment in segments:
            raw = False
            label = None
            visibility = self.default_visibility
            tag = "p"

            if isinstance(segment, str):
                content = _html.escape(segment, quote=False)
            elif isinstance(segment, Mapping):
                raw = "html" in segment
                tag = "span" if raw else tag
                content = segment.get("html")
                if content is None:
                    content = segment.get("text", segment.get("content", ""))
                if not raw:
                    content = _html.escape(str(content), quote=False)
                visibility = self._first_value(
                    segment,
                    (
                        "visibility",
                        "publish",
                        "publication",
                        "audience",
                        "access",
                        "permission",
                        "release",
                    ),
                    visibility,
                )
                label = self._first_value(
                    segment, ("source", "source_id", "label", "origin"), None
                )
                tag = segment.get("tag", tag)
            elif isinstance(segment, (list, tuple)) and len(segment) >= 2:
                content = _html.escape(str(segment[0]), quote=False)
                visibility = segment[1]
                if len(segment) > 2:
                    label = segment[2]
            elif hasattr(segment, "text"):
                content = _html.escape(str(segment.text), quote=False)
                visibility = getattr(
                    segment, "visibility", getattr(segment, "publish", visibility)
                )
                label = getattr(segment, "source", getattr(segment, "label", None))
                tag = getattr(segment, "tag", tag)
            else:
                raise TypeError(f"Unsupported segment: {segment!r}")

            norm_visibility = _normalize_visibility(visibility)
            if norm_visibility not in {PUBLIC, INTERNAL}:
                norm_visibility = INTERNAL
            attrs = f' data-publish="{_html.escape(norm_visibility)}"'
            if label is not None:
                attrs += f' data-source="{_html.escape(str(label))}"'
            parts.append(f"<{tag}{attrs}>{content}</{tag}>")
        return "".join(parts)

    @staticmethod
    def _first_value(mapping, keys, default):
        for key in keys:
            if key in mapping and mapping[key] is not None:
                return mapping[key]
        return default

    def _visibility_from_element(self, element):
        if not isinstance(element.tag, str):
            return None

        candidates = []
        attributes = element.attrib
        for name in self.label_attributes:
            if name not in attributes:
                continue
            value = attributes.get(name)
            if name in {"data-public", "data-publishable"}:
                candidates.append(_truthy_label(value))
            elif name in {"data-confidential", "data-private"}:
                candidates.append(_confidential_label(value))
            else:
                candidates.append(_normalize_visibility(value))

        tag_label = self.tag_labels.get(element.tag.lower())
        if tag_label is not None:
            candidates.append(tag_label)

        class_label = None
        for token in (attributes.get("class") or "").split():
            value = self.class_labels.get(token.lower())
            if value == INTERNAL:
                return INTERNAL
            if value == PUBLIC:
                class_label = PUBLIC
        if class_label is not None:
            candidates.append(class_label)

        valid = [value for value in candidates if value in {PUBLIC, INTERNAL}]
        if INTERNAL in valid:
            return INTERNAL
        if PUBLIC in valid:
            return PUBLIC
        return None

    def _source_label(self, element):
        for name in (
            "data-source",
            "data-source-id",
            "data-origin",
            "data-annotation",
            "id",
        ):
            value = element.attrib.get(name)
            if value:
                return value
        return None

    def _annotate(self, html):
        doc = _parse_fragment(html)
        sources, source_by_id, markers = self._annotate_tree(doc)
        annotated = lxml.html.tostring(doc, encoding="unicode")
        annotated = re.sub(r"^<div>|</div>$", "", annotated)
        return annotated, sources, source_by_id, markers

    def _annotate_tree(self, doc, markers=None, sources=None, source_by_id=None):
        markers = _Markers() if markers is None else markers
        sources = [] if sources is None else sources
        source_by_id = {} if source_by_id is None else source_by_id
        offset = 0

        def mark_run(text, visibility, label, owner, tag, kind, path):
            nonlocal offset
            run_offset = offset
            offset += len(text)

            filtered = filter_control_characters(text)
            if not filtered or self.sanitizer.only_whitespace_re.match(filtered):
                return text

            prefix = ""
            content = text
            if tag in {"li", "p"}:
                match = re.match(r"^(\s*(?:-|\*|&#183;)\s+)", text)
                if match:
                    prefix = text[: match.end()]
                    content = text[match.end() :]
                    filtered_content = filter_control_characters(content)
                    if not filtered_content or self.sanitizer.only_whitespace_re.match(
                        filtered_content
                    ):
                        return text

            # Keep leading/trailing whitespace outside the marker. The
            # sanitizer merges and normalizes adjacent whitespace runs; keeping
            # the marker out of those runs makes the provenance pass produce
            # the same whitespace as a plain sanitization pass. Whitespace
            # never carries a meaningful publication permission on its own.
            whitespace_pattern = self.sanitizer.whitespace_re.pattern
            leading_match = re.match(whitespace_pattern, content)
            leading = leading_match.group(0) if leading_match else ""
            core = content[len(leading) :]
            trailing_match = re.search(rf"(?:{whitespace_pattern})$", core)
            trailing = trailing_match.group(0) if trailing_match else ""
            if trailing:
                core = core[: -len(trailing)]
            if not core:
                return text

            segment = (
                self._nearest_row_segment(owner, doc)
                if self.group_rows
                else self._nearest_block(owner, doc)
            )
            segment_tag = segment.tag if isinstance(segment.tag, str) else ""
            sid = len(sources) + 1
            record = _SourceRecord(
                sid=sid,
                text=text,
                visibility=visibility,
                tag=tag,
                path=path,
                kind=kind,
                label=label,
                offset=run_offset,
                segment_path=_path(segment),
                segment_tag=segment_tag,
            )
            sources.append(record)
            source_by_id[sid] = record
            return prefix + leading + markers.wrap(sid, core) + trailing

        def walk(element, inherited_visibility, inherited_label):
            if not isinstance(element.tag, str):
                return

            visibility = self._visibility_from_element(element) or inherited_visibility
            label = self._source_label(element) or inherited_label
            path = _path(element)

            if element.tag.lower() in IGNORED_TEXT_TAGS:
                return

            if element.text:
                element.text = mark_run(
                    element.text,
                    visibility,
                    label,
                    element,
                    element.tag,
                    "text",
                    path,
                )

            for child in list(element):
                walk(child, visibility, label)
                if child.tail:
                    child.tail = mark_run(
                        child.tail,
                        visibility,
                        label,
                        element,
                        element.tag,
                        "tail",
                        _path(child),
                    )

        walk(doc, self.default_visibility, None)
        return sources, source_by_id, markers

    def _collect_chunks(self, doc, source_by_id, markers):
        chunks = []

        def walk(element):
            if element.text:
                chunks.append(
                    _Chunk(
                        element=element,
                        owner=element,
                        kind="text",
                        raw_text=element.text,
                    )
                )
            for child in list(element):
                if isinstance(child.tag, str):
                    walk(child)
                if child.tail:
                    chunks.append(
                        _Chunk(
                            element=child,
                            owner=element,
                            kind="tail",
                            raw_text=child.tail,
                        )
                    )

        walk(doc)

        flat_parts = []
        char_chunk = []
        for chunk_index, chunk in enumerate(chunks):
            flat_parts.append(chunk.raw_text)
            char_chunk.extend([chunk_index] * len(chunk.raw_text))

        _clean, clean_raw, ranges = _parse_markers("".join(flat_parts), markers)
        parts_by_chunk = [[] for _ in chunks]
        for clean_index, raw_index in enumerate(clean_raw):
            parts_by_chunk[char_chunk[raw_index]].append(_clean[clean_index])

        cursor = 0
        for chunk, parts in zip(chunks, parts_by_chunk):
            chunk.clean_text = "".join(parts)
            chunk.clean_start = cursor
            cursor += len(chunk.clean_text)
            chunk.clean_end = cursor

        for chunk in chunks:
            ids = []
            for marked_range in ranges:
                if not marked_range.text:
                    continue
                if self.sanitizer.only_whitespace_re.match(marked_range.text):
                    continue
                if (
                    marked_range.clean_end > chunk.clean_start
                    and marked_range.clean_start < chunk.clean_end
                ):
                    ids.append(marked_range.sid)
            chunk.source_ids = _unique(ids)
            chunk.visibility = self._visibility_for_ids(chunk.source_ids, source_by_id)
            chunk.merged = len(chunk.source_ids) > 1

        return chunks, ranges

    def _visibility_for_ids(self, source_ids, source_by_id):
        visibilities = {
            source_by_id[sid].visibility for sid in source_ids if sid in source_by_id
        }
        if PUBLIC in visibilities and INTERNAL in visibilities:
            return MIXED
        if INTERNAL in visibilities:
            return INTERNAL
        if PUBLIC in visibilities:
            return PUBLIC
        return NEUTRAL

    def _collect_blocks(self, doc, chunks, source_by_id, markers, ranges):
        block_map = {}
        blocks = []

        for chunk in chunks:
            start = chunk.element if chunk.kind == "text" else chunk.owner
            block_element = self._nearest_block(start, doc)
            block = block_map.get(block_element)
            if block is None:
                block = _BlockRecord(
                    element=block_element,
                    tag=block_element.tag if isinstance(block_element.tag, str) else "",
                    path=_path(block_element),
                )
                block_map[block_element] = block
                blocks.append(block)
            block.chunks.append(chunk)

        for block in blocks:
            ids = []
            for chunk in block.chunks:
                ids.extend(chunk.source_ids)
            block.source_ids = _unique(ids)
            block.visibility = self._block_visibility(block, source_by_id)
            block.status = self._status_for_visibility(block.visibility)
            block.text = "".join(chunk.clean_text for chunk in block.chunks)
            block.html = self._render_block_html(block, markers, doc)

        root_block = block_map.get(doc)
        expanded = blocks
        if root_block is not None:
            segment_keys = _unique(
                source_by_id[sid].segment_path
                for sid in root_block.source_ids
                if sid in source_by_id
            )
            if len(segment_keys) > 1:
                groups = self._root_block_groups(
                    root_block, segment_keys, ranges, source_by_id
                )
                expanded = []
                for block in blocks:
                    if block is root_block:
                        expanded.extend(groups)
                    else:
                        expanded.append(block)
        if self.group_rows:
            return self._group_table_rows(expanded, source_by_id, markers, doc)
        return expanded

    def _root_block_groups(self, block, segment_keys, ranges, source_by_id):
        groups = []
        for key in segment_keys:
            ids = tuple(
                sid for sid in block.source_ids if source_by_id[sid].segment_path == key
            )
            id_set = set(ids)
            group_ranges = [
                marked_range for marked_range in ranges if marked_range.sid in id_set
            ]
            text = "".join(marked_range.text for marked_range in group_ranges)
            source = source_by_id[ids[0]]
            group = _BlockRecord(
                element=block.element,
                tag=source.segment_tag or "text",
                path=key,
                source_ids=ids,
                visibility=self._visibility_for_ids(ids, source_by_id),
                text=text,
                html=_html.escape(text, quote=False),
                group_key=key,
                flat_group=True,
            )
            group.status = self._status_for_visibility(group.visibility)
            groups.append(group)
        return groups

    @staticmethod
    def _status_for_visibility(visibility):
        if visibility == MIXED:
            return REVIEW
        if visibility == INTERNAL:
            return WITHHELD
        return PUBLISHED

    def _group_table_rows(self, blocks, source_by_id, markers, doc):
        row_members = {}
        row_order = []
        for block in blocks:
            if block.flat_group or block.element is doc:
                continue
            if not block.source_ids:
                continue
            sources = [
                source_by_id[sid] for sid in block.source_ids if sid in source_by_id
            ]
            if not sources or any(source.segment_tag != "tr" for source in sources):
                continue
            keys = _unique(source.segment_path for source in sources)
            if len(keys) != 1:
                continue
            key = keys[0]
            if key not in row_members:
                row_members[key] = []
                row_order.append(key)
            row_members[key].append(block)

        if not any(len(members) > 1 for members in row_members.values()):
            return blocks

        first_by_id = {id(block): block for block in blocks}
        grouped = {}
        for key in row_order:
            members = row_members[key]
            if len(members) < 2:
                continue
            grouped[id(members[0])] = self._merge_row_blocks(
                members, source_by_id, markers
            )
            for member in members[1:]:
                grouped[id(member)] = None

        result = []
        for block in blocks:
            replacement = grouped.get(id(block), first_by_id[id(block)])
            if replacement is not None:
                result.append(replacement)
        return result

    def _merge_row_blocks(self, members, source_by_id, markers):
        first = members[0]
        source_ids = _unique(sid for member in members for sid in member.source_ids)
        row_key = source_by_id[first.source_ids[0]].segment_path
        visibility = self._visibility_for_ids(source_ids, source_by_id)
        common = self._common_ancestor([member.element for member in members])
        if (
            common is not None
            and isinstance(common.tag, str)
            and common.tag.lower() == "tr"
        ):
            html = self._render_element_html(common, markers)
        else:
            html = "".join(member.html for member in members)
        return _BlockRecord(
            element=first.element,
            tag="tr",
            path=row_key,
            chunks=[chunk for member in members for chunk in member.chunks],
            source_ids=source_ids,
            visibility=visibility,
            status=self._status_for_visibility(visibility),
            text="".join(member.text for member in members),
            html=html,
            group_key=row_key,
            container=common
            if common is not None
            and isinstance(common.tag, str)
            and common.tag.lower() == "tr"
            else None,
        )

    def _render_element_html(self, element, markers):
        clone = copy.deepcopy(element)
        self._strip_tree_markers(clone, markers)
        rendered = lxml.html.tostring(clone, encoding="unicode", with_tail=False)
        return re.sub(r"<([^/>]+)/>", r"<\1 />", rendered)

    @staticmethod
    def _common_ancestor(elements):
        if not elements:
            return None
        first = elements[0]
        candidates = [first, *first.iterancestors()]
        for candidate in candidates:
            if all(
                PublicationBoundary._is_within(element, candidate)
                for element in elements[1:]
            ):
                return candidate
        return None

    @staticmethod
    def _is_within(element, ancestor):
        current = element
        while current is not None:
            if current is ancestor:
                return True
            current = current.getparent()
        return False

    @staticmethod
    def _nearest_row_segment(element, root):
        current = element
        fallback = None
        while current is not None:
            if isinstance(current.tag, str):
                tag = current.tag.lower()
                if tag == "tr":
                    return current
                if fallback is None and (current is root or tag in BLOCK_TAGS):
                    fallback = current
            if current is root:
                break
            current = current.getparent()
        return fallback if fallback is not None else root

    @staticmethod
    def _nearest_block(element, root):
        current = element
        while current is not None:
            if current is root or _is_block(current):
                return current
            current = current.getparent()
        return root

    def _block_visibility(self, block, source_by_id):
        visibilities = {
            source_by_id[sid].visibility
            for sid in block.source_ids
            if sid in source_by_id
        }
        if PUBLIC in visibilities and INTERNAL in visibilities:
            return MIXED
        if INTERNAL in visibilities:
            return INTERNAL
        if PUBLIC in visibilities:
            return PUBLIC
        if any(chunk.visibility == MIXED for chunk in block.chunks):
            return MIXED
        return PUBLIC

    def _render_block_html(self, block, markers, document):
        root = block.element is document
        clone = copy.deepcopy(block.element)
        for descendant in _topmost_block_descendants(clone):
            _remove_keep_tail(descendant)
        self._strip_tree_markers(clone, markers)
        rendered = lxml.html.tostring(clone, encoding="unicode", with_tail=False)
        if root:
            rendered = re.sub(r"^<div>|</div>$", "", rendered)
        return re.sub(r"<([^/>]+)/>", r"<\1 />", rendered)

    @staticmethod
    def _strip_tree_markers(element, markers):
        element.text = _strip_markers(element.text, markers)
        for child in element:
            PublicationBoundary._strip_tree_markers(child, markers)
            child.tail = _strip_markers(child.tail, markers)

    def _finalize_source_status(self, sources, ranges, blocks):
        found = {
            marked_range.sid
            for marked_range in ranges
            if marked_range.text
            and not self.sanitizer.only_whitespace_re.match(marked_range.text)
        }
        priority = {DROPPED: 0, PUBLISHED: 1, WITHHELD: 2, REVIEW: 3}
        source_by_sid = {source.sid: source for source in sources}
        for source in sources:
            source.status = PUBLISHED if source.sid in found else DROPPED

        for block in blocks:
            for sid in block.source_ids:
                source = source_by_sid.get(sid)
                if source is None:
                    continue
                if priority[block.status] > priority[source.status]:
                    source.status = block.status

    @staticmethod
    def _final_source_refs(sources):
        return {
            source.sid: SourceRef(
                id=f"s{source.sid}",
                text=source.text,
                visibility=source.visibility,
                tag=source.tag,
                path=source.path,
                kind=source.kind,
                offset=source.offset,
                status=source.status,
                label=source.label,
                segment_path=source.segment_path,
                segment_tag=source.segment_tag,
            )
            for source in sources
        }

    def _build_runs(self, chunks, final_sources):
        runs = []
        run_by_chunk = {}
        for chunk in chunks:
            if not chunk.clean_text and not chunk.source_ids:
                continue
            if not chunk.source_ids and not chunk.clean_text.strip():
                continue
            run = TextRun(
                text=chunk.clean_text,
                visibility=chunk.visibility,
                sources=tuple(
                    final_sources[sid]
                    for sid in chunk.source_ids
                    if sid in final_sources
                ),
                kind=chunk.kind,
                tag=chunk.element.tag if chunk.kind == "text" else chunk.owner.tag,
                path=_path(chunk.element if chunk.kind == "text" else chunk.owner),
                start=chunk.clean_start,
                end=chunk.clean_end,
                merged=chunk.merged,
            )
            runs.append(run)
            run_by_chunk[id(chunk)] = run
        return tuple(runs), run_by_chunk

    def _build_segments(self, blocks, final_sources):
        segments = []
        for block in blocks:
            if not block.source_ids and not block.text.strip():
                continue
            segments.append(
                PublicationSegment(
                    html=block.html,
                    text=block.text,
                    visibility=block.visibility,
                    status=block.status,
                    sources=tuple(
                        final_sources[sid]
                        for sid in block.source_ids
                        if sid in final_sources
                    ),
                    runs=block.runs,
                    tag=block.tag,
                    path=block.path,
                )
            )
        return tuple(segments)

    def _render_public_html(self, doc, blocks, chunks, markers, ranges):
        affected = set()
        for chunk in chunks:
            self._set_chunk_text(chunk, chunk.clean_text)

        range_intervals = []
        non_public_ids = {
            sid
            for block in blocks
            if block.status in {REVIEW, WITHHELD}
            for sid in block.source_ids
        }
        for block in blocks:
            if block.status not in {REVIEW, WITHHELD}:
                continue
            if block.flat_group:
                id_set = set(block.source_ids)
                range_intervals.extend(
                    (marked_range.clean_start, marked_range.clean_end)
                    for marked_range in ranges
                    if marked_range.sid in id_set
                    and marked_range.clean_end > marked_range.clean_start
                )
                continue

            affected.add(block.element)
            affected.update(self._ancestors(block.element))
            for chunk in block.chunks:
                self._set_chunk_text(chunk, None)
                owner = chunk.element if chunk.kind == "text" else chunk.owner
                affected.add(owner)
                affected.update(self._ancestors(owner))

            if block.container is not None:
                parent = block.container.getparent()
                _remove_keep_tail(block.container)
                if parent is not None:
                    affected.add(parent)
                    affected.update(self._ancestors(parent))
            else:
                self._remove_inline_children(block.element)
                for chunk in block.chunks:
                    owner = chunk.element if chunk.kind == "text" else chunk.owner
                    self._remove_inline_children(owner)

        if range_intervals:
            self._remove_clean_ranges(chunks, range_intervals, affected, non_public_ids)

        root = doc
        for element in sorted(
            {
                element
                for element in affected
                if element is not None and element is not root
            },
            key=_depth,
            reverse=True,
        ):
            if not isinstance(element.tag, str):
                continue
            if _is_void_or_empty_allowed(element, self.sanitizer.empty):
                continue
            if element.getparent() is None:
                continue
            if len(element) == 0 and (
                not element.text
                or self.sanitizer.only_whitespace_re.match(element.text)
            ):
                element.drop_tag()

        rendered = lxml.html.tostring(doc, encoding="unicode")
        rendered = re.sub(r"<([^/>]+)/>", r"<\1 />", rendered)
        rendered = re.sub(r"^<div>|</div>$", "", rendered)
        return re.sub(
            rf"{re.escape(markers.start)}\d+{re.escape(markers.sep)}|{re.escape(markers.end)}",
            "",
            rendered,
        )

    @staticmethod
    def _remove_inline_children(element):
        if not isinstance(element.tag, str):
            return
        for child in list(element):
            if not isinstance(child.tag, str) or child.tag.lower() not in BLOCK_TAGS:
                element.remove(child)

    @staticmethod
    def _set_chunk_text(chunk, text):
        if chunk.kind == "text":
            chunk.element.text = text
        else:
            chunk.element.tail = text

    @staticmethod
    def _chunk_text(chunk):
        if chunk.kind == "text":
            return chunk.element.text
        return chunk.element.tail

    def _remove_clean_ranges(self, chunks, range_intervals, affected, non_public_ids):
        intervals = sorted(range_intervals)
        for chunk in chunks:
            current = self._chunk_text(chunk)
            if not current:
                continue
            local = []
            for start, end in intervals:
                low = max(start, chunk.clean_start)
                high = min(end, chunk.clean_end)
                if high > low:
                    local.append((low - chunk.clean_start, high - chunk.clean_start))
            if not local:
                continue

            pieces = []
            cursor = 0
            for raw_start, end_offset in sorted(local):
                if end_offset <= cursor:
                    continue
                clipped_start = max(raw_start, cursor)
                pieces.append(current[cursor:clipped_start])
                cursor = end_offset
            pieces.append(current[cursor:])
            self._set_chunk_text(chunk, "".join(pieces))
            self._remove_adjacent_voids(chunk, non_public_ids)
            owner = chunk.element if chunk.kind == "text" else chunk.owner
            affected.add(owner)
            affected.update(self._ancestors(owner))

    def _remove_adjacent_voids(self, chunk, non_public_ids):
        if chunk.kind == "tail":
            element = chunk.element
            if (
                isinstance(element.tag, str)
                and element.tag.lower() in VOID_TAGS
                and chunk.source_ids
                and set(chunk.source_ids) <= non_public_ids
            ):
                parent = element.getparent()
                if parent is not None:
                    parent.remove(element)
            return

        element = chunk.element
        previous = element.getprevious()
        while (
            previous is not None
            and isinstance(previous.tag, str)
            and previous.tag.lower() in VOID_TAGS
            and (
                not previous.tail
                or self.sanitizer.only_whitespace_re.match(previous.tail)
            )
        ):
            before = previous.getprevious()
            parent = previous.getparent()
            if parent is not None:
                parent.remove(previous)
            previous = before

        following = element.getnext()
        while (
            following is not None
            and isinstance(following.tag, str)
            and following.tag.lower() in VOID_TAGS
            and (
                not following.tail
                or self.sanitizer.only_whitespace_re.match(following.tail)
            )
        ):
            after = following.getnext()
            parent = following.getparent()
            if parent is not None:
                parent.remove(following)
            following = after

        for child in list(element):
            if (
                isinstance(child.tag, str)
                and child.tag.lower() in VOID_TAGS
                and (
                    not child.tail
                    or self.sanitizer.only_whitespace_re.match(child.tail)
                )
            ):
                element.remove(child)
            else:
                break

    @staticmethod
    def _ancestors(element):
        ancestors = []
        current = element.getparent()
        while current is not None:
            ancestors.append(current)
            current = current.getparent()
        return ancestors


def check_publication(document, config=None, **kwargs):
    """Convenience wrapper around :class:`PublicationBoundary`."""

    if isinstance(config, PublicationBoundary):
        return config.check(document)
    return PublicationBoundary(config, **kwargs).check(document)


PublishBoundary = PublicationBoundary
PublicationBoundaryCheck = PublicationBoundary


def publication_html(document, config=None, **kwargs):
    """Return only the publishable HTML for document."""

    return check_publication(document, config, **kwargs).public_html


check_publication_boundary = check_publication
check_publish_boundary = check_publication
publication_boundary = check_publication
publication_check = check_publication
sanitize_for_publication = check_publication
sanitize_with_provenance = check_publication
