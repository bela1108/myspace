import re
import unicodedata
from dataclasses import dataclass
from dataclasses import field

import lxml.etree
import lxml.html

from .sanitizer import DEFAULT_SETTINGS
from .sanitizer import Sanitizer


__all__ = (
    "PublicationBoundary",
    "PublicationBoundaryCheck",
    "PublicationResult",
    "PublicationReview",
    "PublicationSanitizer",
    "PublicationSource",
    "ProvenanceSpan",
    "check_publication_boundary",
)


MARKER_START = "\ue000"
MARKER_END = "\ue001"
MARKER_ESCAPE = "\ue002"

_MARKER_RE = re.compile(
    rf"(?<!{re.escape(MARKER_ESCAPE)}){re.escape(MARKER_START)}([0-9]+){re.escape(MARKER_END)}"
)
_IGNORED_TEXT_PATTERN = rf"(?<!{re.escape(MARKER_ESCAPE)}){re.escape(MARKER_START)}[0-9]+{re.escape(MARKER_END)}"

_DEFAULT_ANNOTATION_ATTRIBUTES = (
    "data-publication",
    "data-publish",
    "data-visibility",
    "data-audience",
    "data-access",
    "data-permission",
    "data-scope",
    "data-classification",
    "publication",
    "publish",
    "visibility",
    "audience",
    "access",
    "scope",
)

_PUBLIC_ATTRIBUTES = ("data-public", "public", "is-public", "data-publishable")
_INTERNAL_ATTRIBUTES = (
    "data-internal",
    "internal",
    "private",
    "data-private",
    "is-internal",
    "restricted",
    "data-restricted",
)

_PUBLIC_VALUES = {
    "1",
    "true",
    "yes",
    "y",
    "on",
    "public",
    "publish",
    "published",
    "publishable",
    "open",
    "external",
    "publication",
}
_INTERNAL_VALUES = {
    "0",
    "false",
    "no",
    "n",
    "off",
    "internal",
    "private",
    "restricted",
    "confidential",
    "draft",
    "staff",
    "teacher",
    "note",
    "review",
    "internal-only",
}
_AMBIGUOUS_VALUES = {"mixed", "ambiguous", "unknown", "unset", "auto"}

_PUBLIC_CLASSES = {
    "public",
    "publish",
    "published",
    "publishable",
    "is-public",
    "publication-public",
}
_INTERNAL_CLASSES = {
    "internal",
    "private",
    "restricted",
    "confidential",
    "draft",
    "is-internal",
    "publication-internal",
    "teacher-note",
    "lesson-note",
    "prep-note",
    "internal-note",
}

_PUBLIC_TAGS = {"public", "publishable", "published"}
_INTERNAL_TAGS = {"internal", "private", "restricted", "internal-note"}

_DEFAULT_REVIEW_TAGS = (
    "address",
    "article",
    "aside",
    "blockquote",
    "caption",
    "dd",
    "div",
    "dl",
    "dt",
    "figcaption",
    "figure",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "li",
    "p",
    "pre",
    "section",
    "td",
    "th",
)
_TABLE_REVIEW_TAGS = {"caption", "tr", "td", "th", "thead", "tbody", "tfoot"}

_PUBLICATION_SETTINGS = {
    "annotator",
    "annotation_attribute",
    "annotation_attributes",
    "default_visibility",
    "include_internal_in_provenance",
    "internal_values",
    "mixed_policy",
    "public_values",
    "review_tags",
    "strip_annotation_attributes",
}


def _marker(source_id):
    return f"{MARKER_START}{source_id}{MARKER_END}"


def _escape_marker_characters(text):
    return (
        text.replace(MARKER_ESCAPE, f"{MARKER_ESCAPE}{MARKER_ESCAPE}")
        .replace(MARKER_START, f"{MARKER_ESCAPE}{MARKER_START}")
        .replace(MARKER_END, f"{MARKER_ESCAPE}{MARKER_END}")
    )


def _unescape_marker_characters(text):
    return (
        text.replace(f"{MARKER_ESCAPE}{MARKER_START}", MARKER_START)
        .replace(f"{MARKER_ESCAPE}{MARKER_END}", MARKER_END)
        .replace(f"{MARKER_ESCAPE}{MARKER_ESCAPE}", MARKER_ESCAPE)
    )


def _decode_marked_text(text):
    if not text:
        return []

    matches = list(_MARKER_RE.finditer(text))
    if not matches:
        return [(None, _unescape_marker_characters(text))]

    runs = []
    if matches[0].start():
        runs.append((None, _unescape_marker_characters(text[: matches[0].start()])))

    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        run_text = text[match.end() : end]
        if run_text:
            runs.append((int(match.group(1)), _unescape_marker_characters(run_text)))
    return runs


def _strip_markers(text):
    runs = _decode_marked_text(text)
    return "".join(run_text for _, run_text in runs)


def _element_path(element):
    try:
        return element.getroottree().getpath(element)
    except (AttributeError, ValueError):
        return ""


def _element_label(element):
    for attribute in ("id", "data-source", "data-name"):
        value = element.get(attribute)
        if value:
            return value
    return _element_path(element)


def _normalize_visibility(value):
    if not isinstance(value, str):
        return None
    value = value.strip().lower()
    if not value:
        return None
    if value in _PUBLIC_VALUES:
        return "public"
    if value in _INTERNAL_VALUES:
        return "internal"
    if value in _AMBIGUOUS_VALUES:
        return "mixed"
    return None


def _merge_visibility(left, right):
    if left is None:
        return right
    if right is None:
        return left
    if left == right:
        return left
    return "mixed"


def _text_visibility(sources):
    visibility = None
    for source in sources:
        visibility = _merge_visibility(visibility, source.visibility)
    return visibility or "public"


@dataclass(frozen=True)
class PublicationSource:
    """The annotated source region a piece of output text came from."""

    id: int
    visibility: str
    path: str
    tag: str
    label: str | None = None
    attribute: str | None = None
    value: str | None = None
    explicit: bool = True

    @property
    def is_public(self):
        return self.visibility == "public"

    @property
    def is_internal(self):
        return self.visibility == "internal"

    @property
    def location(self):
        return self.path

    @property
    def source(self):
        return self.path

    def __str__(self):
        return self.label or self.path


@dataclass
class ProvenanceSpan:
    """A text run in the sanitized artifact and the sources it came from."""

    text: str
    sources: tuple[PublicationSource, ...]
    visibility: str
    path: str
    tag: str
    role: str
    index: int
    published: bool
    needs_review: bool
    reason: str | None = None
    element: object = field(default=None, repr=False, compare=False)
    container: object = field(default=None, repr=False, compare=False)

    @property
    def source(self):
        return self.sources[0] if self.sources else None

    @property
    def origin(self):
        return self.source

    @property
    def source_paths(self):
        return tuple(source.path for source in self.sources)

    @property
    def source_ids(self):
        return tuple(source.id for source in self.sources)

    @property
    def is_public(self):
        return self.visibility == "public"

    @property
    def is_internal(self):
        return self.visibility == "internal"

    @property
    def parts(self):
        return tuple((source, self.text) for source in self.sources)


@dataclass
class PublicationReview:
    """A publication unit which cannot be published without human review."""

    text: str
    html: str
    sources: tuple[PublicationSource, ...]
    spans: tuple[ProvenanceSpan, ...]
    path: str
    tag: str
    reason: str

    @property
    def needs_review(self):
        return True

    @property
    def visibility(self):
        return "mixed"

    @property
    def source(self):
        return self.sources[0] if self.sources else None

    @property
    def source_paths(self):
        return tuple(source.path for source in self.sources)

    @property
    def source_ids(self):
        return tuple(source.id for source in self.sources)


@dataclass
class PublicationResult:
    """The published HTML plus provenance and quarantine information."""

    html: str
    provenance: list[ProvenanceSpan] = field(default_factory=list)
    reviews: list[PublicationReview] = field(default_factory=list)
    sources: dict[int, PublicationSource] = field(default_factory=dict)

    @property
    def published_html(self):
        return self.html

    @property
    def published(self):
        return self.html

    @property
    def content(self):
        return self.html

    @property
    def review(self):
        return self.reviews

    @property
    def review_items(self):
        return self.reviews

    @property
    def pending_review(self):
        return self.reviews

    @property
    def needs_review(self):
        return bool(self.reviews)

    @property
    def has_review(self):
        return self.needs_review

    @property
    def review_required(self):
        return self.needs_review

    @property
    def ok(self):
        return not self.reviews

    @property
    def text(self):
        return "".join(span.text for span in self.provenance if span.published)

    @property
    def internal_spans(self):
        return [span for span in self.provenance if span.visibility == "internal"]

    @property
    def mixed_spans(self):
        return [span for span in self.provenance if span.visibility == "mixed"]

    def __iter__(self):
        return iter((self.html, self.reviews, self.provenance))


@dataclass
class _TextSlot:
    element: object
    role: str
    runs: list[tuple[int | None, str]]
    spans: list[ProvenanceSpan] = field(default_factory=list)
    container: object = None


class PublicationBoundary:
    """Check whether trusted, annotated copy may cross the publication boundary.

    The input is trusted HTML which already carries publication annotations.
    Public text is passed through the configured sanitizer. Internal text is
    removed. Text which was merged across a public/internal boundary is
    quarantined for review instead of being published.
    """

    def __init__(
        self,
        config=None,
        *,
        sanitizer=None,
        annotation_attribute=None,
        annotation_attributes=None,
        public_values=None,
        internal_values=None,
        default_visibility="public",
        review_tags=None,
        mixed_policy="review",
        annotator=None,
        strip_annotation_attributes=True,
        include_internal_in_provenance=True,
    ):
        if isinstance(config, Sanitizer) and sanitizer is None:
            sanitizer = config
            config = None

        config, publication = _split_config(config)

        annotation_attributes = (
            annotation_attributes
            if annotation_attributes is not None
            else publication.get("annotation_attributes")
        )
        annotation_attribute = (
            annotation_attribute
            if annotation_attribute is not None
            else publication.get("annotation_attribute")
        )
        public_values = (
            public_values
            if public_values is not None
            else publication.get("public_values")
        )
        internal_values = (
            internal_values
            if internal_values is not None
            else publication.get("internal_values")
        )
        default_visibility = publication.get("default_visibility", default_visibility)
        review_tags = (
            review_tags if review_tags is not None else publication.get("review_tags")
        )
        mixed_policy = publication.get("mixed_policy", mixed_policy)
        annotator = annotator if annotator is not None else publication.get("annotator")
        strip_annotation_attributes = publication.get(
            "strip_annotation_attributes", strip_annotation_attributes
        )
        include_internal_in_provenance = publication.get(
            "include_internal_in_provenance", include_internal_in_provenance
        )

        if default_visibility not in {"public", "internal"}:
            raise ValueError(
                "default_visibility must be either 'public' or 'internal'"
            )
        if mixed_policy not in {"review", "keep", "drop", "quarantine"}:
            raise ValueError(
                "mixed_policy must be one of 'review', 'quarantine', 'keep' or 'drop'"
            )
        if mixed_policy == "quarantine":
            mixed_policy = "review"

        if sanitizer is not None and config is not None:
            raise TypeError("Pass either config or sanitizer, not both")

        if annotation_attribute:
            annotation_attributes = (annotation_attribute,)
        if annotation_attributes is None:
            annotation_attributes = _DEFAULT_ANNOTATION_ATTRIBUTES
        self.annotation_attributes = tuple(dict.fromkeys(annotation_attributes))

        self.public_values = {
            value.strip().lower() for value in (public_values or _PUBLIC_VALUES)
        }
        self.internal_values = {
            value.strip().lower() for value in (internal_values or _INTERNAL_VALUES)
        }
        self.default_visibility = default_visibility
        self.review_tags = set(review_tags or _DEFAULT_REVIEW_TAGS)
        self.mixed_policy = mixed_policy
        self.annotator = annotator
        self.strip_annotation_attributes = strip_annotation_attributes
        self.include_internal_in_provenance = include_internal_in_provenance

        self.sanitizer = self._build_sanitizer(config, sanitizer)

    def _build_sanitizer(self, config, sanitizer):
        if sanitizer is None:
            settings = dict(config or {})
        elif isinstance(sanitizer, Sanitizer):
            settings = {
                key: getattr(sanitizer, key)
                for key in DEFAULT_SETTINGS
                if hasattr(sanitizer, key)
            }
        else:
            raise TypeError("sanitizer must be a Sanitizer instance")

        ignored = tuple(settings.get("ignored_text_patterns", ()))
        if _IGNORED_TEXT_PATTERN not in ignored:
            ignored = (*ignored, _IGNORED_TEXT_PATTERN)
        settings["ignored_text_patterns"] = ignored
        return Sanitizer(settings)

    def __call__(self, html):
        return self.check(html)

    def check(self, html):
        source_map, root = self._annotate(html)
        annotated_html = lxml.etree.tostring(root, encoding="unicode")
        sanitized_html = self.sanitizer.sanitize(annotated_html)
        tree = self._parse(sanitized_html)
        slots = self._decode_tree(tree, source_map)
        provenance = [span for slot in slots for span in slot.spans]
        provenance.sort(key=lambda span: span.index)

        review_spans = [span for span in provenance if span.needs_review]
        reviews, review_elements = self._build_reviews(
            tree, provenance, review_spans
        )

        self._mark_published(provenance, review_elements)

        self._apply_visibility(tree, slots, review_elements)
        published_html = lxml.etree.tostring(tree, encoding="unicode")
        published_html = re.sub(r"^<div>|</div>$", "", published_html)
        published_html = self.sanitizer.sanitize(published_html)

        if not self.include_internal_in_provenance:
            provenance = [
                span for span in provenance if span.visibility != "internal"
            ]

        return PublicationResult(
            html=published_html,
            provenance=provenance,
            reviews=reviews,
            sources=source_map,
        )

    def _parse(self, html):
        html = unicodedata.normalize("NFKC", html)
        wrapped = f"<div>{html}</div>"
        try:
            root = lxml.html.fromstring(wrapped)
            lxml.etree.tostring(root, encoding="utf-8")
        except Exception:  # noqa: BLE001
            from lxml.html import soupparser  # noqa: PLC0415

            root = soupparser.fromstring(wrapped)
        return root

    def _annotate(self, html):
        root = self._parse(html)
        source_map = {}
        next_id = 1

        root_source = PublicationSource(
            id=0,
            visibility=self.default_visibility,
            path=_element_path(root),
            tag=root.tag,
            label=_element_label(root),
            explicit=False,
        )
        source_map[0] = root_source

        def make_source(element, visibility, attribute, value):
            nonlocal next_id
            source = PublicationSource(
                id=next_id,
                visibility=visibility,
                path=_element_path(element),
                tag=element.tag,
                label=_element_label(element),
                attribute=attribute,
                value=value,
            )
            source_map[next_id] = source
            next_id += 1
            return source

        def walk(element, inherited_source, inherited_visibility):
            visibility, attribute, value = self._own_annotation(element)
            if visibility is None:
                current_source = inherited_source
                current_visibility = inherited_visibility
            else:
                current_source = make_source(element, visibility, attribute, value)
                current_visibility = visibility

            if element.text:
                element.text = _marker(current_source.id) + _escape_marker_characters(
                    element.text
                )

            for child in element:
                walk(child, current_source, current_visibility)
                if child.tail:
                    child.tail = _marker(
                        current_source.id
                    ) + _escape_marker_characters(child.tail)

        walk(root, root_source, self.default_visibility)

        if self.strip_annotation_attributes:
            self._strip_annotation_attributes(root)
        return source_map, root

    def _own_annotation(self, element):
        if self.annotator is not None:
            annotated = self.annotator(element)
            if annotated is not None:
                visibility = self._value_visibility(annotated)
                if visibility is None:
                    visibility = "mixed"
                return visibility, "annotator", str(annotated)

        visibility = None
        attribute = None
        value = None

        for name in self.annotation_attributes:
            if name not in element.attrib:
                continue
            raw = element.attrib[name]
            candidate = self._value_visibility(raw)
            if candidate is None and str(raw).strip():
                candidate = "mixed"
            if candidate is not None:
                visibility = _merge_visibility(visibility, candidate)
                attribute = name
                value = raw

        for name in _PUBLIC_ATTRIBUTES:
            if name in element.attrib and not self._is_falsey(element.attrib[name]):
                visibility = _merge_visibility(visibility, "public")
                attribute = attribute or name
                value = value if value is not None else element.attrib[name]

        for name in _INTERNAL_ATTRIBUTES:
            if name in element.attrib and not self._is_falsey(element.attrib[name]):
                visibility = _merge_visibility(visibility, "internal")
                attribute = attribute or name
                value = value if value is not None else element.attrib[name]

        tag = element.tag.lower() if isinstance(element.tag, str) else ""
        if tag in _PUBLIC_TAGS:
            visibility = _merge_visibility(visibility, "public")
        elif tag in _INTERNAL_TAGS:
            visibility = _merge_visibility(visibility, "internal")

        classes = set(element.get("class", "").split())
        if classes & _PUBLIC_CLASSES:
            visibility = _merge_visibility(visibility, "public")
            attribute = attribute or "class"
            value = value if value is not None else " ".join(classes & _PUBLIC_CLASSES)
        if classes & _INTERNAL_CLASSES:
            visibility = _merge_visibility(visibility, "internal")
            attribute = attribute or "class"
            value = value if value is not None else " ".join(classes & _INTERNAL_CLASSES)

        return visibility, attribute, value

    def _value_visibility(self, value):
        if value is None:
            return None
        value = str(value).strip().lower()
        if not value:
            return None
        if value in self.public_values:
            return "public"
        if value in self.internal_values:
            return "internal"
        if value in _AMBIGUOUS_VALUES:
            return "mixed"
        return None

    @staticmethod
    def _is_falsey(value):
        return str(value).strip().lower() in {"0", "false", "no", "off", "none"}

    def _strip_annotation_attributes(self, root):
        for element in root.iter():
            for name in self.annotation_attributes:
                element.attrib.pop(name, None)
            for name in (*_PUBLIC_ATTRIBUTES, *_INTERNAL_ATTRIBUTES):
                element.attrib.pop(name, None)
            classes = set(element.get("class", "").split())
            if classes & (_PUBLIC_CLASSES | _INTERNAL_CLASSES):
                element.set(
                    "class",
                    " ".join(sorted(classes - _PUBLIC_CLASSES - _INTERNAL_CLASSES)),
                )
                if not element.get("class"):
                    del element.attrib["class"]

    def _decode_tree(self, tree, source_map):
        slots = []
        index = 0
        default_source = source_map.get(0)

        def decode(value, element, role):
            nonlocal index
            runs = _decode_marked_text(value)
            if not runs:
                return []
            normalized_runs = []
            previous_source = None
            for source_id, run_text in runs:
                if source_id is None:
                    source_id = previous_source if previous_source is not None else 0
                previous_source = source_id
                if normalized_runs and normalized_runs[-1][0] == source_id:
                    normalized_runs[-1] = (
                        source_id,
                        normalized_runs[-1][1] + run_text,
                    )
                else:
                    normalized_runs.append((source_id, run_text))

            spans = []
            for source_id, run_text in normalized_runs:
                source = source_map.get(source_id, default_source)
                visibility = source.visibility if source is not None else "public"
                sources = (source,) if source is not None else ()
                needs_review = visibility == "mixed"
                span = ProvenanceSpan(
                    text=run_text,
                    sources=sources,
                    visibility=visibility,
                    path=_element_path(element),
                    tag=element.tag,
                    role=role,
                    index=index,
                    published=visibility == "public",
                    needs_review=needs_review,
                    reason="ambiguous_visibility" if needs_review else None,
                )
                spans.append(span)
                index += 1
            return spans

        for element in tree.iter():
            if element.text:
                spans = decode(element.text, element, "text")
                if spans:
                    slots.append(
                        _TextSlot(
                            element=element,
                            role="text",
                            runs=[(span.source.id, span.text) for span in spans],
                            spans=spans,
                        )
                    )
            for child in element:
                if child.tail:
                    spans = decode(child.tail, element, "tail")
                    if spans:
                        slots.append(
                            _TextSlot(
                                element=child,
                                role="tail",
                                runs=[(span.source.id, span.text) for span in spans],
                                spans=spans,
                            )
                        )
        return slots

    def _build_reviews(self, tree, review_spans, source_map):
        if not review_spans:
            return [], set()

        grouped = {}
        for span in review_spans:
            boundary = self._review_boundary(tree, span)
            grouped.setdefault(boundary, []).append(span)

        reviews = []
        review_elements = set()
        for boundary, spans in grouped.items():
            review_elements.add(boundary)
            all_spans = [
                span
                for slot_spans in self._spans_within(boundary)
                for span in slot_spans
            ]
            sources = {}
            for span in all_spans:
                for source in span.sources:
                    sources[source.id] = source
            text = boundary.text_content() if boundary is not tree else tree.text_content()
            text = " ".join(text.split())
            html = lxml.etree.tostring(boundary, encoding="unicode", with_tail=False)
            reviews.append(
                PublicationReview(
                    text=text,
                    html=html,
                    sources=tuple(sources.values()),
                    spans=tuple(all_spans),
                    path=_element_path(boundary),
                    tag=boundary.tag,
                    reason=self._review_reason(spans),
                )
            )
        return reviews, review_elements

    def _spans_within(self, element):
        spans = []
        for descendant in element.iter():
            for attr in ("text",):
                value = getattr(descendant, attr)
                if value:
                    runs = _decode_marked_text(value)
                    if runs:
                        spans.extend(
                            self._spans_from_runs(runs, descendant, "text", element)
                        )
            for child in descendant:
                if child.tail:
                    runs = _decode_marked_text(child.tail)
                    if runs:
                        spans.extend(
                            self._spans_from_runs(runs, descendant, "tail", element)
                        )
        return spans

    def _spans_from_runs(self, runs, element, role, boundary):
        spans = []
        for source_id, run_text in runs:
            source = self.sources.get(source_id) if hasattr(self, "sources") else None
            spans.append((source_id, run_text))
        return [
            ProvenanceSpan(
                text=run_text,
                sources=(),
                visibility="mixed",
                path=_element_path(element),
                tag=element.tag,
                role=role,
                index=0,
                published=False,
                needs_review=True,
                reason="mixed_visibility",
            )
            for _, run_text in spans
        ]

    def _review_boundary(self, tree, span):
        element = span.element if hasattr(span, "element") else None
        if element is None:
            element = self._find_element(tree, span.path)
        if element is None:
            return tree
        if span.role == "tail":
            element = element.getparent() or tree
        for ancestor in element.iterancestors():
            if ancestor is tree:
                break
            if ancestor.tag in self.review_tags:
                return ancestor
        if element.tag in self.review_tags:
            return element
        return tree

    @staticmethod
    def _find_element(tree, path):
        for element in tree.iter():
            if _element_path(element) == path:
                return element
        return None

    @staticmethod
    def _review_reason(spans):
        if any(span.reason == "ambiguous_visibility" for span in spans):
            return "ambiguous_visibility"
        return "mixed_visibility"

    def _apply_visibility(self, tree, slots, review_elements):
        if self.mixed_policy == "review":
            for element in review_elements:
                if element is tree:
                    element.clear()
                elif element.getparent() is not None:
                    element.drop_tree()

        for slot in slots:
            element = slot.element
            if element is tree or element.getparent() is not None:
                visible_text = "".join(
                    span.text
                    for span in slot.spans
                    if span.visibility == "public"
                    or (span.visibility == "mixed" and self.mixed_policy == "keep")
                )
                if slot.role == "text":
                    element.text = visible_text or None
                else:
                    element.tail = visible_text or None


def _split_config(config):
    if config is None:
        return None, {}
    if isinstance(config, Sanitizer):
        return None, {}
    if not isinstance(config, dict):
        return config, {}

    config = dict(config)
    publication = dict(config.pop("publication", {}) or {})
    for key in list(config):
        if key in _PUBLICATION_SETTINGS:
            publication[key] = config.pop(key)
    return config, publication


def check_publication_boundary(html, config=None, **kwargs):
    """Check trusted, annotated HTML against the publication boundary."""

    return PublicationBoundary(config, **kwargs).check(html)


PublicationBoundaryCheck = PublicationBoundary
PublicationSanitizer = PublicationBoundary
