"""Offline comparison for generated, permission-specific HTML views."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from pathlib import Path

import lxml.html


__all__ = [
    "ComparisonReport",
    "Diagnostic",
    "MarkerDecision",
    "OfflineComparisonError",
    "SourceDecision",
    "TextBlock",
    "ViewAnalysis",
    "analyze_view",
    "canonical_visible_text",
    "compare_outputs",
    "compare_views",
    "format_report",
    "main",
]


BLOCK_TAGS = frozenset(
    {
        "address",
        "article",
        "aside",
        "blockquote",
        "dd",
        "div",
        "dl",
        "dt",
        "fieldset",
        "figcaption",
        "figure",
        "footer",
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
        "table",
        "td",
        "th",
        "tr",
        "ul",
    }
)


PROVENANCE_NOTES = (
    "Only explicit allowlists and generated HTML were supplied; the original source HTML cannot be reconstructed.",
    "Matching visible text proves output equivalence, not shared source-node identity.",
    "An observed permitted marker is present in the generated result, but whether it was originally supplied or introduced by a preprocessor cannot be confirmed.",
    "An absent permitted marker cannot be distinguished offline from a marker that was never present in the source.",
)


@dataclass(frozen=True)
class TextBlock:
    text: str
    tags: frozenset[str]


@dataclass(frozen=True)
class Diagnostic:
    code: str
    message: str
    severity: str = "error"
    view: str | None = None
    tag: str | None = None
    excerpt: str | None = None


@dataclass(frozen=True)
class MarkerDecision:
    view: str
    tag: str
    occurrences: int
    permitted: bool
    policy_scope: str
    excerpt: str
    classes: tuple[str, ...] = ()


@dataclass(frozen=True)
class SourceDecision:
    text: str
    classification: str
    views: tuple[str, ...]
    tags: tuple[str, ...] = ()
    detail: str = ""


class OfflineComparisonError(ValueError):
    def __init__(self, diagnostics: Iterable[Diagnostic]):
        self.diagnostics = tuple(diagnostics)
        super().__init__("; ".join(item.message for item in self.diagnostics))


@dataclass
class ViewAnalysis:
    name: str
    allowed_tags: frozenset[str]
    html: str
    visible_text: str
    blocks: list[TextBlock]
    tag_counts: dict[str, int]
    tag_excerpts: dict[str, str]
    tag_classes: dict[str, tuple[str, ...]]
    diagnostics: list[Diagnostic]

    @property
    def text_blocks(self) -> list[str]:
        return [block.text for block in self.blocks]


@dataclass
class ComparisonReport:
    preview_view: ViewAnalysis
    print_view: ViewAnalysis
    shared_visible_text: str
    shared_text_blocks: list[str]
    source_decisions: list[SourceDecision]
    marker_decisions: list[MarkerDecision]
    diagnostics: list[Diagnostic]
    provenance_notes: tuple[str, ...] = PROVENANCE_NOTES

    @property
    def errors(self) -> list[Diagnostic]:
        return [item for item in self.diagnostics if item.severity == "error"]

    @property
    def ok(self) -> bool:
        return not self.errors

    @property
    def is_valid(self) -> bool:
        return self.ok

    @property
    def unverifiable_sources(self) -> list[str]:
        sources = []
        for item in self.source_decisions:
            if item.classification != "unverified_origin":
                continue
            sources.append(
                f"{item.text} -- {item.detail}" if item.detail else item.text
            )
        return sources

    @property
    def preview_only_text(self) -> list[str]:
        return [
            item.text
            for item in self.source_decisions
            if self.preview_view.name in item.views
            and item.classification != "shared_visible_text"
        ]

    @property
    def print_only_text(self) -> list[str]:
        return [
            item.text
            for item in self.source_decisions
            if self.print_view.name in item.views
            and item.classification != "shared_visible_text"
        ]

    @property
    def shared_permitted_tags(self) -> list[str]:
        preview_tags = {
            item.tag
            for item in self.marker_decisions
            if item.view == self.preview_view.name and item.permitted
        }
        print_tags = {
            item.tag
            for item in self.marker_decisions
            if item.view == self.print_view.name and item.permitted
        }
        return sorted(preview_tags & print_tags)

    def raise_for_violations(self) -> None:
        if self.errors:
            raise OfflineComparisonError(self.errors)

    def to_dict(self) -> dict[str, object]:
        return json.loads(
            json.dumps(asdict(self), ensure_ascii=False, default=_json_default)
        )


def _json_default(value: object) -> object:
    if isinstance(value, frozenset | set):
        return sorted(value)
    if isinstance(value, tuple):
        return list(value)
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def _normalize_space(text: str | None) -> str:
    return " ".join((text or "").split())


def _tag_set(tags: Iterable[str]) -> frozenset[str]:
    return frozenset(str(tag).strip().lower() for tag in tags if str(tag).strip())


def _parse_fragment(html: str | None):
    html = html or ""
    try:
        return lxml.html.fragment_fromstring(html, create_parent="div")
    except Exception:
        from lxml.html import soupparser  # noqa: PLC0415

        root = soupparser.fromstring(f"<div>{html}</div>")
        wrapper = root.find(".//div") if hasattr(root, "find") else None
        return wrapper if wrapper is not None else root


def _extract_blocks(root) -> list[TextBlock]:
    boundary = object()
    tokens: list[object] = []

    def append_text(text: str | None, ancestors: tuple[str, ...]) -> None:
        if text:
            tokens.append((text, ancestors))

    def walk_children(element, ancestors: tuple[str, ...]) -> None:
        append_text(element.text, ancestors)
        for child in element:
            if not isinstance(child.tag, str):
                append_text(child.tail, ancestors)
                continue

            tag = child.tag.lower()
            child_ancestors = ancestors + (tag,)
            is_block = tag in BLOCK_TAGS
            if is_block or tag == "br":
                tokens.append(boundary)

            walk_children(child, child_ancestors)

            if is_block or tag == "br":
                tokens.append(boundary)
            append_text(child.tail, ancestors)

    walk_children(root, ())

    raw_blocks: list[dict[str, object]] = [{"parts": [], "tags": set()}]
    for token in tokens:
        if token is boundary:
            raw_blocks.append({"parts": [], "tags": set()})
            continue

        text, ancestors = token  # type: ignore[misc]
        raw_blocks[-1]["parts"].append(text)  # type: ignore[union-attr]
        raw_blocks[-1]["tags"].update(ancestors)  # type: ignore[union-attr]

    blocks = []
    for raw_block in raw_blocks:
        text = _normalize_space("".join(raw_block["parts"]))  # type: ignore[arg-type]
        if text:
            blocks.append(
                TextBlock(
                    text=text,
                    tags=frozenset(raw_block["tags"]),  # type: ignore[arg-type]
                )
            )
    return blocks


def canonical_visible_text(html: str | None) -> str:
    """Return visible text with indentation and whitespace layout normalized."""
    root = _parse_fragment(html)
    return " ".join(block.text for block in _extract_blocks(root))


def analyze_view(
    name: str,
    allowed_tags: Iterable[str],
    html: str | None,
) -> ViewAnalysis:
    """Parse one generated view and inventory its explicit tag permissions."""
    allowed = _tag_set(allowed_tags)
    root = _parse_fragment(html)
    blocks = _extract_blocks(root)

    tag_counts: Counter[str] = Counter()
    tag_excerpts: dict[str, str] = {}
    class_sets: dict[str, set[str]] = {}
    diagnostics: list[Diagnostic] = []

    for element in root.iterdescendants():
        if not isinstance(element.tag, str):
            continue

        tag = element.tag.lower()
        tag_counts[tag] += 1
        excerpt = _normalize_space(element.text_content())[:200]
        tag_excerpts.setdefault(tag, excerpt)

        class_set = class_sets.setdefault(tag, set())
        for class_name in element.get("class", "").split():
            if class_name:
                class_set.add(class_name)

        if tag not in allowed:
            diagnostics.append(
                Diagnostic(
                    code="disallowed_marker",
                    severity="error",
                    view=name,
                    tag=tag,
                    excerpt=excerpt,
                    message=(
                        f"{name}: result contains disallowed marker <{tag}> "
                        f"with text {excerpt!r}; {tag!r} is not in the explicit "
                        f"allowed tag set {sorted(allowed)}."
                    ),
                )
            )

    tag_classes = {
        tag: tuple(sorted(class_names)) for tag, class_names in class_sets.items()
    }

    return ViewAnalysis(
        name=name,
        allowed_tags=allowed,
        html=html or "",
        visible_text=" ".join(block.text for block in blocks),
        blocks=blocks,
        tag_counts=dict(sorted(tag_counts.items())),
        tag_excerpts=tag_excerpts,
        tag_classes=tag_classes,
        diagnostics=diagnostics,
    )


def _block_is_permitted(block: TextBlock, view: ViewAnalysis) -> bool:
    return not (block.tags - view.allowed_tags)


def _unmatched_source_decision(
    block: TextBlock,
    view: ViewAnalysis,
    other_allowed_tags: frozenset[str],
) -> SourceDecision:
    forbidden_tags = tuple(sorted(block.tags - view.allowed_tags))
    if forbidden_tags:
        return SourceDecision(
            text=block.text,
            classification="disallowed_marker_text",
            views=(view.name,),
            tags=tuple(sorted(block.tags)),
            detail=(
                f"{view.name}: text is carried by marker(s) {forbidden_tags} "
                "outside that view's explicit allowlist and must be diagnosed."
            ),
        )

    view_specific_tags = tuple(
        sorted(
            tag
            for tag in block.tags
            if tag in view.allowed_tags and tag not in other_allowed_tags
        )
    )
    if view_specific_tags:
        return SourceDecision(
            text=block.text,
            classification="optional_permission_bound_marker_text",
            views=(view.name,),
            tags=tuple(sorted(block.tags)),
            detail=(
                f"{view.name}: text is explained by optional marker(s) "
                f"{view_specific_tags} permitted only for this view."
            ),
        )

    return SourceDecision(
        text=block.text,
        classification="unverified_origin",
        views=(view.name,),
        tags=tuple(sorted(block.tags)),
        detail=(
            f"{view.name}: text has no matching counterpart and no view-specific "
            "permitted marker explains it; its source cannot be confirmed from "
            "the generated outputs alone."
        ),
    )


def _marker_decisions(
    view: ViewAnalysis,
    other: ViewAnalysis,
) -> list[MarkerDecision]:
    decisions = []
    for tag, occurrences in view.tag_counts.items():
        permitted = tag in view.allowed_tags
        if not permitted:
            policy_scope = "forbidden"
        elif tag in other.allowed_tags:
            policy_scope = "shared_allowed"
        else:
            policy_scope = f"{view.name}_only_allowed"

        decisions.append(
            MarkerDecision(
                view=view.name,
                tag=tag,
                occurrences=occurrences,
                permitted=permitted,
                policy_scope=policy_scope,
                excerpt=view.tag_excerpts.get(tag, ""),
                classes=view.tag_classes.get(tag, ()),
            )
        )
    return decisions


def compare_outputs(
    preview_allowed_tags: Iterable[str],
    preview_html: str | None,
    print_allowed_tags: Iterable[str],
    print_html: str | None,
    *,
    preview_name: str = "public_preview",
    print_name: str = "print",
) -> ComparisonReport:
    """Compare two generated views against explicit tag allowlists."""
    preview = analyze_view(preview_name, preview_allowed_tags, preview_html)
    printed = analyze_view(print_name, print_allowed_tags, print_html)

    remaining_print_blocks = list(printed.blocks)
    source_decisions: list[SourceDecision] = []
    shared_blocks: list[str] = []

    for block in preview.blocks:
        match_index = None
        if _block_is_permitted(block, preview):
            for index, candidate in enumerate(remaining_print_blocks):
                if candidate.text == block.text and _block_is_permitted(
                    candidate, printed
                ):
                    match_index = index
                    break

        if match_index is None:
            source_decisions.append(
                _unmatched_source_decision(block, preview, printed.allowed_tags)
            )
            continue

        candidate = remaining_print_blocks.pop(match_index)
        shared_blocks.append(block.text)
        source_decisions.append(
            SourceDecision(
                text=block.text,
                classification="shared_visible_text",
                views=(preview.name, printed.name),
                tags=tuple(sorted(block.tags | candidate.tags)),
                detail=(
                    "Normalized visible text matches in both generated results; "
                    "original source-node identity remains unconfirmed."
                ),
            )
        )

    for block in remaining_print_blocks:
        source_decisions.append(
            _unmatched_source_decision(block, printed, preview.allowed_tags)
        )

    marker_decisions = _marker_decisions(preview, printed)
    marker_decisions.extend(_marker_decisions(printed, preview))
    diagnostics = [*preview.diagnostics, *printed.diagnostics]

    return ComparisonReport(
        preview_view=preview,
        print_view=printed,
        shared_visible_text=" ".join(shared_blocks),
        shared_text_blocks=shared_blocks,
        source_decisions=source_decisions,
        marker_decisions=marker_decisions,
        diagnostics=diagnostics,
    )


def _view_fields(value):
    if isinstance(value, Mapping):
        return (
            value["allowed_tags"],
            value.get("html", ""),
            value.get("name", "view"),
        )
    if isinstance(value, tuple) and len(value) == 2:
        return value[0], value[1], "view"
    if all(hasattr(value, name) for name in ("allowed_tags", "html")):
        return (
            value.allowed_tags,
            value.html,
            getattr(value, "name", "view"),
        )
    raise TypeError(f"Unsupported offline view input: {value!r}")


def compare_views(preview=None, print_view=None, /, *args, **kwargs):
    """Compare either two view objects or four allowlist/result arguments."""
    if args:
        if print_view is None or len(args) != 2:
            raise TypeError(
                "Call compare_views(tags_a, html_a, tags_b, html_b) or "
                "compare_views(view_a, view_b)."
            )
        return compare_outputs(preview, print_view, *args, **kwargs)

    preview_tags, preview_html, preview_name = _view_fields(preview)
    print_tags, print_html, print_name = _view_fields(print_view)
    return compare_outputs(
        preview_tags,
        preview_html,
        print_tags,
        print_html,
        preview_name=kwargs.pop("preview_name", preview_name),
        print_name=kwargs.pop("print_name", print_name),
        **kwargs,
    )


def format_report(report: ComparisonReport) -> str:
    lines = [
        "Offline HTML view comparison",
        "",
        "Shared visible text:",
        report.shared_visible_text or "(none)",
        "",
        "Marker decisions:",
    ]
    for marker in report.marker_decisions:
        lines.append(
            f"- {marker.view} <{marker.tag}> x{marker.occurrences} "
            f"[{marker.policy_scope}] permitted={marker.permitted}: "
            f"{marker.excerpt}"
        )

    lines.extend(["", "Source decisions:"])
    for source in report.source_decisions:
        lines.append(f"- [{source.classification}] {source.text}")
        if source.detail:
            lines.append(f"  {source.detail}")

    lines.extend(["", "Diagnostics:"])
    if report.diagnostics:
        for diagnostic in report.diagnostics:
            lines.append(f"- {diagnostic.code}: {diagnostic.message}")
    else:
        lines.append("- none")

    lines.extend(["", "Provenance limitations:"])
    for note in report.provenance_notes:
        lines.append(f"- {note}")

    return "\n".join(lines)


def _read_html(html_value: str | None, file_value: str | None) -> str | None:
    if html_value is not None:
        return html_value
    if file_value is not None:
        return Path(file_value).read_text(encoding="utf-8")
    return None


def _tags_from_csv(value: str) -> frozenset[str]:
    return _tag_set(part for part in value.split(",") if part.strip())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m html_sanitizer.offline_compare",
        description="Offline-compare two generated HTML views against explicit tag sets.",
    )
    parser.add_argument("--preview-name", default="public_preview")
    parser.add_argument("--preview-tags", required=True)
    parser.add_argument("--preview-html")
    parser.add_argument("--preview-file")
    parser.add_argument("--print-name", default="print")
    parser.add_argument("--print-tags", required=True)
    parser.add_argument("--print-html")
    parser.add_argument("--print-file")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    preview_html = _read_html(args.preview_html, args.preview_file)
    print_html = _read_html(args.print_html, args.print_file)
    if preview_html is None or print_html is None:
        parser.error(
            "Provide --preview-html/--preview-file and --print-html/--print-file."
        )

    report = compare_outputs(
        _tags_from_csv(args.preview_tags),
        preview_html,
        _tags_from_csv(args.print_tags),
        print_html,
        preview_name=args.preview_name,
        print_name=args.print_name,
    )

    if args.json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(format_report(report))
    return 0 if report.ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
