"""Static compliance review for templates that render managed sections.

The reviewer intentionally works on the template AST only.  It never renders a
template, so it can be used as a fast commit-time check.  Callers declare which
sections are managed and the one host-provided marker source that is accepted.
Literal copies of the marker text in a template are ignored.

The supported layout surface is deliberately small:

* ``extends`` chains and blocks, including ``super()``
* static ``include`` references
* ordinary ``if``/``for`` control flow, including paths where a loop is empty
* local and statically imported macros

Dynamic template references and output calls that cannot be resolved statically
are reported for manual review instead of being silently accepted.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import typing as t
from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import replace
from pathlib import Path

from . import nodes
from .environment import Environment
from .exceptions import TemplateNotFound
from .exceptions import TemplateSyntaxError
from .loaders import BaseLoader
from .loaders import DictLoader
from .loaders import FileSystemLoader

if t.TYPE_CHECKING:
    from collections.abc import Iterable
    from collections.abc import Sequence


__all__ = [
    "Finding",
    "ManagedSection",
    "MarkerSource",
    "PathCondition",
    "ReviewConfig",
    "ReviewError",
    "ReviewResult",
    "review_file",
    "review_files",
    "review_template",
]


_MISSING = object()


class ReviewError(Exception):
    """Raised for an invalid review configuration or unusable input."""


@dataclass(frozen=True)
class ManagedSection:
    """A document section whose output requires the host marker.

    A section can be matched in four independent ways:

    ``variables``
        Output expressions that load one of these names, such as
        ``{{ impact }}``.
    ``blocks``
        Template blocks with one of these names.  The block is considered
        rendered when the effective block definition is reached.
    ``literals``
        Textual fragments in static template output, for example
        ``data-managed="impact"``.
    ``templates``
        Statically referenced templates whose inclusion renders the section.
    """

    name: str
    variables: frozenset[str] = frozenset()
    blocks: frozenset[str] = frozenset()
    literals: tuple[str, ...] = ()
    templates: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not self.name:
            raise ReviewError("managed section name must not be empty")

        if not any((self.variables, self.blocks, self.literals, self.templates)):
            object.__setattr__(self, "variables", frozenset({self.name}))
            object.__setattr__(self, "blocks", frozenset({self.name}))

        if any(not literal for literal in self.literals):
            raise ReviewError(
                f"managed section {self.name!r} has an empty literal selector"
            )

    @classmethod
    def variable(cls, name: str, *, section: str | None = None) -> ManagedSection:
        return cls(section or name, variables=frozenset({name}))

    @classmethod
    def block(cls, name: str, *, section: str | None = None) -> ManagedSection:
        return cls(section or name, blocks=frozenset({name}))

    @classmethod
    def literal(cls, value: str, *, section: str) -> ManagedSection:
        return cls(section, literals=(value,))

    @classmethod
    def template(cls, name: str, *, section: str | None = None) -> ManagedSection:
        return cls(section or name, templates=frozenset({name}))


@dataclass(frozen=True)
class MarkerSource:
    """The one host-provided marker source accepted by the review.

    ``variable`` recognises output expressions that load the named variable,
    ``template`` recognises inclusion of the named host template, and ``call``
    recognises an output call to the named function or macro.

    A literal marker source is intentionally not supported.  Writing the same
    text in a template body must never satisfy the requirement.
    """

    kind: str
    value: str

    def __post_init__(self) -> None:
        if self.kind not in {"variable", "template", "call"}:
            raise ReviewError(
                "marker source kind must be 'variable', 'template', or 'call',"
                f" not {self.kind!r}"
            )

        if not self.value:
            raise ReviewError("marker source value must not be empty")

    @classmethod
    def variable(cls, name: str) -> MarkerSource:
        return cls("variable", name)

    @classmethod
    def template(cls, name: str) -> MarkerSource:
        return cls("template", name)

    @classmethod
    def call(cls, name: str) -> MarkerSource:
        return cls("call", name)

    def describe(self) -> str:
        return f'{self.kind} "{self.value}"'


def _string_set(value: t.Any, *, field: str) -> frozenset[str]:
    if value is None:
        return frozenset()

    if isinstance(value, str):
        value = [value]

    if not isinstance(value, (list, tuple, set, frozenset)):
        raise ReviewError(f"{field} must be a string or a list of strings")

    result: list[str] = []

    for item in value:
        if not isinstance(item, str) or not item:
            raise ReviewError(f"{field} must contain non-empty strings")

        result.append(item)

    return frozenset(result)


def _coerce_section(
    value: ManagedSection | str | Mapping[str, t.Any],
) -> ManagedSection:
    if isinstance(value, ManagedSection):
        return value

    if isinstance(value, str):
        return ManagedSection(
            value,
            variables=frozenset({value}),
            blocks=frozenset({value}),
        )

    if not isinstance(value, Mapping):
        raise ReviewError(
            "managed sections must be strings, mappings, or ManagedSection"
        )

    name = value.get("name")

    if not isinstance(name, str) or not name:
        raise ReviewError("managed section mapping needs a non-empty 'name'")

    kind = value.get("kind")

    if kind is not None:
        kind_value = value.get("value")

        if not isinstance(kind_value, str) or not kind_value:
            raise ReviewError(
                f"managed section {name!r} needs a non-empty 'value' for kind"
            )

        if kind == "variable":
            return ManagedSection.variable(kind_value, section=name)

        if kind == "block":
            return ManagedSection.block(kind_value, section=name)

        if kind == "literal":
            return ManagedSection.literal(kind_value, section=name)

        if kind == "template":
            return ManagedSection.template(kind_value, section=name)

        raise ReviewError(f"unknown managed section kind {kind!r}")

    variables = _string_set(value.get("variables"), field=f"{name}.variables")
    blocks = _string_set(value.get("blocks"), field=f"{name}.blocks")
    templates = _string_set(value.get("templates"), field=f"{name}.templates")

    if "variable" in value:
        variables |= _string_set(value["variable"], field=f"{name}.variable")

    if "block" in value:
        blocks |= _string_set(value["block"], field=f"{name}.block")

    if "template" in value:
        templates |= _string_set(value["template"], field=f"{name}.template")

    literals_value = value.get("literals", value.get("literal", ()))

    if isinstance(literals_value, str):
        literals_value = (literals_value,)

    if not isinstance(literals_value, (list, tuple)):
        raise ReviewError(f"{name}.literals must be a string or list of strings")

    literals = tuple(literals_value)

    if any(not isinstance(item, str) or not item for item in literals):
        raise ReviewError(f"{name}.literals must contain non-empty strings")

    return ManagedSection(
        name,
        variables=variables,
        blocks=blocks,
        literals=literals,
        templates=templates,
    )


def _coerce_marker(value: MarkerSource | str | Mapping[str, t.Any]) -> MarkerSource:
    if isinstance(value, MarkerSource):
        return value

    if isinstance(value, str):
        return MarkerSource.variable(value)

    if not isinstance(value, Mapping):
        raise ReviewError("marker must be a string, mapping, or MarkerSource")

    kind = value.get("kind")
    raw_value = value.get("value", value.get("name", value.get("source")))

    if kind is None:
        for candidate in ("variable", "template", "call"):
            if candidate in value:
                kind = candidate
                raw_value = value[candidate]
                break

    if kind == "literal":
        raise ReviewError(
            "a literal marker source is not accepted; use the host variable,"
            " template, or call that provides the marker"
        )

    if not isinstance(kind, str) or not isinstance(raw_value, str) or not raw_value:
        raise ReviewError("marker mapping needs string 'kind' and 'value'")

    return MarkerSource(kind, raw_value)


@dataclass(frozen=True)
class ReviewConfig:
    """Configuration for :func:`review_template` and :func:`review_file`."""

    managed_sections: tuple[ManagedSection, ...]
    marker: MarkerSource
    max_paths: int = 512

    def __post_init__(self) -> None:
        raw_sections = self.managed_sections

        if isinstance(raw_sections, (str, ManagedSection, Mapping)):
            raw_sections = (raw_sections,)

        sections = tuple(_coerce_section(item) for item in raw_sections)
        marker = _coerce_marker(self.marker)

        if self.max_paths < 1:
            raise ReviewError("max_paths must be at least 1")

        names = [section.name for section in sections]

        if len(names) != len(set(names)):
            raise ReviewError("managed section names must be unique")

        object.__setattr__(self, "managed_sections", sections)
        object.__setattr__(self, "marker", marker)

    @classmethod
    def from_mapping(cls, data: Mapping[str, t.Any]) -> ReviewConfig:
        try:
            raw_sections = data["managed_sections"]
        except KeyError:
            raw_sections = data.get("sections")

        if raw_sections is None:
            raise ReviewError("configuration needs 'managed_sections'")

        if isinstance(raw_sections, (str, ManagedSection, Mapping)):
            raw_sections = (raw_sections,)

        marker = data.get("marker", data.get("marker_source"))

        if marker is None:
            raise ReviewError("configuration needs 'marker'")

        try:
            max_paths = int(data.get("max_paths", 512))
        except (TypeError, ValueError) as e:
            raise ReviewError("max_paths must be an integer") from e

        return cls(
            tuple(_coerce_section(item) for item in raw_sections),
            _coerce_marker(marker),
            max_paths=max_paths,
        )


@dataclass(frozen=True)
class PathCondition:
    """One condition on a reachable rendering path."""

    expression: str
    truth: bool
    template: str
    line: int
    kind: str = "condition"

    def describe(self) -> str:
        if self.kind == "note":
            return self.expression

        if self.kind == "loop":
            if self.truth:
                return f"{self.expression} is non-empty"

            return f"{self.expression} is empty"

        if self.truth:
            return self.expression

        if self.expression.isidentifier():
            return f"{self.expression} is empty"

        return f"not ({self.expression})"

    def location(self) -> str:
        return f"{self.template}:{self.line}"


@dataclass(frozen=True)
class Finding:
    """One review finding."""

    code: str
    message: str
    severity: str
    template: str
    line: int
    section: str | None = None
    marker: str | None = None
    path: tuple[PathCondition, ...] = ()

    @property
    def location(self) -> str:
        return f"{self.template}:{self.line}"

    def as_dict(self) -> dict[str, t.Any]:
        return {
            "code": self.code,
            "message": self.message,
            "severity": self.severity,
            "template": self.template,
            "line": self.line,
            "section": self.section,
            "marker": self.marker,
            "path": [
                {
                    "description": condition.describe(),
                    "expression": condition.expression,
                    "truth": condition.truth,
                    "template": condition.template,
                    "line": condition.line,
                    "kind": condition.kind,
                }
                for condition in self.path
            ],
        }


@dataclass(frozen=True)
class ReviewResult:
    """The result of one or more static template reviews."""

    findings: tuple[Finding, ...] = ()
    templates_reviewed: tuple[str, ...] = ()

    @property
    def errors(self) -> tuple[Finding, ...]:
        return tuple(item for item in self.findings if item.severity == "error")

    @property
    def manual(self) -> tuple[Finding, ...]:
        return tuple(item for item in self.findings if item.severity == "manual")

    @property
    def status(self) -> str:
        if self.errors:
            return "fail"

        if self.manual:
            return "manual"

        return "pass"

    @property
    def ok(self) -> bool:
        return self.status == "pass"

    def format_text(self) -> str:
        lines = [f"{self.status.upper()}: {len(self.templates_reviewed)} template(s)"]

        for finding in self.findings:
            lines.append(
                f"{finding.location}: {finding.severity} {finding.code}"
                f" {finding.message}"
            )

            if finding.path:
                path = "; ".join(
                    f"{condition.describe()} ({condition.location()})"
                    for condition in finding.path
                )
                lines.append(f"  reachable path: {path}")

        return "\n".join(lines)

    def as_dict(self) -> dict[str, t.Any]:
        return {
            "status": self.status,
            "templates_reviewed": list(self.templates_reviewed),
            "findings": [finding.as_dict() for finding in self.findings],
        }


def review_template(
    source: str,
    config: ReviewConfig | None = None,
    *,
    managed_sections: Iterable[ManagedSection | str | Mapping[str, t.Any]]
    | None = None,
    marker: MarkerSource | str | Mapping[str, t.Any] | None = None,
    template_name: str = "<template>",
    loader: BaseLoader | Mapping[str, str] | None = None,
    environment: Environment | None = None,
    max_paths: int | None = None,
) -> ReviewResult:
    """Statically review one template source.

    Either *config* or both *managed_sections* and *marker* must be provided.
    References to other templates are resolved through *loader* (or the
    environment's loader).
    """

    if config is None:
        if managed_sections is None or marker is None:
            raise ReviewError("provide config or managed_sections and marker")

        config = ReviewConfig(
            tuple(_coerce_section(item) for item in managed_sections),
            _coerce_marker(marker),
            max_paths=512 if max_paths is None else max_paths,
        )
    elif max_paths is not None:
        config = replace(config, max_paths=max_paths)

    reviewer = _Reviewer(
        config,
        source=source,
        template_name=template_name,
        loader=loader,
        environment=environment,
    )
    return reviewer.review(template_name)


def review_file(
    path: str | os.PathLike[str],
    config: ReviewConfig | None = None,
    *,
    managed_sections: Iterable[ManagedSection | str | Mapping[str, t.Any]]
    | None = None,
    marker: MarkerSource | str | Mapping[str, t.Any] | None = None,
    search_path: str
    | os.PathLike[str]
    | Sequence[str | os.PathLike[str]]
    | None = None,
    environment: Environment | None = None,
    max_paths: int | None = None,
) -> ReviewResult:
    """Review a plaintext template file.

    Relative references are resolved from *search_path* when given, otherwise
    from the template's parent directory.
    """

    if config is None:
        if managed_sections is None or marker is None:
            raise ReviewError("provide config or managed_sections and marker")

        config = ReviewConfig(
            tuple(_coerce_section(item) for item in managed_sections),
            _coerce_marker(marker),
            max_paths=512 if max_paths is None else max_paths,
        )

    file_path = Path(path)

    try:
        source = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        raise ReviewError(f"{file_path} is not a plaintext UTF-8 template") from e

    if search_path is None:
        search_paths: list[str] = [str(file_path.parent)]
    elif isinstance(search_path, (str, os.PathLike)):
        search_paths = [str(search_path)]
    else:
        search_paths = [str(item) for item in search_path]

    root_name = file_path.name

    for candidate in search_paths:
        try:
            root_name = str(file_path.resolve().relative_to(Path(candidate).resolve()))
            break
        except ValueError:
            continue

    loader = FileSystemLoader(search_paths)

    return review_template(
        source,
        config,
        template_name=root_name,
        loader=loader,
        environment=environment,
        max_paths=max_paths,
    )


def review_files(
    paths: Iterable[str | os.PathLike[str]],
    config: ReviewConfig | None = None,
    *,
    managed_sections: Iterable[ManagedSection | str | Mapping[str, t.Any]]
    | None = None,
    marker: MarkerSource | str | Mapping[str, t.Any] | None = None,
    search_path: str
    | os.PathLike[str]
    | Sequence[str | os.PathLike[str]]
    | None = None,
    environment: Environment | None = None,
    max_paths: int | None = None,
) -> ReviewResult:
    """Review multiple root templates and combine the findings."""

    findings: list[Finding] = []
    reviewed: list[str] = []

    for path in paths:
        result = review_file(
            path,
            config,
            managed_sections=managed_sections,
            marker=marker,
            search_path=search_path,
            environment=environment,
            max_paths=max_paths,
        )
        findings.extend(result.findings)
        reviewed.extend(result.templates_reviewed)

    return ReviewResult(tuple(findings), tuple(reviewed))


@dataclass(frozen=True)
class _TemplateInfo:
    name: str
    ast: nodes.Template
    extends: str | None
    extends_node: nodes.Extends | None
    blocks: dict[str, nodes.Block]
    macros: dict[str, nodes.Macro]
    imports: dict[str, str]
    from_imports: dict[str, tuple[str, str]]


@dataclass(frozen=True)
class _SectionHit:
    name: str
    template: str
    line: int


@dataclass(frozen=True)
class _MarkerHit:
    source: str
    template: str
    line: int


@dataclass(frozen=True)
class _Issue:
    code: str
    message: str
    severity: str
    template: str
    line: int


@dataclass(frozen=True)
class _State:
    facts: tuple[PathCondition, ...] = ()
    sections: tuple[_SectionHit, ...] = ()
    markers: tuple[_MarkerHit, ...] = ()
    issues: tuple[_Issue, ...] = ()
    captures: tuple[tuple[str, tuple[nodes.Node, ...]], ...] = ()
    uncertain_marker: bool = False


@dataclass
class _Context:
    template: _TemplateInfo
    chain: tuple[_TemplateInfo, ...]
    block_defs: dict[str, tuple[nodes.Block, ...]]
    macros: dict[str, nodes.Macro]
    imported_macros: dict[tuple[str, str], nodes.Macro]
    aliases: dict[str, nodes.Expr]
    macro_stack: tuple[int, ...] = ()
    block_stack: tuple[tuple[str, int], ...] = ()
    capture_stack: tuple[str, ...] = ()


class _LoadFailure(Exception):
    def __init__(self, code: str, message: str, template: str, line: int) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.template = template
        self.line = line


class _Reviewer:
    def __init__(
        self,
        config: ReviewConfig,
        *,
        source: str,
        template_name: str,
        loader: BaseLoader | Mapping[str, str] | None,
        environment: Environment | None,
    ) -> None:
        if isinstance(loader, Mapping):
            loader = DictLoader(dict(loader))

        if environment is None:
            environment = Environment(loader=loader)

        self.config = config
        self.environment = environment
        self.loader: BaseLoader | None = (
            loader if loader is not None else environment.loader
        )
        self.source = source
        self.template_name = template_name
        self._cache: dict[str, _TemplateInfo] = {}
        self._node_templates: dict[int, str] = {}

    def review(self, name: str) -> ReviewResult:
        states = self._render(name, _State(), ())
        findings: list[Finding] = []
        seen_findings: set[t.Any] = set()

        for state in states:
            for issue in state.issues:
                key = (
                    issue.code,
                    issue.severity,
                    issue.template,
                    issue.line,
                    issue.message,
                )

                if key in seen_findings:
                    continue

                seen_findings.add(key)
                findings.append(
                    Finding(
                        issue.code,
                        issue.message,
                        issue.severity,
                        issue.template,
                        issue.line,
                    )
                )

            for section_hit in state.sections:
                if state.markers or state.uncertain_marker:
                    continue

                path_key = (
                    section_hit.name,
                    section_hit.template,
                    section_hit.line,
                    tuple(
                        (
                            condition.expression,
                            condition.truth,
                            condition.template,
                            condition.line,
                            condition.kind,
                        )
                        for condition in state.facts
                    ),
                )

                if path_key in seen_findings:
                    continue

                seen_findings.add(path_key)
                findings.append(
                    Finding(
                        "E_MISSING_MARKER",
                        f"managed section {section_hit.name!r} is rendered without"
                        f" the accepted marker source {self.config.marker.describe()}",
                        "error",
                        section_hit.template,
                        section_hit.line,
                        section=section_hit.name,
                        marker=self.config.marker.describe(),
                        path=state.facts,
                    )
                )

        return ReviewResult(tuple(findings), (self.template_name,))

    def _get_source(self, name: str) -> str:
        if name == self.template_name:
            return self.source

        if self.loader is None:
            raise TemplateNotFound(name)

        source, _, _ = self.loader.get_source(self.environment, name)
        return source

    def _load(self, name: str, *, line: int, referrer: str) -> _TemplateInfo:
        cached = self._cache.get(name)

        if cached is not None:
            return cached

        try:
            source = self._get_source(name)
        except TemplateNotFound as e:
            raise _LoadFailure(
                "E_TEMPLATE_NOT_FOUND",
                f"referenced template {name!r} was not found",
                referrer,
                line,
            ) from e

        try:
            ast = self.environment.parse(source, name)
        except TemplateSyntaxError as e:
            raise _LoadFailure(
                "E_TEMPLATE_SYNTAX",
                f"template {name!r} has a syntax error: {e}",
                name,
                e.lineno or line,
            ) from e

        blocks: dict[str, nodes.Block] = {}
        macros: dict[str, nodes.Macro] = {}
        imports: dict[str, str] = {}
        from_imports: dict[str, tuple[str, str]] = {}

        self._node_templates[id(ast)] = name

        for child in ast.find_all(nodes.Node):
            self._node_templates[id(child)] = name

            if isinstance(child, nodes.Block):
                blocks.setdefault(child.name, child)
            elif isinstance(child, nodes.Macro):
                macros.setdefault(child.name, child)
            elif isinstance(child, nodes.Import):
                imports[child.target] = self._template_reference(child.template)
            elif isinstance(child, nodes.FromImport):
                imported = self._template_reference(child.template)

                for item in child.names:
                    if isinstance(item, tuple):
                        imported_name, local_name = item
                    else:
                        imported_name = local_name = item

                    from_imports[local_name] = (imported, imported_name)

        extends_node = next(
            (item for item in ast.body if isinstance(item, nodes.Extends)), None
        )
        extends: str | None = None

        if extends_node is not None:
            value = self._const_value(extends_node.template)

            if isinstance(value, str):
                extends = value

        info = _TemplateInfo(
            name,
            ast,
            extends,
            extends_node,
            blocks,
            macros,
            imports,
            from_imports,
        )
        self._cache[name] = info
        return info

    def _template_reference(self, node: nodes.Expr) -> str:
        value = self._const_value(node)
        return value if isinstance(value, str) else ""

    def _render(self, name: str, state: _State, stack: tuple[str, ...]) -> list[_State]:
        if name in stack:
            return [
                self._issue(state, "M_RECURSIVE_INCLUDE", "recursive include", name, 1)
            ]

        try:
            info = self._load(name, line=1, referrer=name)
            chain, dynamic_extends = self._layout(info)
        except _LoadFailure as e:
            return [
                self._issue(
                    state, e.code, e.message, e.template, e.line, severity="error"
                )
            ]

        if dynamic_extends is not None:
            return [
                self._issue(
                    state,
                    "M_DYNAMIC_REFERENCE",
                    "dynamic extends expression cannot be resolved statically;"
                    " review the layout manually",
                    self._template_of(dynamic_extends, info.name),
                    dynamic_extends.lineno or 1,
                )
            ]

        context = self._make_context(chain)
        root = chain[-1]
        return self._process_nodes(
            root.ast.body, [state], context, None, stack + (name,)
        )

    def _layout(
        self, info: _TemplateInfo
    ) -> tuple[tuple[_TemplateInfo, ...], nodes.Expr | None]:
        chain = [info]
        seen = {info.name}
        current = info

        while current.extends_node is not None:
            if current.extends is None:
                return tuple(chain), current.extends_node

            try:
                parent = self._load(
                    current.extends,
                    line=current.extends_node.lineno or 1,
                    referrer=current.name,
                )
            except _LoadFailure as e:
                raise e

            if parent.name in seen:
                raise _LoadFailure(
                    "E_EXTENDS_CYCLE",
                    f"extends cycle involving template {parent.name!r}",
                    current.name,
                    current.extends_node.lineno or 1,
                )

            chain.append(parent)
            seen.add(parent.name)
            current = parent

        return tuple(chain), None

    def _make_context(self, chain: tuple[_TemplateInfo, ...]) -> _Context:
        blocks: dict[str, list[nodes.Block]] = {}
        macros: dict[str, nodes.Macro] = {}

        for info in chain:
            for name, block in info.blocks.items():
                blocks.setdefault(name, []).append(block)

            for name, macro in info.macros.items():
                macros.setdefault(name, macro)

        imported_macros: dict[tuple[str, str], nodes.Macro] = {}

        for info in chain:
            for alias, template_name in info.imports.items():
                if not template_name:
                    continue

                try:
                    imported = self._load(
                        template_name,
                        line=1,
                        referrer=info.name,
                    )
                except _LoadFailure:
                    continue

                for macro_name, macro in imported.macros.items():
                    imported_macros[(alias, macro_name)] = macro

            for local_name, (template_name, imported_name) in info.from_imports.items():
                if not template_name:
                    continue

                try:
                    imported = self._load(
                        template_name,
                        line=1,
                        referrer=info.name,
                    )
                except _LoadFailure:
                    continue

                macro = imported.macros.get(imported_name)

                if macro is not None:
                    macros.setdefault(local_name, macro)

        block_defs = {name: tuple(items) for name, items in blocks.items()}

        return _Context(
            chain[0],
            chain,
            block_defs,
            macros,
            imported_macros,
            {},
        )

    def _template_of(self, node: nodes.Node, default: str) -> str:
        return self._node_templates.get(id(node), default)

    def _const_value(self, node: nodes.Expr) -> t.Any:
        if isinstance(node, nodes.Const):
            return node.value

        if isinstance(node, nodes.TemplateData):
            return node.data

        if not self._is_pure_literal(node):
            return _MISSING

        try:
            return node.as_const()
        except nodes.Impossible:
            return _MISSING
        except Exception:
            return _MISSING

    def _is_pure_literal(self, node: nodes.Node) -> bool:
        if isinstance(
            node,
            (
                nodes.Name,
                nodes.Call,
                nodes.Filter,
                nodes.Test,
                nodes.Getattr,
                nodes.Getitem,
                nodes.NSRef,
                nodes.EnvironmentAttribute,
                nodes.ExtensionAttribute,
                nodes.ImportedName,
                nodes.InternalName,
                nodes.ContextReference,
                nodes.DerivedContextReference,
                nodes.MarkSafe,
                nodes.MarkSafeIfAutoescape,
            ),
        ):
            return False

        return all(self._is_pure_literal(child) for child in node.iter_child_nodes())

    def _const_truth(self, node: nodes.Expr) -> bool | None:
        value = self._const_value(node)

        if value is _MISSING:
            return None

        return bool(value)

    def _issue(
        self,
        state: _State,
        code: str,
        message: str,
        template: str,
        line: int,
        *,
        severity: str = "manual",
    ) -> _State:
        issue = _Issue(code, message, severity, template, line)

        if issue in state.issues:
            return state

        return replace(state, issues=state.issues + (issue,))

    def _add_fact(
        self,
        state: _State,
        node: nodes.Expr,
        truth: bool,
        *,
        kind: str = "condition",
        expression: str | None = None,
        template: str | None = None,
        line: int | None = None,
    ) -> _State | None:
        atom = node

        if expression is None:
            while isinstance(atom, nodes.Not):
                truth = not truth
                atom = atom.node

            expression = self._expr_text(atom)

        condition = PathCondition(
            expression,
            truth,
            template or self._template_of(atom, self.template_name),
            line or atom.lineno or 1,
            kind,
        )

        for existing in state.facts:
            if (
                existing.template == condition.template
                and existing.expression == condition.expression
                and existing.kind in {"condition", "loop"}
                and condition.kind in {"condition", "loop"}
            ):
                if existing.truth != condition.truth:
                    return None

                if existing.kind == "loop" and condition.kind == "condition":
                    return replace(
                        state,
                        facts=tuple(
                            condition if item is existing else item
                            for item in state.facts
                        ),
                    )

                return state

        return replace(state, facts=state.facts + (condition,))

    def _add_capture(
        self, state: _State, name: str, body: Sequence[nodes.Node]
    ) -> _State:
        captures = tuple(item for item in state.captures if item[0] != name)
        return replace(state, captures=captures + ((name, tuple(body)),))

    def _capture_for(self, state: _State, name: str) -> tuple[nodes.Node, ...] | None:
        for key, body in reversed(state.captures):
            if key == name:
                return body

        return None

    def _mark_uncertain(self, state: _State) -> _State:
        if state.uncertain_marker:
            return state

        return replace(state, uncertain_marker=True)

    def _section_hit(
        self, state: _State, name: str, template: str, line: int
    ) -> _State:
        hit = _SectionHit(name, template, line)

        if hit in state.sections:
            return state

        return replace(state, sections=state.sections + (hit,))

    def _marker_hit(self, state: _State, template: str, line: int) -> _State:
        hit = _MarkerHit(self.config.marker.describe(), template, line)

        if hit in state.markers:
            return state

        return replace(state, markers=state.markers + (hit,))

    def _sections_for_literal(
        self, state: _State, value: str, node: nodes.Node
    ) -> _State:
        template = self._template_of(node, self.template_name)
        line = node.lineno or 1

        for section in self.config.managed_sections:
            if any(literal in value for literal in section.literals):
                state = self._section_hit(state, section.name, template, line)

        return state

    def _sections_for_expression(
        self, state: _State, node: nodes.Expr, context: _Context
    ) -> _State:
        value = self._const_value(node)

        if isinstance(value, str):
            state = self._sections_for_literal(state, value, node)

        names = self._loaded_names(node, context)
        template = self._template_of(node, context.template.name)
        line = node.lineno or 1

        for section in self.config.managed_sections:
            if names & section.variables:
                state = self._section_hit(state, section.name, template, line)

        for section_name, description in self._dynamic_section_references(
            node, context
        ):
            state = self._issue(
                state,
                "M_DYNAMIC_REFERENCE",
                f"dynamic section reference {description!r} cannot be resolved"
                " statically; review it manually",
                template,
                line,
            )
            state = self._section_hit(state, section_name, template, line)

        return state

    def _dynamic_section_references(
        self, node: nodes.Expr, context: _Context
    ) -> list[tuple[str, str]]:
        result: list[tuple[str, str]] = []

        candidates = list(node.find_all(nodes.Getitem))

        if isinstance(node, nodes.Getitem):
            candidates.append(node)

        for child in candidates:
            if isinstance(child.arg, nodes.Const):
                continue

            names = self._loaded_names(child.node, context)

            for section in self.config.managed_sections:
                if names & section.variables:
                    result.append((section.name, self._expr_text(child)))

        return result

    def _loaded_names(self, node: nodes.Node, context: _Context) -> set[str]:
        result: set[str] = set()
        pending = [node]
        seen: set[int] = set()

        while pending:
            current = pending.pop()

            if id(current) in seen:
                continue

            seen.add(id(current))

            if isinstance(current, nodes.Name) and current.ctx == "load":
                alias = context.aliases.get(current.name)

                if alias is None:
                    result.add(current.name)
                else:
                    pending.append(alias)

                continue

            pending.extend(current.iter_child_nodes())

        return result

    def _is_marker_expression(self, node: nodes.Expr, context: _Context) -> bool:
        marker = self.config.marker

        if marker.kind == "variable":
            return marker.value in self._loaded_names(node, context)

        if marker.kind == "call":
            for child in node.find_all(nodes.Call):
                if (
                    isinstance(child.node, nodes.Name)
                    and child.node.name == marker.value
                ):
                    return True

            if isinstance(node, nodes.Call) and isinstance(node.node, nodes.Name):
                return node.node.name == marker.value

        return False

    def _expr_text(self, node: nodes.Node) -> str:
        if isinstance(node, nodes.Name):
            return node.name

        if isinstance(node, nodes.Const):
            return repr(node.value)

        if isinstance(node, nodes.TemplateData):
            return repr(node.data)

        if isinstance(node, nodes.Getattr):
            return f"{self._expr_text(node.node)}.{node.attr}"

        if isinstance(node, nodes.Getitem):
            return f"{self._expr_text(node.node)}[{self._expr_text(node.arg)}]"

        if isinstance(node, nodes.Call):
            args = [self._expr_text(item) for item in node.args]
            args.extend(
                f"{item.key}={self._expr_text(item.value)}" for item in node.kwargs
            )
            return f"{self._expr_text(node.node)}({', '.join(args)})"

        if isinstance(node, nodes.Filter):
            if node.node is None:
                return f"|{node.name}"

            return f"{self._expr_text(node.node)}|{node.name}"

        if isinstance(node, nodes.Test):
            return f"{self._expr_text(node.node)} is {node.name}"

        if isinstance(node, nodes.Compare):
            parts = [self._expr_text(node.expr)]

            for operand in node.ops:
                parts.append(operand.op)
                parts.append(self._expr_text(operand.expr))

            return " ".join(parts)

        if isinstance(node, nodes.Not):
            return f"not {self._expr_text(node.node)}"

        if isinstance(node, nodes.And):
            return f"{self._expr_text(node.left)} and {self._expr_text(node.right)}"

        if isinstance(node, nodes.Or):
            return f"{self._expr_text(node.left)} or {self._expr_text(node.right)}"

        if isinstance(node, nodes.BinExpr):
            return (
                f"{self._expr_text(node.left)} {node.operator}"
                f" {self._expr_text(node.right)}"
            )

        if isinstance(node, nodes.UnaryExpr):
            return f"{node.operator}{self._expr_text(node.node)}"

        if isinstance(node, nodes.Concat):
            return " ~ ".join(self._expr_text(item) for item in node.nodes)

        if isinstance(node, nodes.Tuple):
            values = ", ".join(self._expr_text(item) for item in node.items)

            if len(node.items) == 1:
                values += ","

            return f"({values})"

        if isinstance(node, nodes.List):
            return f"[{', '.join(self._expr_text(item) for item in node.items)}]"

        if isinstance(node, nodes.Dict):
            pairs = ", ".join(
                f"{self._expr_text(pair.key)}: {self._expr_text(pair.value)}"
                for pair in node.items
            )
            return f"{{{pairs}}}"

        if isinstance(node, nodes.CondExpr):
            false_text = (
                self._expr_text(node.expr2) if node.expr2 is not None else "undefined"
            )
            return (
                f"{self._expr_text(node.expr1)} if"
                f" {self._expr_text(node.test)} else {false_text}"
            )

        return f"{type(node).__name__}@{node.lineno or '?'}"

    def _process_nodes(
        self,
        items: Sequence[nodes.Node],
        states: list[_State],
        context: _Context,
        block: tuple[str, int, tuple[nodes.Block, ...]] | None,
        stack: tuple[str, ...],
    ) -> list[_State]:
        for item in items:
            states = self._process_node(item, states, context, block, stack)
            states = self._limit_states(states, context)

            if not states:
                break

        return states

    def _limit_states(self, states: list[_State], context: _Context) -> list[_State]:
        unique: dict[_State, _State] = {}

        for state in states:
            unique.setdefault(state, state)

        states = list(unique.values())

        if len(states) <= self.config.max_paths:
            return states

        kept = states[: self.config.max_paths]
        kept[0] = self._issue(
            kept[0],
            "M_PATH_LIMIT",
            f"more than {self.config.max_paths} reachable paths were found;"
            " the remaining paths need manual review",
            context.template.name,
            1,
        )
        return kept

    def _process_node(
        self,
        node: nodes.Node,
        states: list[_State],
        context: _Context,
        block: tuple[str, int, tuple[nodes.Block, ...]] | None,
        stack: tuple[str, ...],
    ) -> list[_State]:
        if isinstance(node, nodes.TemplateData):
            return [
                self._sections_for_literal(state, node.data, node) for state in states
            ]

        if isinstance(node, nodes.Output):
            return self._process_output(node, states, context, block, stack)

        if isinstance(node, nodes.If):
            return self._process_if(node, states, context, block, stack)

        if isinstance(node, nodes.For):
            return self._process_for(node, states, context, block, stack)

        if isinstance(node, nodes.Block):
            return self._process_block(node, states, context, stack)

        if isinstance(node, nodes.Include):
            return self._process_include(node, states, context, stack)

        if isinstance(node, nodes.Extends):
            return states

        if isinstance(node, nodes.Import):
            result: list[_State] = []
            template = self._template_reference(node.template)

            for state in states:
                if not template:
                    state = self._issue(
                        state,
                        "M_DYNAMIC_REFERENCE",
                        "dynamic import expression cannot be resolved statically;"
                        " review it manually",
                        self._template_of(node, context.template.name),
                        node.lineno or 1,
                    )
                else:
                    try:
                        self._load(
                            template,
                            line=node.lineno or 1,
                            referrer=context.template.name,
                        )
                    except _LoadFailure as e:
                        state = self._issue(
                            state,
                            e.code,
                            e.message,
                            e.template,
                            e.line,
                            severity="error",
                        )

                result.append(state)

            return result

        if isinstance(node, nodes.FromImport):
            result = []
            template = self._template_reference(node.template)

            for state in states:
                if not template:
                    state = self._issue(
                        state,
                        "M_DYNAMIC_REFERENCE",
                        "dynamic import expression cannot be resolved statically;"
                        " review it manually",
                        self._template_of(node, context.template.name),
                        node.lineno or 1,
                    )
                else:
                    try:
                        self._load(
                            template,
                            line=node.lineno or 1,
                            referrer=context.template.name,
                        )
                    except _LoadFailure as e:
                        state = self._issue(
                            state,
                            e.code,
                            e.message,
                            e.template,
                            e.line,
                            severity="error",
                        )

                result.append(state)

            return result

        if isinstance(node, nodes.FilterBlock):
            return self._process_nodes(node.body, states, context, block, stack)

        if isinstance(node, nodes.With):
            return self._process_nodes(node.body, states, context, block, stack)

        if isinstance(node, nodes.Scope):
            return self._process_nodes(node.body, states, context, block, stack)

        if isinstance(node, nodes.OverlayScope):
            return self._process_nodes(node.body, states, context, block, stack)

        if isinstance(node, nodes.CallBlock):
            return [
                self._mark_uncertain(
                    self._issue(
                        state,
                        "M_DYNAMIC_OUTPUT",
                        "call blocks are not resolved statically; review the output"
                        " manually",
                        self._template_of(node, context.template.name),
                        node.lineno or 1,
                    )
                )
                for state in states
            ]

        if isinstance(node, nodes.AssignBlock):
            result: list[_State] = []

            for state in states:
                if isinstance(node.target, nodes.Name):
                    result.append(self._add_capture(state, node.target.name, node.body))
                else:
                    result.append(
                        self._issue(
                            state,
                            "M_DYNAMIC_REFERENCE",
                            "dynamic capture target cannot be resolved statically;"
                            " review it manually",
                            self._template_of(node, context.template.name),
                            node.lineno or 1,
                        )
                    )

            return result

        if isinstance(node, nodes.Assign):
            return states

        if isinstance(node, nodes.ExprStmt):
            return states

        if isinstance(node, nodes.Macro):
            return states

        if isinstance(node, nodes.Break) or isinstance(node, nodes.Continue):
            return states

        body = getattr(node, "body", None)

        if isinstance(body, list) and all(
            isinstance(item, nodes.Node) for item in body
        ):
            return self._process_nodes(body, states, context, block, stack)

        return states

    def _process_output(
        self,
        node: nodes.Output,
        states: list[_State],
        context: _Context,
        block: tuple[str, int, tuple[nodes.Block, ...]] | None,
        stack: tuple[str, ...],
    ) -> list[_State]:
        for expression in node.nodes:
            states = self._process_expression(expression, states, context, block, stack)

        return states

    def _process_expression(
        self,
        expression: nodes.Expr,
        states: list[_State],
        context: _Context,
        block: tuple[str, int, tuple[nodes.Block, ...]] | None,
        stack: tuple[str, ...],
    ) -> list[_State]:
        result: list[_State] = []

        for state in states:
            if block is not None and self._is_super_call(expression):
                name, level, definitions = block

                if level + 1 >= len(definitions):
                    result.append(state)
                    continue

                parent = definitions[level + 1]
                parent_block = (name, level + 1, definitions)
                parent_state = self._with_block_stack(state, parent_block, context)

                if parent_state is None:
                    result.append(
                        self._issue(
                            state,
                            "M_RECURSIVE_BLOCK",
                            f"recursive block {name!r} cannot be reviewed statically",
                            self._template_of(parent, context.template.name),
                            parent.lineno or 1,
                        )
                    )
                    continue

                result.extend(
                    self._process_nodes(
                        parent.body,
                        [parent_state],
                        replace(
                            context,
                            block_stack=context.block_stack + ((name, level + 1),),
                        ),
                        parent_block,
                        stack,
                    )
                )
                continue

            if isinstance(expression, nodes.Name):
                captured = self._capture_for(state, expression.name)

                if captured is not None:
                    if expression.name in context.capture_stack:
                        result.append(
                            self._issue(
                                state,
                                "M_RECURSIVE_CAPTURE",
                                f"recursive capture {expression.name!r} cannot be"
                                " reviewed statically",
                                self._template_of(expression, context.template.name),
                                expression.lineno or 1,
                            )
                        )
                    else:
                        result.extend(
                            self._process_nodes(
                                captured,
                                [state],
                                replace(
                                    context,
                                    capture_stack=context.capture_stack
                                    + (expression.name,),
                                ),
                                block,
                                stack,
                            )
                        )

                    continue

            if isinstance(expression, nodes.Filter) and expression.node is not None:
                result.extend(
                    self._process_expression(
                        expression.node, [state], context, block, stack
                    )
                )
                continue

            if isinstance(expression, nodes.Concat):
                current = [state]

                for item in expression.nodes:
                    current = self._process_expression(
                        item, current, context, block, stack
                    )

                result.extend(current)
                continue

            if isinstance(expression, nodes.CondExpr):
                truth = self._const_truth(expression.test)

                if truth is True:
                    result.extend(
                        self._process_expression(
                            expression.expr1, [state], context, block, stack
                        )
                    )
                    continue

                if truth is False:
                    if expression.expr2 is not None:
                        result.extend(
                            self._process_expression(
                                expression.expr2, [state], context, block, stack
                            )
                        )
                    else:
                        result.append(state)

                    continue

                true_state = self._add_fact(state, expression.test, True)

                if true_state is not None:
                    result.extend(
                        self._process_expression(
                            expression.expr1, [true_state], context, block, stack
                        )
                    )

                false_state = self._add_fact(state, expression.test, False)

                if false_state is not None:
                    if expression.expr2 is not None:
                        result.extend(
                            self._process_expression(
                                expression.expr2,
                                [false_state],
                                context,
                                block,
                                stack,
                            )
                        )
                    else:
                        result.append(false_state)

                continue

            macro = self._resolve_macro(expression, context)

            if macro is not None:
                macro_key = id(macro)

                if macro_key in context.macro_stack:
                    result.append(
                        self._issue(
                            state,
                            "M_RECURSIVE_MACRO",
                            "recursive macro output cannot be reviewed statically",
                            self._template_of(macro, context.template.name),
                            macro.lineno or 1,
                        )
                    )
                    continue

                binding = self._macro_binding(expression, macro, context)
                macro_context = replace(
                    context,
                    aliases={**context.aliases, **binding},
                    macro_stack=context.macro_stack + (macro_key,),
                )
                expanded = self._process_nodes(
                    macro.body,
                    [state],
                    macro_context,
                    block,
                    stack,
                )

                if self.config.marker.kind == "call" and self._is_marker_expression(
                    expression, context
                ):
                    expanded = [
                        self._marker_hit(
                            item,
                            self._template_of(expression, context.template.name),
                            expression.lineno or 1,
                        )
                        for item in expanded
                    ]

                result.extend(expanded)
                continue

            state = self._sections_for_expression(state, expression, context)

            if self._is_marker_expression(expression, context):
                state = self._marker_hit(
                    state,
                    self._template_of(expression, context.template.name),
                    expression.lineno or 1,
                )

            issue = self._dynamic_output_issue(expression, context)

            if issue is not None:
                state = self._issue(
                    state,
                    "M_DYNAMIC_OUTPUT",
                    issue,
                    self._template_of(expression, context.template.name),
                    expression.lineno or 1,
                )
                state = self._mark_uncertain(state)

            result.append(state)

        return result

    def _is_super_call(self, node: nodes.Expr) -> bool:
        return (
            isinstance(node, nodes.Call)
            and isinstance(node.node, nodes.Name)
            and node.node.name == "super"
            and not node.args
            and not node.kwargs
        )

    def _resolve_macro(self, node: nodes.Expr, context: _Context) -> nodes.Macro | None:
        if not isinstance(node, nodes.Call):
            return None

        callee = node.node

        if isinstance(callee, nodes.Name):
            return context.macros.get(callee.name)

        if isinstance(callee, nodes.Getattr) and isinstance(callee.node, nodes.Name):
            return context.imported_macros.get((callee.node.name, callee.attr))

        return None

    def _macro_binding(
        self,
        call: nodes.Expr,
        macro: nodes.Macro,
        context: _Context,
    ) -> dict[str, nodes.Expr]:
        if not isinstance(call, nodes.Call):
            return {}

        binding: dict[str, nodes.Expr] = {}
        positional = {
            arg.name: value for arg, value in zip(macro.args, call.args, strict=False)
        }
        keywords = {item.key: item.value for item in call.kwargs}
        defaults = {
            argument.name: value
            for argument, value in zip(
                macro.args[-len(macro.defaults) :], macro.defaults, strict=False
            )
        }

        for argument in macro.args:
            value = keywords.get(argument.name, positional.get(argument.name))

            if value is None:
                value = defaults.get(argument.name)

            if value is not None:
                binding[argument.name] = value

        return binding

    def _dynamic_output_issue(self, node: nodes.Expr, context: _Context) -> str | None:
        if not isinstance(node, nodes.Call):
            return None

        callee = node.node

        if isinstance(callee, nodes.Name):
            if callee.name in self.environment.globals:
                return None

            if callee.name in context.macros:
                return None

            if (
                self.config.marker.kind == "call"
                and callee.name == self.config.marker.value
            ):
                return None

            return (
                f"output call {callee.name!r} cannot be resolved statically;"
                " review it manually"
            )

        if isinstance(callee, nodes.Getattr) and isinstance(callee.node, nodes.Name):
            if (callee.node.name, callee.attr) in context.imported_macros:
                return None

            return (
                f"output call {callee.node.name}.{callee.attr} cannot be resolved"
                " statically; review it manually"
            )

        return None

    def _process_if(
        self,
        node: nodes.If,
        states: list[_State],
        context: _Context,
        block: tuple[str, int, tuple[nodes.Block, ...]] | None,
        stack: tuple[str, ...],
    ) -> list[_State]:
        result: list[_State] = []

        for state in states:
            truth = self._const_truth(node.test)

            if truth is True:
                result.extend(
                    self._process_nodes(node.body, [state], context, block, stack)
                )
                continue

            if truth is False:
                result.extend(self._process_else(node, state, context, block, stack))
                continue

            true_state = self._add_fact(state, node.test, True)

            if true_state is not None:
                result.extend(
                    self._process_nodes(node.body, [true_state], context, block, stack)
                )

            false_state = self._add_fact(state, node.test, False)

            if false_state is not None:
                result.extend(
                    self._process_else(node, false_state, context, block, stack)
                )

        return result

    def _process_else(
        self,
        node: nodes.If,
        state: _State,
        context: _Context,
        block: tuple[str, int, tuple[nodes.Block, ...]] | None,
        stack: tuple[str, ...],
    ) -> list[_State]:
        if node.elif_:
            return self._process_elif_chain(
                node.elif_, node.else_, state, context, block, stack
            )

        return self._process_nodes(node.else_, [state], context, block, stack)

    def _process_elif_chain(
        self,
        elif_nodes: Sequence[nodes.If],
        final_else: Sequence[nodes.Node],
        state: _State,
        context: _Context,
        block: tuple[str, int, tuple[nodes.Block, ...]] | None,
        stack: tuple[str, ...],
    ) -> list[_State]:
        result: list[_State] = []

        for elif_node in elif_nodes:
            truth = self._const_truth(elif_node.test)

            if truth is True:
                result.extend(
                    self._process_nodes(elif_node.body, [state], context, block, stack)
                )
                return result

            if truth is False:
                continue

            true_state = self._add_fact(state, elif_node.test, True)

            if true_state is not None:
                result.extend(
                    self._process_nodes(
                        elif_node.body, [true_state], context, block, stack
                    )
                )

            false_state = self._add_fact(state, elif_node.test, False)

            if false_state is None:
                return result

            state = false_state

        result.extend(self._process_nodes(final_else, [state], context, block, stack))
        return result

    def _process_for(
        self,
        node: nodes.For,
        states: list[_State],
        context: _Context,
        block: tuple[str, int, tuple[nodes.Block, ...]] | None,
        stack: tuple[str, ...],
    ) -> list[_State]:
        result: list[_State] = []
        iterable_text = self._expr_text(node.iter)
        value = self._const_value(node.iter)
        known_sequence = isinstance(value, (str, list, tuple, dict, set, frozenset))
        empty = known_sequence and len(value) == 0  # type: ignore[arg-type]
        nonempty = known_sequence and not empty

        for state in states:
            if empty:
                zero = self._add_fact(
                    state,
                    node.iter,
                    False,
                    kind="loop",
                    expression=iterable_text,
                )

                if zero is not None:
                    result.extend(
                        self._process_nodes(node.else_, [zero], context, block, stack)
                    )

                continue

            body_base = self._add_fact(
                state,
                node.iter,
                True,
                kind="loop",
                expression=iterable_text,
            )

            if body_base is not None:
                body_state: _State | None = body_base

                if node.test is not None:
                    body_state = self._add_fact(body_state, node.test, True)

                if body_state is not None:
                    after_body = self._process_nodes(
                        node.body, [body_state], context, block, stack
                    )

                    for item in after_body:
                        result.append(replace(item, facts=body_base.facts))

            if nonempty and node.test is None:
                continue

            if node.test is not None:
                zero = self._add_fact(
                    state,
                    node.test,
                    False,
                    kind="note",
                    expression=(
                        f"{iterable_text} has no item passing"
                        f" {self._expr_text(node.test)}"
                    ),
                )
            else:
                zero = self._add_fact(
                    state,
                    node.iter,
                    False,
                    kind="loop",
                    expression=iterable_text,
                )

            if zero is not None:
                result.extend(
                    self._process_nodes(node.else_, [zero], context, block, stack)
                )

        return result

    def _with_block_stack(
        self,
        state: _State,
        block: tuple[str, int, tuple[nodes.Block, ...]],
        context: _Context,
    ) -> _State | None:
        name, level, _ = block

        if (name, level) in context.block_stack:
            return None

        return state

    def _process_block(
        self,
        node: nodes.Block,
        states: list[_State],
        context: _Context,
        stack: tuple[str, ...],
    ) -> list[_State]:
        definitions = context.block_defs.get(node.name, (node,))

        if not definitions:
            definitions = (node,)

        effective = definitions[0]
        key = (node.name, 0)

        if key in context.block_stack:
            return [
                self._issue(
                    state,
                    "M_RECURSIVE_BLOCK",
                    f"recursive block {node.name!r} cannot be reviewed statically",
                    self._template_of(effective, context.template.name),
                    effective.lineno or 1,
                )
                for state in states
            ]

        result: list[_State] = []

        for state in states:
            for section in self.config.managed_sections:
                if node.name in section.blocks:
                    state = self._section_hit(
                        state,
                        section.name,
                        self._template_of(effective, context.template.name),
                        effective.lineno or 1,
                    )

            if effective.required and len(definitions) == 1:
                state = self._issue(
                    state,
                    "E_REQUIRED_BLOCK",
                    f"required block {node.name!r} has no override",
                    self._template_of(effective, context.template.name),
                    effective.lineno or 1,
                    severity="error",
                )

            result.extend(
                self._process_nodes(
                    effective.body,
                    [state],
                    replace(
                        context,
                        block_stack=context.block_stack + (key,),
                    ),
                    (node.name, 0, definitions),
                    stack,
                )
            )

        return result

    def _process_include(
        self,
        node: nodes.Include,
        states: list[_State],
        context: _Context,
        stack: tuple[str, ...],
    ) -> list[_State]:
        value = self._const_value(node.template)

        candidates: list[str]

        if isinstance(value, str):
            candidates = [value]
        elif isinstance(value, (list, tuple)) and all(
            isinstance(item, str) for item in value
        ):
            candidates = [item for item in value if isinstance(item, str)]
        else:
            return [
                self._mark_uncertain(
                    self._issue(
                        state,
                        "M_DYNAMIC_REFERENCE",
                        "dynamic include expression cannot be resolved statically;"
                        " review the included output manually",
                        self._template_of(node, context.template.name),
                        node.lineno or 1,
                    )
                )
                for state in states
            ]

        result: list[_State] = []

        for state in states:
            selected: str | None = None
            had_error = False
            missing: _LoadFailure | None = None

            for candidate in candidates:
                try:
                    self._load(
                        candidate,
                        line=node.lineno or 1,
                        referrer=context.template.name,
                    )
                except _LoadFailure as e:
                    if e.code == "E_TEMPLATE_NOT_FOUND":
                        missing = e
                        continue

                    result.append(
                        self._issue(
                            state,
                            e.code,
                            e.message,
                            e.template,
                            e.line,
                            severity="error",
                        )
                    )
                    had_error = True
                    break

                selected = candidate
                break

            if had_error:
                continue

            if selected is None:
                if missing is not None and node.ignore_missing:
                    result.append(state)
                    continue

                if missing is not None:
                    result.append(
                        self._issue(
                            state,
                            missing.code,
                            missing.message,
                            missing.template,
                            missing.line,
                            severity="error",
                        )
                    )
                    continue

                result.append(
                    self._issue(
                        state,
                        "M_MISSING_INCLUDE",
                        "all possible include targets are missing; the include"
                        " renders no output",
                        self._template_of(node, context.template.name),
                        node.lineno or 1,
                    )
                )
                continue

            for section in self.config.managed_sections:
                if selected in section.templates:
                    state = self._section_hit(
                        state,
                        section.name,
                        self._template_of(node, context.template.name),
                        node.lineno or 1,
                    )

            if (
                self.config.marker.kind == "template"
                and selected == self.config.marker.value
            ):
                state = self._marker_hit(
                    state,
                    self._template_of(node, context.template.name),
                    node.lineno or 1,
                )

            result.extend(self._render(selected, state, stack))

        return result


def _load_config(path: Path) -> tuple[ReviewConfig, list[str], list[str]]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise ReviewError(f"could not read config {path}: {e}") from e

    if not isinstance(data, dict):
        raise ReviewError("configuration must be a JSON object")

    config = ReviewConfig.from_mapping(data)
    raw_templates = data.get("templates", ())

    if isinstance(raw_templates, str):
        raw_templates = [raw_templates]

    raw_paths = data.get("search_paths", ())

    if isinstance(raw_paths, str):
        raw_paths = [raw_paths]

    templates = [str(item) for item in raw_templates]
    search_paths = [str(item) for item in raw_paths]

    return config, templates, search_paths


def _expand_templates(templates: Iterable[str], base: Path) -> list[Path]:
    result: list[Path] = []

    for item in templates:
        path = Path(item)

        if not path.is_absolute():
            path = base / path

        matches = sorted(path.parent.glob(path.name))

        if matches:
            result.extend(matches)
        else:
            result.append(path)

    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m jinja2.compliance",
        description="statically review Jinja templates for managed-section markers",
    )
    parser.add_argument("--config", required=True, help="path to the JSON config")
    parser.add_argument(
        "--template",
        action="append",
        default=[],
        help="root template to review; may be given multiple times",
    )
    parser.add_argument(
        "--search-path",
        action="append",
        default=[],
        help="template search path; may be given multiple times",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON output")
    parser.add_argument(
        "--max-paths",
        type=int,
        default=None,
        help="maximum number of reachable paths to keep per template",
    )
    args = parser.parse_args(argv)

    config_path = Path(args.config)

    try:
        config, configured_templates, configured_paths = _load_config(config_path)
    except ReviewError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    template_names = args.template or configured_templates

    if not template_names:
        print("error: no templates configured", file=sys.stderr)
        return 2

    base = config_path.parent
    search_paths = args.search_path or configured_paths

    if not search_paths:
        search_paths = [str(base)]
    else:
        search_paths = [
            str(Path(item) if Path(item).is_absolute() else base / item)
            for item in search_paths
        ]

    template_base = Path.cwd() if args.template else base
    templates = _expand_templates(template_names, template_base)

    try:
        result = review_files(
            templates,
            config,
            search_path=search_paths,
            max_paths=args.max_paths,
        )
    except (OSError, ReviewError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result.as_dict(), indent=2, ensure_ascii=False))
    else:
        print(result.format_text())

    if result.status == "fail":
        return 1

    if result.status == "manual":
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
