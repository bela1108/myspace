"""Mapping review for the merged log source pipeline.

The auditor combines two views:

1. A static index built directly from the FieldMappingTransformation items of
   the pipeline.  It classifies every source->target edge as reversible (the
   target has a unique source), many-to-one (several sources collapse into one
   target) or fan-out (one source expands into several targets).
2. A dynamic view produced by the fake backend.  Each converted detection item
   is traced back to the original detection it came from, including the rule
   condition branch (AND/OR nesting) and the processing items that fired.

For every colliding target field the module emits the smallest possible set of
witness detection items (one per distinct source field) so the review team can
see exactly which original rule condition lost its identity.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from sigma.processing.pipeline import ProcessingPipeline
from sigma.processing.transformations import FieldMappingTransformation

from field_mapping_audit.fake_backend import ConvertedItemTrace


@dataclass
class MappingEdge:
    """One static source->target mapping declared by a processing item."""

    source: str
    targets: tuple[str, ...]
    processing_item_id: str
    rule_condition: str | None


@dataclass
class MappingClassification:
    """Result of classifying the static mapping table."""

    reversible: dict[str, str] = field(default_factory=dict)
    many_to_one: dict[str, list[str]] = field(default_factory=dict)
    fan_out: dict[str, list[str]] = field(default_factory=dict)
    edges: list[MappingEdge] = field(default_factory=list)
    reverse_index: dict[str, set[str]] = field(default_factory=dict)


@dataclass
class CollisionEvidence:
    """Minimal witness set for one target field affected by a collision."""

    target_field: str
    witness_traces: list[ConvertedItemTrace]
    source_fields: list[str]
    reversible: bool


def _describe_condition(condition) -> str:
    name = type(condition).__name__
    if name == "LogsourceCondition":
        bits = [
            "{}={}".format(attr, getattr(condition, attr))
            for attr in ("category", "product", "service")
            if getattr(condition, attr, None) is not None
        ]
        return "Logsource({})".format(", ".join(bits))
    if name == "ContainsWildcardCondition":
        return "ContainsWildcard(cond={})".format(getattr(condition, "cond", "any"))
    if name == "RuleContainsFieldCondition":
        return "RuleContainsField(field={})".format(getattr(condition, "field", None))
    attrs = {
        key: value
        for key, value in vars(condition).items()
        if not key.startswith("_") and value is not None
    }
    return "{}({})".format(name, attrs)


def _describe_rule_conditions(item) -> str | None:
    conditions = list(item.rule_conditions) + list(item.detection_item_conditions)
    if not conditions:
        return None
    return " AND ".join(_describe_condition(condition) for condition in conditions)
    return " AND ".join(parts)

def build_static_index(pipeline: ProcessingPipeline) -> MappingClassification:
    """Classify all field mapping edges declared in the pipeline."""
    classification = MappingClassification()
    for item in pipeline.items:
        transformation = item.transformation
        if not isinstance(transformation, FieldMappingTransformation):
            continue
        condition_description = _describe_rule_conditions(item)
        for source, destination in transformation.mapping.items():
            targets = (destination,) if isinstance(destination, str) else tuple(destination)
            edge = MappingEdge(
                source=source,
                targets=targets,
                processing_item_id=item.identifier or "<no-id>",
                rule_condition=condition_description,
            )
            classification.edges.append(edge)
            if len(targets) > 1:
                classification.fan_out[source] = list(targets)
            for target in targets:
                classification.reverse_index.setdefault(target, set()).add(source)
    for target, sources in classification.reverse_index.items():
        if len(sources) == 1:
            (only_source,) = sources
            only_edge = next(edge for edge in classification.edges if target in edge.targets)
            if len(only_edge.targets) == 1:
                classification.reversible[target] = only_source
        else:
            classification.many_to_one[target] = sorted(sources)
    return classification

def build_collision_evidence(
    traces: list[ConvertedItemTrace],
    classification: MappingClassification,
) -> list[CollisionEvidence]:
    """Group backend traces by target field and keep one witness per source."""
    by_target: dict[str, list[ConvertedItemTrace]] = {}
    for trace in traces:
        if trace.converted_field is None:
            continue
        by_target.setdefault(trace.converted_field, []).append(trace)
    evidence: list[CollisionEvidence] = []
    for target_field, target_traces in sorted(by_target.items()):
        sources = sorted({
            trace.original_field for trace in target_traces if trace.original_field is not None
        })
        if len(sources) <= 1:
            continue
        witnesses = _minimal_witnesses(target_traces)
        evidence.append(
            CollisionEvidence(
                target_field=target_field,
                witness_traces=witnesses,
                source_fields=sources,
                reversible=target_field in classification.reversible,
            )
        )
    return evidence


def _minimal_witnesses(
    traces: list[ConvertedItemTrace],
) -> list[ConvertedItemTrace]:
    """Pick the first trace for each distinct original field (smallest witness set)."""
    seen: set[str] = set()
    witnesses: list[ConvertedItemTrace] = []
    for trace in traces:
        source = trace.original_field
        if source is None or source in seen:
            continue
        seen.add(source)
        witnesses.append(trace)
    return witnesses


def conditional_paths(
    traces: list[ConvertedItemTrace],
    classification: MappingClassification,
) -> dict[str, dict[str, object]]:
    """Summarise firing and skipped paths for every field mapping item."""
    item_to_edges: dict[str, list[MappingEdge]] = {}
    for edge in classification.edges:
        item_to_edges.setdefault(edge.processing_item_id, []).append(edge)
    summary: dict[str, dict[str, object]] = {}
    for item_id, edges in item_to_edges.items():
        summary[item_id] = {
            "rules": set(),
            "selectors": set(),
            "branches": set(),
            "mappings": edges,
            "skipped": [],
        }
    source_to_item = {
        edge.source: edge.processing_item_id
        for edge in classification.edges
    }
    for trace in traces:
        owner_item = source_to_item.get(trace.original_field)
        if owner_item is None:
            continue
        entry = summary[owner_item]
        if owner_item in trace.applied_processing_item_ids:
            entry["rules"].add(trace.rule_name)
            entry["selectors"].add(trace.selector)
            entry["branches"].add(trace.boolean_branch)
        else:
            entry["skipped"].append(trace)
    return summary

def load_rules_yaml(rules_dir: str | Path) -> str:
    """Concatenate all Sigma rule YAML files in a directory into one document."""
    documents: list[str] = []
    for path in sorted(Path(rules_dir).glob("*.yml")):
        documents.append(path.read_text(encoding="utf-8"))
    if not documents:
        raise FileNotFoundError(f"no rule files found in {rules_dir}")
    return "\n---\n".join(documents)


def render_report(
    classification: MappingClassification,
    traces: list[ConvertedItemTrace],
    evidence: list[CollisionEvidence],
    paths: dict[str, dict[str, object]],
) -> str:
    """Render a human-readable review report."""
    lines: list[str] = []
    lines.append("# Field mapping review for merged log source")
    lines.append("")
    lines.append("## Static mapping classification")
    lines.append("")
    for edge in classification.edges:
        arrow = " -> ".join(edge.targets)
        guard = f" | guard: {edge.rule_condition}" if edge.rule_condition else ""
        lines.append(f"- {edge.source} -> {arrow} [{edge.processing_item_id}]{guard}")
    lines.append("")
    lines.append("### Reversible (target uniquely identifies source)")
    for target, source in sorted(classification.reversible.items()):
        lines.append(f"- {target} <- {source}")
    lines.append("")
    lines.append("### Many-to-one collisions (source identity lost)")
    if not classification.many_to_one:
        lines.append("- none")
    for target, sources in sorted(classification.many_to_one.items()):
        lines.append("- {} <- {}".format(target, ", ".join(sources)))
    lines.append("")
    lines.append("### Fan-out (one source expands to several targets)")
    if not classification.fan_out:
        lines.append("- none")
    for source, targets in sorted(classification.fan_out.items()):
        lines.append("- {} -> {}".format(source, ", ".join(targets)))
    return "\n".join(lines)

def _render_paths_section(paths: dict[str, dict[str, object]]) -> list[str]:
    lines: list[str] = []
    lines.append("")
    lines.append("## Conditional transformation firing paths")
    lines.append("")
    if not paths:
        lines.append("- no field mapping transformation fired on any rule")
        return lines
    for item_id, entry in sorted(paths.items()):
        fired = bool(entry["rules"])
        status = "fired" if fired else "never fired"
        lines.append("- processing item `{}` ({})".format(item_id, status))
        for edge in entry["mappings"]:
            guard = edge.rule_condition or "unconditional"
            lines.append(
                "  - edge {} -> {} (guard: {})".format(
                    edge.source, ", ".join(edge.targets), guard
                )
            )
        if fired:
            lines.append("  - fired on rules: {}".format(", ".join(sorted(entry["rules"]))))
            lines.append("  - selectors touched: {}".format(", ".join(sorted(entry["selectors"]))))
            lines.append("  - boolean branches: {}".format(", ".join(sorted(entry["branches"]))))
        skipped: list[ConvertedItemTrace] = entry["skipped"]
        if skipped:
            lines.append("  - skipped source paths (guard not satisfied, field kept):")
            for trace in skipped:
                lines.append(
                "    * rule `{}` selector `{}` source `{}` stays `{}` value `{}`".format(
                    trace.rule_name,
                    trace.selector,
                    trace.original_field,
                    trace.converted_field,
                    trace.value_repr,
                )
            )
    return lines
    return lines


def run_review(rules_dir: str | Path) -> tuple[str, MappingClassification, list[ConvertedItemTrace], list[CollisionEvidence]]:
    from field_mapping_audit.fake_backend import run_audit_backend
    from field_mapping_audit.pipeline import merged_logsource_pipeline

    pipeline = merged_logsource_pipeline()
    rules_yaml = load_rules_yaml(rules_dir)
    backend, queries = run_audit_backend(rules_yaml, pipeline)
    classification = build_static_index(pipeline)
    evidence = build_collision_evidence(backend.traces, classification)
    paths = conditional_paths(backend.traces, classification)
    report = render_report(classification, backend.traces, evidence, paths)
    report = report + "\n" + "\n".join(_render_dynamic_section(backend.traces, evidence, paths))
    report = report + "\n" + "\n".join(_render_paths_section(paths))
    report = report + "\n" + "\n".join(_render_query_section(queries))
    return report, classification, backend.traces, evidence

def _render_dynamic_section(
    traces: list[ConvertedItemTrace],
    evidence: list[CollisionEvidence],
    paths: dict[str, dict[str, object]],
) -> list[str]:
    lines: list[str] = []
    lines.append("## Backend trace (source condition -> converted field)")
    lines.append("")
    lines.append("| rule | selector | branch | source field | target field | value | processing items |")
    lines.append("| --- | --- | --- | --- | --- | --- | --- |")
    for trace in traces:
        items = ", ".join(sorted(trace.applied_processing_item_ids)) or "-"
        row = "| {} | {} | {} | {} | {} | {} | {} |".format(
            trace.rule_name,
            trace.selector,
            trace.boolean_branch,
            trace.original_field or "-",
            trace.converted_field or "-",
            trace.value_repr,
            items,
        )
        lines.append(row)
    lines.append("")
    lines.append("## Minimal collision evidence")
    lines.append("")
    if not evidence:
        lines.append("- no collisions observed in converted rules")
    for collision in evidence:
        joined = ", ".join(collision.source_fields)
        kind = "reversible target" if collision.reversible else "many-to-one target"
        lines.append("### target `{}` ({})".format(collision.target_field, kind))
        lines.append("colliding source fields: {}".format(joined))
        for witness in collision.witness_traces:
            item_list = ", ".join(sorted(witness.applied_processing_item_ids))
            lines.append(
                "- witness: rule `{}` selector `{}` branch `{}` source `{}` value `{}` items `{}`".format(
                    witness.rule_name,
                    witness.selector,
                    witness.boolean_branch,
                    witness.original_field,
                    witness.value_repr,
                    item_list,
                )
            )
        lines.append("")
    return lines

def _render_query_section(queries: list[str]) -> list[str]:
    lines = ["## Converted queries (fake backend output)", ""]
    for index, query in enumerate(queries, start=1):
        lines.append("{}. {}".format(index, query))
    return lines


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Field mapping review for the merged log source.")
    parser.add_argument("rules_dir", nargs="?", default="field_mapping_audit/rules")
    parser.add_argument("--output", default="field_mapping_audit/review_report.md")
    args = parser.parse_args()
    report, _, _, _ = run_review(args.rules_dir)
    Path(args.output).write_text(report, encoding="utf-8")
    print(report)
    print("")
    print("report written to {}".format(args.output))


if __name__ == "__main__":
    main()
