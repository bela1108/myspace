"""Read-only redundancy analysis for finite policy tables.

This module is a read-only analysis interface built on PyYAML's safe
reading side.  Policy tables are parsed with ``yaml.compose`` and
``yaml.SafeLoader`` -- no Python objects are constructed from the input
and the input is never modified -- then the analyzer reports which
clauses are fully covered by other *valid* clauses.  The analysis is
restricted to the operation and attribute domains declared in the
table's local dictionary.

Policy table schema (a single YAML mapping)::

    dictionary:
      operations: [read, write]        # allowed operations
      subjects:   [alice, bob]         # known subjects
      attributes:                      # attribute -> allowed values
        level: [low, high]
    clauses:
      - id: allow-read-low             # optional, defaults to clause-N
        effect: allow                  # allow | deny (explicit deny)
        operation: read                # scalar, list, or null = all
        subjects: {except: [mallory]}  # scalar, list, null = all, or except-map
        attributes:
          level: low                   # scalar, list, or null = any value

Semantics:

* ``effect: deny`` is an explicit denial; deny clauses only ever cover
  other deny clauses, never allow clauses (and vice versa).
* An explicit ``null`` (or a missing key) for ``operation``,
  ``subjects`` or an attribute value is a wildcard over the whole
  domain declared in the local dictionary.
* Anything that parses but is not supported by the analyzer (unknown
  operations/attributes/values, unsupported node shapes, duplicate
  keys, ...) degrades the affected clause to the ``undetermined``
  verdict instead of failing the whole run.
* Every reported item carries the source lines of its YAML node.

The closest pair of valid clauses that differs on exactly one
exception subject is surfaced as ``review_hint`` with the differing
subject and the affected line numbers, for a human reviewer.
"""

from __future__ import annotations

import itertools
import json
import sys

import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode

__all__ = ["analyze_policy_table", "analyze_policy_tables"]

_NULL_TAG = "tag:yaml.org,2002:null"
_STR_TAG = "tag:yaml.org,2002:str"

_EFFECTS = ("allow", "deny")
_TABLE_KEYS = frozenset({"dictionary", "clauses"})
_DICTIONARY_KEYS = frozenset({"operations", "subjects", "attributes"})
_CLAUSE_KEYS = frozenset({"id", "effect", "operation", "subjects", "attributes"})


class _Unsupported(Exception):
    """A parseable node fell outside the analyzer's supported domain."""


def _mark(mark):
    return {"line": mark.line + 1, "column": mark.column + 1}


def _span(node):
    return {"start": _mark(node.start_mark), "end": _mark(node.end_mark)}


def _is_null(node):
    return isinstance(node, ScalarNode) and node.tag == _NULL_TAG


def _scalar_text(node):
    if not isinstance(node, ScalarNode):
        raise _Unsupported("expected a scalar node")
    if node.tag == _NULL_TAG:
        return None
    if node.tag != _STR_TAG:
        raise _Unsupported("unsupported scalar tag %r" % node.tag)
    return node.value


def _mapping_items(node):
    """Yield ``(key, key_node, value_node)``; reject exotic/duplicate keys."""
    seen = set()
    for key_node, value_node in node.value:
        key = _scalar_text(key_node)
        if key is None:
            raise _Unsupported("null mapping key")
        if key in seen:
            raise _Unsupported("duplicate key %r" % key)
        seen.add(key)
        yield key, key_node, value_node


def _string_set(node, domain, what):
    """Parse scalar | sequence-of-scalars | null into a set within ``domain``.

    ``node=None`` (missing key) and explicit ``null`` both mean the
    whole domain (wildcard).
    """
    if node is None or _is_null(node):
        return frozenset(domain)
    if isinstance(node, ScalarNode):
        value = _scalar_text(node)
        if value not in domain:
            raise _Unsupported("%s %r is not in the local dictionary" % (what, value))
        return frozenset({value})
    if isinstance(node, SequenceNode):
        values = []
        for item in node.value:
            value = _scalar_text(item)
            if value is None:
                raise _Unsupported("null entry in %s list" % what)
            if value not in domain:
                raise _Unsupported("%s %r is not in the local dictionary" % (what, value))
            values.append(value)
        return frozenset(values)
    raise _Unsupported("unsupported %s expression" % what)


def _subject_set(node, domain):
    if isinstance(node, MappingNode):
        items = list(_mapping_items(node))
        if len(items) != 1 or items[0][0] != "except":
            raise _Unsupported("subjects mapping only supports the 'except' form")
        excluded = _string_set(items[0][2], domain, "subject")
        return frozenset(domain) - excluded
    return _string_set(node, domain, "subject")


def _domain_list(node, what):
    if not isinstance(node, SequenceNode):
        raise _Unsupported("dictionary %s must be a sequence" % what)
    values = []
    for item in node.value:
        value = _scalar_text(item)
        if value is None:
            raise _Unsupported("null entry in dictionary %s" % what)
        values.append(value)
    if not values:
        raise _Unsupported("dictionary %s must not be empty" % what)
    if len(set(values)) != len(values):
        raise _Unsupported("duplicate entries in dictionary %s" % what)
    return tuple(values)


def _parse_dictionary(node):
    if not isinstance(node, MappingNode):
        raise _Unsupported("dictionary must be a mapping")
    raw = {}
    for key, _key_node, value_node in _mapping_items(node):
        if key not in _DICTIONARY_KEYS:
            raise _Unsupported("unknown dictionary key %r" % key)
        raw[key] = value_node
    missing = _DICTIONARY_KEYS - raw.keys()
    if missing:
        raise _Unsupported("dictionary is missing %s" % sorted(missing))
    attributes = {}
    attr_node = raw["attributes"]
    if not isinstance(attr_node, MappingNode):
        raise _Unsupported("dictionary attributes must be a mapping")
    for name, _key_node, value_node in _mapping_items(attr_node):
        attributes[name] = _domain_list(value_node, "attribute %r" % name)
    return {
        "operations": _domain_list(raw["operations"], "operations"),
        "subjects": _domain_list(raw["subjects"], "subjects"),
        "attributes": attributes,
    }


class _Clause:
    def __init__(self, index, node):
        self.index = index
        self.node = node
        self.id = "clause-%d" % (index + 1)
        self.effect = None
        self.operations = frozenset()
        self.subjects = frozenset()
        self.attributes = {}
        self.denotation = frozenset()

    @property
    def span(self):
        return _span(self.node)


def _parse_clause(index, node, dictionary):
    clause = _Clause(index, node)
    if not isinstance(node, MappingNode):
        raise _Unsupported("clause must be a mapping")
    raw = {}
    for key, _key_node, value_node in _mapping_items(node):
        if key not in _CLAUSE_KEYS:
            raise _Unsupported("unknown clause key %r" % key)
        raw[key] = value_node
    if "id" in raw:
        clause_id = _scalar_text(raw["id"])
        if clause_id is None:
            raise _Unsupported("clause id must be a string")
        clause.id = clause_id
    if "effect" not in raw:
        raise _Unsupported("clause is missing 'effect'")
    effect = _scalar_text(raw["effect"])
    if effect not in _EFFECTS:
        raise _Unsupported("unsupported effect %r" % effect)
    clause.effect = effect
    clause.operations = _string_set(
        raw.get("operation"), dictionary["operations"], "operation"
    )
    clause.subjects = _subject_set(raw.get("subjects"), dictionary["subjects"])
    attr_node = raw.get("attributes")
    attrs = {}
    if attr_node is not None and not _is_null(attr_node):
        if not isinstance(attr_node, MappingNode):
            raise _Unsupported("clause attributes must be a mapping")
        for name, _key_node, value_node in _mapping_items(attr_node):
            if name not in dictionary["attributes"]:
                raise _Unsupported(
                    "attribute %r is not in the local dictionary" % name
                )
            attrs[name] = _string_set(
                value_node, dictionary["attributes"][name], "attribute %r" % name
            )
    for name, domain in dictionary["attributes"].items():
        attrs.setdefault(name, frozenset(domain))
    clause.attributes = attrs
    return clause


def _denotation(clause, dictionary):
    attr_names = tuple(dictionary["attributes"])
    points = set()
    for operation, subject, values in itertools.product(
        sorted(clause.operations),
        sorted(clause.subjects),
        itertools.product(
            *(sorted(clause.attributes[name]) for name in attr_names)
        ),
    ):
        points.add((operation, subject, values))
    return frozenset(points)


def _parse_table(node):
    if not isinstance(node, MappingNode):
        raise _Unsupported("policy table must be a mapping")
    raw = {}
    for key, _key_node, value_node in _mapping_items(node):
        if key not in _TABLE_KEYS:
            raise _Unsupported("unknown top-level key %r" % key)
        raw[key] = value_node
    missing = _TABLE_KEYS - raw.keys()
    if missing:
        raise _Unsupported("policy table is missing %s" % sorted(missing))
    dictionary = _parse_dictionary(raw["dictionary"])
    clauses_node = raw["clauses"]
    if not isinstance(clauses_node, SequenceNode):
        raise _Unsupported("clauses must be a sequence")
    return dictionary, clauses_node.value


def _best_effort_id(node, index):
    """Extract the clause id for reporting, even if the clause is broken."""
    fallback = "clause-%d" % (index + 1)
    if not isinstance(node, MappingNode):
        return fallback
    for key_node, value_node in node.value:
        if (
            isinstance(key_node, ScalarNode)
            and key_node.tag == _STR_TAG
            and key_node.value == "id"
            and isinstance(value_node, ScalarNode)
            and value_node.tag == _STR_TAG
        ):
            return value_node.value
    return fallback


def _review_hint(valid):
    """Closest valid pair differing on exactly one exception subject."""
    best = None
    for first, second in itertools.combinations(valid, 2):
        if first.effect != second.effect:
            continue
        if first.operations != second.operations:
            continue
        if first.attributes != second.attributes:
            continue
        diff = first.subjects ^ second.subjects
        if len(diff) != 1:
            continue
        distance = len(first.denotation ^ second.denotation)
        if best is None or distance < best[0]:
            best = (distance, first, second, diff)
    if best is None:
        return None
    distance, first, second, diff = best
    subject = next(iter(diff))
    holder = first if subject in first.subjects else second
    return {
        "kind": "single-exception-subject-difference",
        "subject": subject,
        "only_in": holder.id,
        "clauses": [
            {"id": first.id, "lines": first.span},
            {"id": second.id, "lines": second.span},
        ],
        "affected_lines": sorted(
            {first.span["start"]["line"], second.span["start"]["line"]}
        ),
        "affected_points": distance,
    }


def analyze_policy_table(source, name="table"):
    """Analyze one finite policy table; returns a JSON-friendly report."""
    report = {
        "name": name,
        "status": "ok",
        "clauses": [],
        "covered": [],
        "review_hint": None,
    }
    try:
        node = yaml.compose(source, Loader=yaml.SafeLoader)
    except yaml.YAMLError as exc:
        report["status"] = "undetermined"
        report["reason"] = "unparseable YAML: %s" % exc
        return report
    if node is None:
        report["status"] = "undetermined"
        report["reason"] = "empty document"
        return report
    try:
        dictionary, clause_nodes = _parse_table(node)
    except _Unsupported as exc:
        report["status"] = "undetermined"
        report["reason"] = str(exc)
        report["lines"] = _span(node)
        return report
    report["dictionary"] = {
        "operations": list(dictionary["operations"]),
        "subjects": list(dictionary["subjects"]),
        "attributes": {
            key: list(values) for key, values in dictionary["attributes"].items()
        },
    }

    valid = []
    valid_entries = []
    for index, clause_node in enumerate(clause_nodes):
        entry = {"index": index, "lines": _span(clause_node)}
        report["clauses"].append(entry)
        try:
            clause = _parse_clause(index, clause_node, dictionary)
        except _Unsupported as exc:
            entry["id"] = _best_effort_id(clause_node, index)
            entry["verdict"] = "undetermined"
            entry["reason"] = str(exc)
            continue
        clause.denotation = _denotation(clause, dictionary)
        valid.append(clause)
        valid_entries.append((clause, entry))

    for clause, entry in valid_entries:
        others = [
            other
            for other in valid
            if other is not clause and other.effect == clause.effect
        ]
        union = set()
        for other in others:
            union |= other.denotation
        entry["id"] = clause.id
        entry["effect"] = clause.effect
        if clause.denotation <= union:
            entry["verdict"] = "covered"
            entry["covered_by"] = sorted(
                other.id for other in others if other.denotation & clause.denotation
            )
            if not clause.denotation:
                entry["note"] = "clause denotes an empty set"
            report["covered"].append(clause.id)
        else:
            entry["verdict"] = "not_covered"
            entry["unique_points"] = len(clause.denotation - union)

    report["review_hint"] = _review_hint(valid)
    return report


def analyze_policy_tables(table_a, table_b, names=("table_a", "table_b")):
    """Analyze the two business-provided policy tables; read-only."""
    return {
        "tables": [
            analyze_policy_table(table_a, name=names[0]),
            analyze_policy_table(table_b, name=names[1]),
        ]
    }


def main(argv):
    if len(argv) != 3:
        sys.stderr.write("usage: python policy_coverage.py TABLE_A.yaml TABLE_B.yaml\n")
        return 2
    with open(argv[1], "r", encoding="utf-8") as stream:
        table_a = stream.read()
    with open(argv[2], "r", encoding="utf-8") as stream:
        table_b = stream.read()
    report = analyze_policy_tables(table_a, table_b, names=(argv[1], argv[2]))
    json.dump(report, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
