"""Receiver-safe local summaries over STIX 2 object graphs.

This module is intended for the case where several case teams share one
STIX 2 bundle (or the same local aggregation endpoint) while each team is
only allowed to see its own private branch plus the common public subgraph.

The important property is not merely "hide objects the subject may not
read".  A naive redaction still leaks information through:

* summary/inventory counts which include hidden objects;
* pagination totals and page counts derived from the whole store;
* references left on visible objects which point at hidden objects; and
* malformed or dangling references being rendered differently from
  references to hidden objects.

``LocalBundleSummary`` therefore builds a complete *view* first and derives
the summary, pagination and reference listing only from that view.  Hidden
objects never contribute to any receiver-visible value.  A reference is
kept only when its target is itself visible; all other reference values
(hidden targets, unknown IDs and malformed values) are omitted in exactly
the same way.  Relationship/Sighting objects act as edges, so an edge whose
endpoint is not visible is omitted entirely instead of being displayed with
a dangling reference.

Policy changes have two audiences:

* ``PolicySwitch.receiver_notice()`` describes only objects which were
  visible before the switch, are visible after it, or both.  It never names
  an object which was hidden both before and after.
* ``PolicySwitch.audit()`` compares the rules by ``rule_id`` and reports
  added, removed and modified rules with their old and new values.

The implementation deliberately does not depend on the STIX parsing layer;
it accepts plain dictionaries, STIX ``_STIXBase`` objects and bundles.  It
is therefore usable offline and does not require custom object/property
registration.

Example::

    policy = DistributionPolicy(
        "2026.11-a",
        [
            SubjectGrant("group-a-public", ["group-a"], ["public"]),
            SubjectGrant("group-b-public", ["group-b"], ["public"]),
            SubjectGrant("group-a-case", ["group-a"], ["case-a"]),
            SubjectGrant("group-b-case", ["group-b"], ["case-b"]),
            ObjectAssignment("public-objects", "public", public_ids),
            ObjectAssignment("case-a-objects", "case-a", case_a_ids),
            ObjectAssignment("case-b-objects", "case-b", case_b_ids),
        ],
    )
    summary = LocalBundleSummary(bundle, policy)
    outsider_view = summary.view("outsider")
    outsider_view.summary()
    outsider_view.page(1, page_size=20)
    outsider_view.references()

"""

import copy
import datetime as dt
import hashlib
import json
import math
import uuid
from collections import Counter, defaultdict
from collections.abc import Mapping

# Objects assigned to this case are visible to every subject, including an
# anonymous/unauthorized one.  ``PublicCase`` is provided as a spelling
# friendly alias for callers which prefer class-like constants.
PUBLIC_CASE = "public"
PublicCase = PUBLIC_CASE

# Endpoint properties which make an object an edge in the graph.  A visible
# edge with even one hidden or unresolved endpoint must not be shown: its
# mere existence would reveal that the other case has content.
_EDGE_REFS = {
    "relationship": (
        ("source_ref", "target_ref"),
        (),
    ),
    "sighting": (
        ("sighting_of_ref",),
        ("observed_data_refs", "where_sighted_refs"),
    ),
}


def _require_nonempty_string(value, name):
    if not isinstance(value, str) or not value:
        raise ValueError("{} must be a non-empty string".format(name))
    return value


def _freeze_strings(value, name):
    """Normalize a string or iterable of strings to a non-empty frozenset."""
    if isinstance(value, str):
        value = [value]

    try:
        items = list(value)
    except TypeError:
        raise TypeError("{} must be a string or an iterable of strings".format(name))

    result = set()
    for item in items:
        if not isinstance(item, str) or not item:
            raise ValueError("{} must contain only non-empty strings".format(name))
        result.add(item)

    if not result:
        raise ValueError("{} must not be empty".format(name))

    return frozenset(result)


def _canonical_json(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    )


class SubjectGrant(object):
    """A named rule granting one or more cases to one or more subjects.

    ``"*"`` as a subject means every subject.  ``PUBLIC_CASE`` can be
    granted explicitly, but objects assigned to ``PUBLIC_CASE`` are visible
    to everyone regardless of subject grants.
    """

    __slots__ = ("rule_id", "subjects", "cases")

    def __init__(self, rule_id, subjects, cases):
        self.rule_id = _require_nonempty_string(rule_id, "rule_id")
        self.subjects = _freeze_strings(subjects, "subjects")
        self.cases = _freeze_strings(cases, "cases")

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "kind": "subject_grant",
            "subjects": sorted(self.subjects),
            "cases": sorted(self.cases),
        }

    def __eq__(self, other):
        return isinstance(other, SubjectGrant) and self.to_dict() == other.to_dict()

    def __hash__(self):
        return hash((self.rule_id, self.subjects, self.cases))

    def __repr__(self):
        return "SubjectGrant(rule_id={!r}, subjects={!r}, cases={!r})".format(
            self.rule_id, sorted(self.subjects), sorted(self.cases),
        )


class ObjectAssignment(object):
    """A named rule assigning STIX object IDs to a single case.

    An object may be assigned to several cases by several rules.  An object
    with no assignment is hidden from every subject (fail closed).
    """

    __slots__ = ("rule_id", "case", "object_ids")

    def __init__(self, rule_id, case, object_ids):
        self.rule_id = _require_nonempty_string(rule_id, "rule_id")
        self.case = _require_nonempty_string(case, "case")
        self.object_ids = _freeze_strings(object_ids, "object_ids")

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "kind": "object_assignment",
            "case": self.case,
            "object_ids": sorted(self.object_ids),
        }

    def __eq__(self, other):
        return isinstance(other, ObjectAssignment) and self.to_dict() == other.to_dict()

    def __hash__(self):
        return hash((self.rule_id, self.case, self.object_ids))

    def __repr__(self):
        return "ObjectAssignment(rule_id={!r}, case={!r}, object_ids={!r})".format(
            self.rule_id, self.case, len(self.object_ids),
        )


class DistributionPolicy(object):
    """A versioned, immutable case-distribution policy.

    Args:
        version (str): Opaque version label (for example ``"2026.11-a"``).
        rules (iterable): :class:`SubjectGrant` and/or
            :class:`ObjectAssignment` instances.  Rule IDs must be unique.
        name (str): Optional human-readable policy name.

    Visibility rule::

        PUBLIC_CASE in object_cases(object_id)
            or object_cases(object_id) & subject_cases(subject)

    The object's own ``object_marking_refs`` are not interpreted here.
    Case membership is supplied explicitly so the behaviour is independent
    of whether marking definitions are themselves visible.
    """

    def __init__(self, version, rules=(), name=None):
        self.version = _require_nonempty_string(version, "version")
        if name is not None:
            name = _require_nonempty_string(name, "name")
        self.name = name

        by_id = {}
        for rule in rules:
            if not isinstance(rule, (SubjectGrant, ObjectAssignment)):
                raise TypeError(
                    "rules must contain SubjectGrant or ObjectAssignment instances",
                )
            if rule.rule_id in by_id:
                raise ValueError("duplicate rule_id: {!r}".format(rule.rule_id))
            by_id[rule.rule_id] = rule

        self._rules = by_id

        wildcard_cases = set()
        subject_cases = defaultdict(set)
        object_cases = defaultdict(set)

        for rule in by_id.values():
            if isinstance(rule, SubjectGrant):
                for subject in rule.subjects:
                    if subject == "*":
                        wildcard_cases.update(rule.cases)
                    else:
                        subject_cases[subject].update(rule.cases)
            else:
                for object_id in rule.object_ids:
                    object_cases[object_id].add(rule.case)

        self._wildcard_cases = frozenset(wildcard_cases)
        self._subject_cases = {
            subject: frozenset(cases) for subject, cases in subject_cases.items()
        }
        self._object_cases = {
            object_id: frozenset(cases) for object_id, cases in object_cases.items()
        }

    @property
    def rules(self):
        """Return the rules sorted by ``rule_id``."""
        return tuple(self._rules[key] for key in sorted(self._rules))

    @property
    def rules_by_id(self):
        """Return a copy of the ``rule_id -> rule`` mapping."""
        return dict(self._rules)

    def subject_cases(self, subject):
        """Return the set of cases explicitly granted to ``subject``."""
        cases = set(self._wildcard_cases)
        if subject is not None:
            cases.update(self._subject_cases.get(subject, ()))
        return frozenset(cases)

    def object_cases(self, object_id):
        """Return the set of cases assigned to ``object_id``."""
        return self._object_cases.get(object_id, frozenset())

    def is_visible(self, subject, object_id):
        """Whether ``subject`` may see ``object_id`` under this policy."""
        assigned = self.object_cases(object_id)
        if PUBLIC_CASE in assigned:
            return True
        return bool(assigned & self.subject_cases(subject))

    def to_dict(self):
        """Return a JSON-compatible, deterministic representation."""
        result = {
            "version": self.version,
            "rules": [rule.to_dict() for rule in self.rules],
        }
        if self.name is not None:
            result["name"] = self.name
        return result

    @classmethod
    def from_dict(cls, value):
        """Build a policy from :meth:`to_dict` output."""
        if not isinstance(value, Mapping):
            raise TypeError("policy must be a mapping")

        rules = []
        for rule in value.get("rules", ()):
            kind = rule.get("kind")
            if kind == "subject_grant":
                rules.append(
                    SubjectGrant(
                        rule["rule_id"], rule.get("subjects", ()),
                        rule.get("cases", ()),
                    ),
                )
            elif kind == "object_assignment":
                rules.append(
                    ObjectAssignment(
                        rule["rule_id"], rule["case"],
                        rule.get("object_ids", ()),
                    ),
                )
            else:
                raise ValueError("unknown rule kind: {!r}".format(kind))

        return cls(
            value["version"], rules=rules, name=value.get("name"),
        )

    def __eq__(self, other):
        return isinstance(other, DistributionPolicy) and self.to_dict() == other.to_dict()

    def __repr__(self):
        return "DistributionPolicy(version={!r}, rules={}, name={!r})".format(
            self.version, len(self._rules), self.name,
        )


def _plain(value):
    """Recursively convert STIX mappings to plain, detached dictionaries."""
    if isinstance(value, dt.datetime):
        from stix2.utils import format_datetime
        return format_datetime(value)
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return copy.deepcopy(value)


def _extract_objects(data):
    if data is None:
        return []
    if isinstance(data, Mapping):
        if data.get("type") == "bundle":
            return list(data.get("objects", ()))
        return [data]
    if isinstance(data, (list, tuple)):
        result = []
        for item in data:
            result.extend(_extract_objects(item))
        return result
    raise TypeError(
        "objects must be a STIX object, bundle, or list/tuple of objects",
    )


def _version_key(obj):
    # Hidden content must not influence which version of a *visible* object
    # is selected.  Modified/created timestamps are public metadata; if two
    # objects are tied, the first one supplied wins.
    return (
        str(obj.get("modified") or ""),
        str(obj.get("created") or ""),
    )


def _normalize_objects(data):
    """Return one plain dictionary per object ID, ordered by (type, id)."""
    by_id = {}
    for raw in _extract_objects(data):
        if not isinstance(raw, Mapping):
            raise TypeError("each STIX object must be a mapping")

        obj = _plain(raw)
        object_id = obj.get("id")
        if not isinstance(object_id, str) or not object_id:
            raise ValueError("each STIX object must have a non-empty string id")
        if obj.get("type") == "bundle":
            continue

        previous = by_id.get(object_id)
        if previous is None or _version_key(obj) > _version_key(previous):
            by_id[object_id] = obj

    return [
        by_id[object_id]
        for object_id in sorted(
            by_id,
            key=lambda oid: (str(by_id[oid].get("type") or ""), oid),
        )
    ]


def _edge_is_unresolved(obj, visible_ids):
    """Whether an edge object has a missing/hidden/malformed endpoint."""
    spec = _EDGE_REFS.get(obj.get("type"))
    if spec is None:
        return False

    required, optional = spec
    for prop in required:
        if prop not in obj:
            return True

    for prop in required + optional:
        if prop not in obj:
            continue

        value = obj[prop]
        if isinstance(value, str):
            refs = [value]
        elif isinstance(value, (list, tuple)):
            refs = value
        else:
            return True

        for ref in refs:
            if not isinstance(ref, str) or ref not in visible_ids:
                return True

    return False


def _prune_refs(value, visible_ids):
    """Recursively omit reference values whose targets are not visible.

    Returns ``(new_value, removed)``.  ``removed`` tells a parent container
    that this value referenced something hidden.  Nested list entries which
    referenced hidden content are dropped entirely so a partially redacted
    entry cannot become a fingerprint.
    """
    if isinstance(value, Mapping):
        result = {}
        removed = False

        for key, item in value.items():
            if key.endswith("_ref") and not key.endswith("_refs"):
                if isinstance(item, str) and item in visible_ids:
                    result[key] = item
                else:
                    removed = True
                continue

            if key.endswith("_refs"):
                if isinstance(item, (list, tuple)):
                    kept = [
                        ref for ref in item
                        if isinstance(ref, str) and ref in visible_ids
                    ]
                    if kept:
                        result[key] = kept
                    if len(kept) != len(item):
                        removed = True
                else:
                    removed = True
                continue

            new_item, child_removed = _prune_refs(item, visible_ids)
            if child_removed:
                # A nested mapping which referenced hidden content is
                # dropped as a whole.  Keeping a partially redacted entry
                # (e.g. a granular marking without its marking_ref) would
                # itself become a fingerprint of the hidden branch.
                removed = True
                continue

            result[key] = new_item
            removed = removed or child_removed

        return result, removed

    if isinstance(value, (list, tuple)):
        result = []
        removed = False

        for item in value:
            new_item, child_removed = _prune_refs(item, visible_ids)
            if child_removed:
                removed = True
                if isinstance(item, (Mapping, list, tuple)):
                    continue
            result.append(new_item)

        return result, removed

    return copy.deepcopy(value), False


def _iter_refs(value, path=""):
    if isinstance(value, Mapping):
        for key, item in value.items():
            child_path = "{}.{}".format(path, key) if path else key
            if key.endswith("_ref") and not key.endswith("_refs"):
                if isinstance(item, str):
                    yield child_path, item
            elif key.endswith("_refs") and isinstance(item, (list, tuple)):
                for index, ref in enumerate(item):
                    if isinstance(ref, str):
                        yield "{}[{}]".format(child_path, index), ref
            else:
                for found in _iter_refs(item, child_path):
                    yield found

    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            child_path = "{}[{}]".format(path, index)
            for found in _iter_refs(item, child_path):
                yield found


class Page(object):
    """One deterministic page of a receiver-safe bundle view."""

    __slots__ = (
        "items", "number", "page_size", "total", "page_count",
        "has_next", "has_previous",
    )

    def __init__(self, items, number, page_size, total, page_count):
        self.items = items
        self.number = number
        self.page_size = page_size
        self.total = total
        self.page_count = page_count
        self.has_next = number < page_count
        self.has_previous = number > 1 and page_count > 0

    def to_dict(self):
        return {
            "items": copy.deepcopy(self.items),
            "page": self.number,
            "page_size": self.page_size,
            "total": self.total,
            "page_count": self.page_count,
            "has_next": self.has_next,
            "has_previous": self.has_previous,
        }

    def __eq__(self, other):
        return isinstance(other, Page) and self.to_dict() == other.to_dict()

    def __repr__(self):
        return (
            "Page(number={!r}, page_size={!r}, total={!r}, "
            "page_count={!r}, items={})"
        ).format(
            self.number, self.page_size, self.total, self.page_count,
            len(self.items),
        )


class BundleView(object):
    """A receiver-safe view of a local bundle for one subject.

    The view is immutable from the caller's perspective.  ``objects``,
    ``summary``, ``page``, ``references`` and ``to_bundle`` are all derived
    solely from objects visible to ``subject``.
    """

    def __init__(self, objects, policy, subject=None):
        self.policy = policy
        self.subject = subject

        granted = set(policy.subject_cases(subject))
        granted.add(PUBLIC_CASE)

        visible = {}
        for obj in objects:
            if policy.object_cases(obj["id"]) & granted:
                visible[obj["id"]] = obj

        # Edges whose endpoint is not visible are not displayable.  Repeat
        # until stable so an edge pointing at another dropped edge is also
        # removed instead of being rendered with a missing endpoint.
        while True:
            effective_ids = frozenset(visible)
            dropped = [
                object_id for object_id, obj in visible.items()
                if _edge_is_unresolved(obj, effective_ids)
            ]
            if not dropped:
                break
            for object_id in dropped:
                del visible[object_id]

        effective_ids = frozenset(visible)
        pruned = {}
        for object_id, obj in visible.items():
            pruned[object_id], _ = _prune_refs(obj, effective_ids)

        self._items_by_id = pruned
        self._ids = frozenset(pruned)
        self._ordered = [
            pruned[object_id]
            for object_id in sorted(
                pruned,
                key=lambda oid: (str(pruned[oid].get("type") or ""), oid),
            )
        ]

    @property
    def ids(self):
        """The IDs visible in this view, as a frozenset."""
        return self._ids

    @property
    def objects(self):
        """The visible, reference-pruned objects as detached dictionaries."""
        return copy.deepcopy(self._ordered)

    def object(self, object_id):
        """Return one visible object, or ``None`` if it is not visible."""
        obj = self._items_by_id.get(object_id)
        return copy.deepcopy(obj) if obj is not None else None

    def __len__(self):
        return len(self._ordered)

    def __iter__(self):
        return iter(self.objects)

    def summary(self):
        """Return the receiver-safe inventory summary.

        Only visible objects are counted.  No hidden total, hidden type
        count, case count or unresolved-reference count is included.
        """
        by_type = Counter(str(obj.get("type") or "") for obj in self._ordered)
        return {
            "total": len(self._ordered),
            "by_type": {key: by_type[key] for key in sorted(by_type)},
        }

    def page(self, number=1, page_size=10):
        """Return a deterministic page over the visible objects.

        The total and page count are computed from the visible view only.
        Requesting a page past the end returns an empty ``items`` list with
        the same honest totals.
        """
        if not isinstance(number, int) or isinstance(number, bool) or number < 1:
            raise ValueError("page number must be a positive integer")
        if page_size is None:
            page_size = max(len(self._ordered), 1)
        if (
            not isinstance(page_size, int) or isinstance(page_size, bool)
            or page_size < 1
        ):
            raise ValueError("page_size must be a positive integer or None")

        total = len(self._ordered)
        if page_size >= total:
            page_count = 1 if total else 0
        else:
            page_count = int(math.ceil(total / page_size))

        start = (number - 1) * page_size
        items = self._ordered[start:start + page_size]

        return Page(copy.deepcopy(items), number, page_size, total, page_count)

    def pages(self, page_size=10):
        """Yield every page in order."""
        if page_size is None:
            page_size = max(len(self._ordered), 1)
        if (
            not isinstance(page_size, int) or isinstance(page_size, bool)
            or page_size < 1
        ):
            raise ValueError("page_size must be a positive integer or None")

        total = len(self._ordered)
        page_count = int(math.ceil(total / page_size)) if total else 0
        for number in range(1, page_count + 1):
            yield self.page(number, page_size)

    def references(self):
        """Return visible source -> visible target references.

        References to hidden objects, missing objects and malformed values
        have already been removed by the same pruning path, so they cannot
        be distinguished from each other or from an absent reference.
        """
        result = []
        for object_id in sorted(self._items_by_id):
            obj = self._items_by_id[object_id]
            for path, target_id in _iter_refs(obj):
                result.append(
                    {
                        "source_id": object_id,
                        "property": path,
                        "target_id": target_id,
                    },
                )

        result.sort(key=lambda ref: (
            ref["source_id"], ref["property"], ref["target_id"],
        ))
        return result

    def to_bundle(self, bundle_id=None):
        """Return a deterministic STIX 2 bundle of this view.

        If no bundle ID is given, it is derived from the visible content, so
        swapping a hidden private branch cannot change an unauthorized
        recipient's bundle ID.
        """
        serialized = _canonical_json(self._ordered)
        if bundle_id is None:
            digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
            bundle_id = "bundle--{}".format(
                uuid.uuid5(uuid.NAMESPACE_URL, "stix2-local-view:" + digest),
            )

        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": copy.deepcopy(self._ordered),
        }


class PolicyAudit(object):
    """Internal, rule-level audit of a policy switch.

    This output is intentionally richer than the receiver notice and is
    meant for internal audit only.  Rules are matched by ``rule_id``.
    """

    __slots__ = (
        "old_policy", "new_policy", "added", "removed", "modified",
        "changed_rule_ids", "changed_subjects", "changed_cases",
    )

    def __init__(self, old_policy, new_policy):
        self.old_policy = old_policy
        self.new_policy = new_policy

        old_rules = old_policy.rules_by_id
        new_rules = new_policy.rules_by_id
        old_ids = set(old_rules)
        new_ids = set(new_rules)

        self.added = [new_rules[rule_id] for rule_id in sorted(new_ids - old_ids)]
        self.removed = [old_rules[rule_id] for rule_id in sorted(old_ids - new_ids)]

        self.modified = []
        for rule_id in sorted(old_ids & new_ids):
            old_rule = old_rules[rule_id]
            new_rule = new_rules[rule_id]
            if old_rule.to_dict() != new_rule.to_dict():
                self.modified.append((old_rule, new_rule))

        self.changed_rule_ids = tuple(
            sorted(
                [rule.rule_id for rule in self.added]
                + [rule.rule_id for rule in self.removed]
                + [old.rule_id for old, _ in self.modified],
            ),
        )

        subjects = set()
        cases = set()
        for rule in self.added + self.removed:
            if isinstance(rule, SubjectGrant):
                subjects.update(rule.subjects)
                cases.update(rule.cases)
            else:
                cases.add(rule.case)
        for old_rule, new_rule in self.modified:
            for rule in (old_rule, new_rule):
                if isinstance(rule, SubjectGrant):
                    subjects.update(rule.subjects)
                    cases.update(rule.cases)
                else:
                    cases.add(rule.case)

        self.changed_subjects = tuple(sorted(subjects))
        self.changed_cases = tuple(sorted(cases))

    @property
    def version_changed(self):
        return self.old_policy.version != self.new_policy.version

    @property
    def is_empty(self):
        return not (
            self.added or self.removed or self.modified or self.version_changed
        )

    def to_dict(self):
        return {
            "old_version": self.old_policy.version,
            "new_version": self.new_policy.version,
            "version_changed": self.version_changed,
            "added": [rule.to_dict() for rule in self.added],
            "removed": [rule.to_dict() for rule in self.removed],
            "modified": [
                {
                    "rule_id": old_rule.rule_id,
                    "before": old_rule.to_dict(),
                    "after": new_rule.to_dict(),
                }
                for old_rule, new_rule in self.modified
            ],
            "changed_rule_ids": list(self.changed_rule_ids),
            "changed_subjects": list(self.changed_subjects),
            "changed_cases": list(self.changed_cases),
        }

    def __repr__(self):
        return (
            "PolicyAudit(old_version={!r}, new_version={!r}, "
            "added={}, removed={}, modified={})"
        ).format(
            self.old_policy.version, self.new_policy.version,
            len(self.added), len(self.removed), len(self.modified),
        )


def audit_policy_change(old_policy, new_policy):
    """Return the internal rule-level :class:`PolicyAudit` for a switch."""
    if not isinstance(old_policy, DistributionPolicy):
        raise TypeError("old_policy must be a DistributionPolicy")
    if not isinstance(new_policy, DistributionPolicy):
        raise TypeError("new_policy must be a DistributionPolicy")
    return PolicyAudit(old_policy, new_policy)


def _object_descriptor(obj):
    descriptor = {
        "type": obj.get("type"),
        "id": obj.get("id"),
    }
    for key in ("name", "title", "display_name"):
        value = obj.get(key)
        if isinstance(value, str) and value:
            descriptor["label"] = value
            break
    return descriptor


class PolicyChangeNotice(object):
    """Receiver-facing explanation of a policy switch for one subject.

    Only objects visible on at least one side of the switch are named.  An
    object hidden both before and after never appears, even if a rule which
    governs it changed.  Policy versions, rule IDs and rule values are
    deliberately omitted: those belong to :class:`PolicyAudit` and could
    themselves describe another case.
    """

    __slots__ = ("before", "after")

    def __init__(self, before, after):
        self.before = before
        self.after = after

    @property
    def added_ids(self):
        return tuple(sorted(self.after.ids - self.before.ids))

    @property
    def removed_ids(self):
        return tuple(sorted(self.before.ids - self.after.ids))

    @property
    def changed(self):
        return bool(self.added_ids or self.removed_ids)

    def to_dict(self):
        added = []
        for object_id in self.added_ids:
            obj = self.after.object(object_id)
            if obj is not None:
                added.append(_object_descriptor(obj))

        removed = []
        for object_id in self.removed_ids:
            obj = self.before.object(object_id)
            if obj is not None:
                removed.append(_object_descriptor(obj))

        added.sort(key=lambda item: (str(item["type"]), item["id"]))
        removed.sort(key=lambda item: (str(item["type"]), item["id"]))

        if added or removed:
            message = "{} object(s) added, {} object(s) removed.".format(
                len(added), len(removed),
            )
        else:
            message = "No visible objects changed."

        return {
            "subject": self.after.subject,
            "changed": self.changed,
            "added": added,
            "removed": removed,
            "summary_before": self.before.summary(),
            "summary_after": self.after.summary(),
            "message": message,
        }

    def __repr__(self):
        return "PolicyChangeNotice(subject={!r}, added={}, removed={})".format(
            self.after.subject, len(self.added_ids), len(self.removed_ids),
        )


class PolicySwitch(object):
    """A policy transition for one local summary and one subject."""

    __slots__ = (
        "objects", "old_policy", "new_policy", "subject",
        "_before", "_after", "_audit",
    )

    def __init__(self, objects, old_policy, new_policy, subject=None):
        if not isinstance(old_policy, DistributionPolicy):
            raise TypeError("old_policy must be a DistributionPolicy")
        if not isinstance(new_policy, DistributionPolicy):
            raise TypeError("new_policy must be a DistributionPolicy")
        if subject is not None and not isinstance(subject, str):
            raise TypeError("subject must be a string or None")

        self.objects = objects
        self.old_policy = old_policy
        self.new_policy = new_policy
        self.subject = subject
        self._before = None
        self._after = None
        self._audit = None

    @property
    def before(self):
        if self._before is None:
            self._before = BundleView(
                self.objects, self.old_policy, self.subject,
            )
        return self._before

    @property
    def after(self):
        if self._after is None:
            self._after = BundleView(
                self.objects, self.new_policy, self.subject,
            )
        return self._after

    def receiver_notice(self):
        """Return the receiver-facing :class:`PolicyChangeNotice`."""
        return PolicyChangeNotice(self.before, self.after)

    def notice(self):
        """Alias for :meth:`receiver_notice`."""
        return self.receiver_notice()

    def audit(self):
        """Return the internal rule-level :class:`PolicyAudit`."""
        if self._audit is None:
            self._audit = PolicyAudit(self.old_policy, self.new_policy)
        return self._audit


class LocalBundleSummary(object):
    """A local STIX 2 summary with case-scoped, receiver-safe views."""

    __slots__ = ("_objects", "policy", "_views")

    def __init__(self, objects, policy):
        if not isinstance(policy, DistributionPolicy):
            raise TypeError("policy must be a DistributionPolicy")

        self._objects = _normalize_objects(objects)
        self.policy = policy
        self._views = {}

    @property
    def object_count(self):
        """Total objects held locally (internal value; not receiver-safe)."""
        return len(self._objects)

    def view(self, subject=None):
        """Return a cached :class:`BundleView` for ``subject``."""
        if subject is not None and not isinstance(subject, str):
            raise TypeError("subject must be a string or None")
        if subject not in self._views:
            self._views[subject] = BundleView(
                self._objects, self.policy, subject,
            )
        return self._views[subject]

    def summary(self, subject=None):
        """Receiver-safe summary for ``subject``."""
        return self.view(subject).summary()

    def external_summary(self, subject=None):
        """Alias for :meth:`summary` emphasizing that it is receiver-safe."""
        return self.summary(subject)

    def page(self, subject=None, number=1, page_size=10):
        """Receiver-safe page for ``subject``."""
        return self.view(subject).page(number, page_size)

    def pages(self, subject=None, page_size=10):
        """Iterate receiver-safe pages for ``subject``."""
        return self.view(subject).pages(page_size)

    def references(self, subject=None):
        """Receiver-safe visible reference listing for ``subject``."""
        return self.view(subject).references()

    def export(self, subject=None, bundle_id=None):
        """Export the receiver-safe view as a deterministic bundle."""
        return self.view(subject).to_bundle(bundle_id)

    def switch(self, new_policy, subject=None):
        """Build a :class:`PolicySwitch` against ``new_policy``."""
        return PolicySwitch(
            self._objects, self.policy, new_policy, subject,
        )

    def audit_switch(self, new_policy):
        """Internal rule-level audit for a switch to ``new_policy``."""
        return audit_policy_change(self.policy, new_policy)

    def audit_summary(self):
        """Internal inventory summary; never hand this to a recipient."""
        by_type = Counter(str(obj.get("type") or "") for obj in self._objects)
        by_case = Counter()
        unassigned = 0

        for obj in self._objects:
            cases = self.policy.object_cases(obj["id"])
            if not cases:
                unassigned += 1
            for case in cases:
                by_case[case] += 1

        return {
            "policy_version": self.policy.version,
            "objects_total": len(self._objects),
            "objects_by_type": {
                key: by_type[key] for key in sorted(by_type)
            },
            "objects_by_case": {
                key: by_case[key] for key in sorted(by_case)
            },
            "unassigned_objects": unassigned,
            "rules": [rule.to_dict() for rule in self.policy.rules],
        }


def local_summary(objects, policy):
    """Convenience factory for :class:`LocalBundleSummary`."""
    return LocalBundleSummary(objects, policy)
