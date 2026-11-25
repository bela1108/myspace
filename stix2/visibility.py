"""Receiver-safe local summaries over STIX 2 object graphs.

Several case teams may share one local STIX 2 aggregation endpoint while
each team is only allowed to see its own private branch plus the common
public subgraph.  Hiding object bytes is not enough: a receiver can infer
the existence of another case from counts, page totals, dangling
references, or a policy-change message.

This module builds a complete receiver view first and derives every
receiver-visible value from that view:

* summaries count only visible objects;
* pagination totals and page counts cover only visible objects;
* references are retained only when their target is visible, so hidden,
  missing, and malformed references look the same;
* relationship and sighting objects are dropped when any endpoint is not
  visible, including endpoints which are themselves dropped edges;
* exported bundle IDs are derived from visible content.

Policy changes have two audiences.  :meth:`PolicySwitch.receiver_notice`
describes only objects visible before the switch, after the switch, or
both.  :meth:`PolicySwitch.audit` compares rules by ``rule_id`` and keeps
the full rule-level detail for internal audit.

The implementation accepts plain dictionaries, STIX ``_STIXBase`` objects,
and bundles.  It does not require custom STIX registrations and works
offline.
"""

import copy
import datetime as dt
import hashlib
import json
import math
import uuid
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping

PUBLIC_CASE = "public"
PublicCase = PUBLIC_CASE

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
        raise ValueError(f"{name} must be a non-empty string")
    return value


def _freeze_strings(value, name):
    if isinstance(value, str):
        value = [value]

    try:
        items = list(value)
    except TypeError:
        raise TypeError(f"{name} must be a string or an iterable of strings")

    result = set()
    for item in items:
        if not isinstance(item, str) or not item:
            raise ValueError(f"{name} must contain only non-empty strings")
        result.add(item)

    if not result:
        raise ValueError(f"{name} must not be empty")

    return frozenset(result)


def _object_id(value):
    if isinstance(value, str) and value:
        return value
    if isinstance(value, Mapping):
        item_id = value.get("id")
        if isinstance(item_id, str) and item_id:
            return item_id
    item_id = getattr(value, "id", None)
    if isinstance(item_id, str) and item_id:
        return item_id
    raise ValueError("object IDs must be non-empty strings or STIX objects")


def _freeze_object_ids(value):
    if isinstance(value, (str, Mapping)) or hasattr(value, "id"):
        value = [value]

    try:
        items = list(value)
    except TypeError:
        raise TypeError("object_ids must be an object or an iterable of objects")

    result = set()
    for item in items:
        result.add(_object_id(item))

    if not result:
        raise ValueError("object_ids must not be empty")

    return frozenset(result)


def _subject_key(subject):
    if subject is None or isinstance(subject, str):
        return subject
    if isinstance(subject, Mapping):
        subject_id = subject.get("id")
        if isinstance(subject_id, str) and subject_id:
            return subject_id
    subject_id = getattr(subject, "id", None)
    if isinstance(subject_id, str) and subject_id:
        return subject_id
    raise TypeError("subject must be a string, STIX object, or None")


def _canonical_json(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


class SubjectGrant:
    """A named rule granting one or more cases to one or more subjects.

    ``"*"`` as a subject means every subject.  ``PUBLIC_CASE`` may be
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
        return (
            "SubjectGrant(rule_id={!r}, subjects={!r}, cases={!r})"
        ).format(self.rule_id, sorted(self.subjects), sorted(self.cases))


class ObjectAssignment:
    """A named rule assigning STIX object IDs to a single case.

    An object may be assigned to several cases by several rules.  An object
    with no assignment is hidden from every subject (fail closed).
    """

    __slots__ = ("rule_id", "case", "object_ids")

    def __init__(self, rule_id, case, object_ids):
        self.rule_id = _require_nonempty_string(rule_id, "rule_id")
        self.case = _require_nonempty_string(case, "case")
        self.object_ids = _freeze_object_ids(object_ids)

    def to_dict(self):
        return {
            "rule_id": self.rule_id,
            "kind": "object_assignment",
            "case": self.case,
            "object_ids": sorted(self.object_ids),
        }

    def __eq__(self, other):
        return (
            isinstance(other, ObjectAssignment)
            and self.to_dict() == other.to_dict()
        )

    def __hash__(self):
        return hash((self.rule_id, self.case, self.object_ids))

    def __repr__(self):
        return (
            "ObjectAssignment(rule_id={!r}, case={!r}, object_ids={!r})"
        ).format(self.rule_id, self.case, len(self.object_ids))


class DistributionPolicy:
    """A versioned, immutable case-distribution policy.

    Args:
        version: Opaque version label, for example ``"2026.11-a"``.
        rules: :class:`SubjectGrant` and/or :class:`ObjectAssignment`
            instances.  Rule IDs must be unique.
        name: Optional human-readable policy name.

    Visibility rule::

        PUBLIC_CASE in object_cases(object_id)
            or object_cases(object_id) & subject_cases(subject)

    Case membership is supplied explicitly so behaviour is independent of
    whether marking definitions are themselves visible.
    """

    def __init__(self, version, rules=(), name=None):
        self.version = _require_nonempty_string(version, "version")
        if name is not None:
            name = _require_nonempty_string(name, "name")
        self.name = name

        if isinstance(rules, (SubjectGrant, ObjectAssignment)):
            rules = [rules]
        elif isinstance(rules, Mapping):
            rules = rules.values()

        by_id = {}
        for rule in rules:
            if not isinstance(rule, (SubjectGrant, ObjectAssignment)):
                raise TypeError(
                    "rules must contain SubjectGrant or ObjectAssignment "
                    "instances",
                )
            if rule.rule_id in by_id:
                raise ValueError(f"duplicate rule_id: {rule.rule_id!r}")
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
            subject: frozenset(cases)
            for subject, cases in subject_cases.items()
        }
        self._object_cases = {
            object_id: frozenset(cases)
            for object_id, cases in object_cases.items()
        }

    @property
    def rules(self):
        return tuple(self._rules[key] for key in sorted(self._rules))

    @property
    def rules_by_id(self):
        return dict(self._rules)

    def subject_cases(self, subject):
        subject = _subject_key(subject)
        cases = set(self._wildcard_cases)
        if subject is not None:
            cases.update(self._subject_cases.get(subject, ()))
        return frozenset(cases)

    def object_cases(self, object_id):
        return self._object_cases.get(object_id, frozenset())

    def is_visible(self, subject, object_id):
        assigned = self.object_cases(object_id)
        if PUBLIC_CASE in assigned:
            return True
        return bool(assigned & self.subject_cases(subject))

    def to_dict(self):
        result = {
            "version": self.version,
            "rules": [rule.to_dict() for rule in self.rules],
        }
        if self.name is not None:
            result["name"] = self.name
        return result

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, Mapping):
            raise TypeError("policy must be a mapping")

        rules = []
        for rule in value.get("rules", ()):
            if not isinstance(rule, Mapping):
                raise TypeError("each rule must be a mapping")
            kind = rule.get("kind")
            if kind == "subject_grant":
                rules.append(
                    SubjectGrant(
                        rule["rule_id"],
                        rule.get("subjects", ()),
                        rule.get("cases", ()),
                    ),
                )
            elif kind == "object_assignment":
                rules.append(
                    ObjectAssignment(
                        rule["rule_id"],
                        rule["case"],
                        rule.get("object_ids", ()),
                    ),
                )
            else:
                raise ValueError(f"unknown rule kind: {kind!r}")

        return cls(value["version"], rules=rules, name=value.get("name"))

    def diff(self, old_policy):
        return audit_policy_change(old_policy, self)

    def compare(self, other_policy):
        return audit_policy_change(self, other_policy)

    def __eq__(self, other):
        return (
            isinstance(other, DistributionPolicy)
            and self.to_dict() == other.to_dict()
        )

    def __repr__(self):
        return (
            "DistributionPolicy(version={!r}, rules={}, name={!r})"
        ).format(self.version, len(self._rules), self.name)


def _plain(value):
    if isinstance(value, dt.datetime):
        from stix2.utils import format_datetime

        return format_datetime(value)
    if isinstance(value, dt.date):
        return value.isoformat()
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
            return list(data.get("objects") or ())
        return [data]
    if isinstance(data, (str, bytes, bytearray)):
        raise TypeError(
            "objects must be a STIX object, bundle, or iterable of objects",
        )
    if isinstance(data, Iterable):
        result = []
        for item in data:
            result.extend(_extract_objects(item))
        return result
    raise TypeError(
        "objects must be a STIX object, bundle, or iterable of objects",
    )


def _version_key(obj):
    return (
        str(obj.get("modified") or ""),
        str(obj.get("created") or ""),
    )


def _normalize_objects(data):
    by_id = {}
    for raw in _extract_objects(data):
        if not isinstance(raw, Mapping):
            raise TypeError("each STIX object must be a mapping")

        obj = _plain(raw)
        object_id = obj.get("id")
        if not isinstance(object_id, str) or not object_id:
            raise ValueError(
                "each STIX object must have a non-empty string id",
            )
        if obj.get("type") == "bundle":
            continue

        previous = by_id.get(object_id)
        if previous is None:
            by_id[object_id] = obj
            continue

        previous_key = _version_key(previous)
        current_key = _version_key(obj)
        if current_key > previous_key:
            by_id[object_id] = obj
        elif (
            current_key == previous_key
            and _canonical_json(previous) != _canonical_json(obj)
        ):
            raise ValueError(
                f"ambiguous versions for object id {object_id!r}: same "
                "modified/created timestamp but different content",
            )

    return [
        by_id[object_id]
        for object_id in sorted(
            by_id,
            key=lambda item: (str(by_id[item].get("type") or ""), item),
        )
    ]


def _edge_is_unresolved(obj, visible_ids):
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
            references = [value]
        elif isinstance(value, (list, tuple)):
            references = value
        else:
            return True

        for reference in references:
            if not isinstance(reference, str) or reference not in visible_ids:
                return True

    return False


def _prune_refs(value, visible_ids, root=False):
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
                        reference for reference in item
                        if isinstance(reference, str)
                        and reference in visible_ids
                    ]
                    if kept or not item:
                        result[key] = kept
                    if len(kept) != len(item):
                        removed = True
                else:
                    removed = True
                continue

            new_item, child_removed = _prune_refs(
                item, visible_ids, root=False,
            )
            if new_item is None:
                removed = True
                continue

            result[key] = new_item
            removed = removed or child_removed

        if removed and not root:
            return None, True
        return result, removed

    if isinstance(value, (list, tuple)):
        result = []
        removed = False

        for item in value:
            new_item, child_removed = _prune_refs(
                item, visible_ids, root=False,
            )
            if new_item is None:
                removed = True
                continue
            result.append(new_item)
            removed = removed or child_removed

        if removed and not result and value:
            return None, True
        return result, removed

    return copy.deepcopy(value), False


def _iter_refs(value, path=""):
    if isinstance(value, Mapping):
        for key, item in value.items():
            child_path = f"{path}.{key}" if path else key
            if key.endswith("_ref") and not key.endswith("_refs"):
                if isinstance(item, str):
                    yield child_path, item
            elif key.endswith("_refs") and isinstance(item, (list, tuple)):
                for index, reference in enumerate(item):
                    if isinstance(reference, str):
                        yield f"{child_path}[{index}]", reference
            else:
                for found in _iter_refs(item, child_path):
                    yield found

    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            child_path = f"{path}[{index}]"
            for found in _iter_refs(item, child_path):
                yield found


class Page:
    """One deterministic page of a receiver-safe bundle view."""

    __slots__ = (
        "items",
        "number",
        "page_size",
        "total",
        "page_count",
        "has_next",
        "has_previous",
    )

    def __init__(self, items, number, page_size, total, page_count):
        self.items = items
        self.number = number
        self.page_size = page_size
        self.total = total
        self.page_count = page_count
        self.has_next = number < page_count
        self.has_previous = number > 1 and page_count > 0

    @property
    def page(self):
        return self.number

    @property
    def total_pages(self):
        return self.page_count

    @property
    def size(self):
        return self.page_size

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

    def __len__(self):
        return len(self.items)

    def __repr__(self):
        return (
            "Page(number={!r}, page_size={!r}, total={!r}, "
            "page_count={!r}, items={})"
        ).format(
            self.number,
            self.page_size,
            self.total,
            self.page_count,
            len(self.items),
        )


class BundleView:
    """A receiver-safe view of a local bundle for one subject.

    ``objects``, ``summary``, ``page``, ``references`` and ``to_bundle`` are
    all derived solely from objects visible to ``subject``.
    """

    def __init__(self, objects, policy, subject=None):
        if not isinstance(policy, DistributionPolicy):
            raise TypeError("policy must be a DistributionPolicy")

        self.policy = policy
        self.subject = subject
        self.subject_id = _subject_key(subject)

        normalized = _normalize_objects(objects)
        granted = set(policy.subject_cases(self.subject_id))
        granted.add(PUBLIC_CASE)

        visible = {}
        for obj in normalized:
            if policy.object_cases(obj["id"]) & granted:
                visible[obj["id"]] = obj

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
            pruned[object_id], _ = _prune_refs(obj, effective_ids, root=True)

        self._items_by_id = pruned
        self._ids = frozenset(pruned)
        self._ordered = [
            pruned[object_id]
            for object_id in sorted(
                pruned,
                key=lambda item: (str(pruned[item].get("type") or ""), item),
            )
        ]

    @property
    def ids(self):
        return self._ids

    @property
    def objects(self):
        return copy.deepcopy(self._ordered)

    def object(self, object_id):
        obj = self._items_by_id.get(object_id)
        return copy.deepcopy(obj) if obj is not None else None

    def __len__(self):
        return len(self._ordered)

    def __iter__(self):
        return iter(self.objects)

    def summary(self):
        by_type = Counter(
            str(obj.get("type") or "") for obj in self._ordered
        )
        return {
            "total": len(self._ordered),
            "by_type": {key: by_type[key] for key in sorted(by_type)},
        }

    def page(self, number=1, page_size=10):
        if not isinstance(number, int) or isinstance(number, bool) or number < 1:
            raise ValueError("page number must be a positive integer")
        if page_size is None:
            page_size = max(len(self._ordered), 1)
        if (
            not isinstance(page_size, int)
            or isinstance(page_size, bool)
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
        if page_size is None:
            page_size = max(len(self._ordered), 1)
        if (
            not isinstance(page_size, int)
            or isinstance(page_size, bool)
            or page_size < 1
        ):
            raise ValueError("page_size must be a positive integer or None")

        total = len(self._ordered)
        page_count = int(math.ceil(total / page_size)) if total else 0
        for number in range(1, page_count + 1):
            yield self.page(number, page_size)

    def references(self):
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

        result.sort(
            key=lambda ref: (
                ref["source_id"],
                ref["property"],
                ref["target_id"],
            ),
        )
        return result

    def to_bundle(self, bundle_id=None):
        serialized = _canonical_json(self._ordered)
        if bundle_id is None:
            digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
            bundle_id = "bundle--{}".format(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    "stix2-local-view:" + digest,
                ),
            )
        else:
            bundle_id = _require_nonempty_string(bundle_id, "bundle_id")

        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": copy.deepcopy(self._ordered),
        }

    def export(self, bundle_id=None):
        return self.to_bundle(bundle_id)


class PolicyAudit:
    """Internal, rule-level audit of a policy switch.

    Rules are matched by ``rule_id``.  The result is intentionally richer
    than the receiver notice and is meant for internal audit only.
    """

    __slots__ = (
        "old_policy",
        "new_policy",
        "added",
        "removed",
        "modified",
        "changed_rule_ids",
        "changed_subjects",
        "changed_cases",
    )

    def __init__(self, old_policy, new_policy):
        self.old_policy = old_policy
        self.new_policy = new_policy

        old_rules = old_policy.rules_by_id
        new_rules = new_policy.rules_by_id
        old_ids = set(old_rules)
        new_ids = set(new_rules)

        self.added = [
            new_rules[rule_id] for rule_id in sorted(new_ids - old_ids)
        ]
        self.removed = [
            old_rules[rule_id] for rule_id in sorted(old_ids - new_ids)
        ]

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
            self.added
            or self.removed
            or self.modified
            or self.version_changed
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
            self.old_policy.version,
            self.new_policy.version,
            len(self.added),
            len(self.removed),
            len(self.modified),
        )


def audit_policy_change(old_policy, new_policy):
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


class PolicyChangeNotice:
    """Receiver-facing explanation of a policy switch for one subject.

    Only objects visible on at least one side of the switch are named.  An
    object hidden both before and after never appears, even if a rule which
    governs it changed.  Policy versions, rule IDs and rule values are
    deliberately omitted; those belong to :class:`PolicyAudit`.
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
    def updated_ids(self):
        common = self.before.ids & self.after.ids
        return tuple(
            sorted(
                object_id
                for object_id in common
                if self.before.object(object_id)
                != self.after.object(object_id)
            ),
        )

    @property
    def changed(self):
        return bool(self.added_ids or self.removed_ids or self.updated_ids)

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

        updated = []
        for object_id in self.updated_ids:
            obj = self.after.object(object_id)
            if obj is not None:
                updated.append(_object_descriptor(obj))

        added.sort(key=lambda item: (str(item["type"]), item["id"]))
        removed.sort(key=lambda item: (str(item["type"]), item["id"]))
        updated.sort(key=lambda item: (str(item["type"]), item["id"]))

        parts = []
        if added:
            parts.append(f"{len(added)} object(s) added")
        if removed:
            parts.append(f"{len(removed)} object(s) removed")
        if updated:
            parts.append(f"{len(updated)} object(s) updated")
        message = ", ".join(parts) + "." if parts else (
            "No visible objects changed."
        )

        result = {
            "subject": self.after.subject_id,
            "changed": self.changed,
            "added": added,
            "removed": removed,
            "summary_before": self.before.summary(),
            "summary_after": self.after.summary(),
            "message": message,
        }
        if updated:
            result["updated"] = updated
        return result

    def __repr__(self):
        return (
            "PolicyChangeNotice(subject={!r}, added={}, removed={}, "
            "updated={})"
        ).format(
            self.after.subject_id,
            len(self.added_ids),
            len(self.removed_ids),
            len(self.updated_ids),
        )


class PolicySwitch:
    """A policy transition for one local summary and one subject."""

    __slots__ = (
        "objects",
        "old_policy",
        "new_policy",
        "subject",
        "_before",
        "_after",
        "_audit",
    )

    def __init__(self, objects, old_policy, new_policy, subject=None):
        if not isinstance(old_policy, DistributionPolicy):
            raise TypeError("old_policy must be a DistributionPolicy")
        if not isinstance(new_policy, DistributionPolicy):
            raise TypeError("new_policy must be a DistributionPolicy")

        self.objects = _normalize_objects(objects)
        self.old_policy = old_policy
        self.new_policy = new_policy
        self.subject = _subject_key(subject)
        self._before = None
        self._after = None
        self._audit = None

    @property
    def before(self):
        if self._before is None:
            self._before = BundleView(
                self.objects,
                self.old_policy,
                self.subject,
            )
        return self._before

    @property
    def after(self):
        if self._after is None:
            self._after = BundleView(
                self.objects,
                self.new_policy,
                self.subject,
            )
        return self._after

    def receiver_notice(self):
        return PolicyChangeNotice(self.before, self.after)

    def notice(self):
        return self.receiver_notice()

    def audit(self):
        if self._audit is None:
            self._audit = PolicyAudit(
                self.old_policy,
                self.new_policy,
            )
        return self._audit

    def internal_audit(self):
        return self.audit()


class LocalBundleSummary:
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
        return len(self._objects)

    def view(self, subject=None):
        subject_id = _subject_key(subject)
        if subject_id not in self._views:
            self._views[subject_id] = BundleView(
                self._objects,
                self.policy,
                subject_id,
            )
        return self._views[subject_id]

    def summary(self, subject=None):
        return self.view(subject).summary()

    def external_summary(self, subject=None):
        return self.summary(subject)

    def page(self, subject=None, number=1, page_size=10):
        if isinstance(subject, int) and not isinstance(subject, bool):
            subject, number, page_size = None, subject, number
        return self.view(subject).page(number, page_size)

    def pages(self, subject=None, page_size=10):
        if isinstance(subject, int) and not isinstance(subject, bool):
            subject, page_size = None, subject
        return self.view(subject).pages(page_size)

    def references(self, subject=None):
        return self.view(subject).references()

    def export(self, subject=None, bundle_id=None):
        return self.view(subject).to_bundle(bundle_id)

    def switch(self, new_policy, subject=None):
        return PolicySwitch(
            self._objects,
            self.policy,
            new_policy,
            subject,
        )

    def policy_switch(self, new_policy, subject=None):
        return self.switch(new_policy, subject)

    def audit_switch(self, new_policy):
        return audit_policy_change(self.policy, new_policy)

    def internal_audit(self, new_policy):
        return self.audit_switch(new_policy)

    def audit_summary(self):
        by_type = Counter(
            str(obj.get("type") or "") for obj in self._objects
        )
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

    def internal_summary(self):
        return self.audit_summary()


def local_summary(objects, policy):
    """Convenience factory for :class:`LocalBundleSummary`."""
    return LocalBundleSummary(objects, policy)


def external_summary(objects, policy, subject=None):
    """Return the receiver-safe summary for ``subject``."""
    return local_summary(objects, policy).summary(subject)


def visible_references(objects, policy, subject=None):
    """Return the receiver-safe reference listing for ``subject``."""
    return local_summary(objects, policy).references(subject)


def policy_switch(objects, old_policy, new_policy, subject=None):
    """Convenience factory for :class:`PolicySwitch`."""
    return PolicySwitch(objects, old_policy, new_policy, subject)


CaseDistributionPolicy = DistributionPolicy
CaseGrant = SubjectGrant
LocalSummary = LocalBundleSummary
aggregate_bundle = local_summary
build_local_summary = local_summary
