# -*- coding: utf-8 -*-

"""
Offline interpretation of small CPE configuration expressions.

An advisory configuration is a small tree of AND, OR and exclusion nodes
whose leaves refer to CPE Names.  A device is described by an inventory of
components.  Inventory entries have one of three observations:

``seen``
    The component was collected.  Its CPE Name is matched against the leaf.

``absent``
    The inventory explicitly established that the component is not present.

``pending``
    The component has not been collected yet.  This is an unknown observation,
    not an absence.

The evaluator uses three-valued logic.  In particular, an exclusion node is
never satisfied from a pending observation, because doing so would turn a
missing collection into a negative fact.

The public entry point is :func:`explain`::

    from cpe.configuration import explain

    result = explain(config, device)
    result.status                  # affected, undetermined or excluded
    result.evidence["os"]          # evidence for the os clause

``ConfigurationExplainer`` keeps explanations cached and provides
``revise(...)`` for changing one evidence item.  A revision reports the
conclusions that depended on the changed component separately from those
that remain supported.
"""

from __future__ import absolute_import, unicode_literals

from collections import OrderedDict
import copy

from .cpe import CPE
from .cpe2_3_wfn import CPE2_3_WFN
from .cpeset2_3 import CPESet2_3
from .comp.cpecomp import CPEComponent

try:
    string_types = (basestring,)  # noqa: F821 - Python 2
except NameError:
    string_types = (str,)


class Observation(object):
    """Possible states of an inventory item."""

    SEEN = "seen"
    ABSENT = "absent"
    PENDING = "pending"

    #: Convenient aliases used by common inventory schemas.
    PRESENT = SEEN
    OBSERVED = SEEN
    MISSING = ABSENT
    UNKNOWN = PENDING
    NOT_COLLECTED = PENDING

    ALL = (SEEN, ABSENT, PENDING)


class Truth(object):
    """Three-valued truth values used internally and in explanations."""

    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"


class Decision(object):
    """Possible device-level conclusions."""

    AFFECTED = "affected"
    UNDETERMINED = "undetermined"
    EXCLUDED = "excluded"

    #: Aliases for callers using different advisory terminology.
    PENDING = UNDETERMINED
    NOT_AFFECTED = EXCLUDED
    UNAFFECTED = EXCLUDED


class ClauseDecision(object):
    """Possible conclusions for an individual configuration node."""

    SATISFIED = "satisfied"
    NOT_SATISFIED = "not_satisfied"
    UNDETERMINED = "undetermined"


#: Module-level aliases for the three inventory observations.
SEEN = Observation.SEEN
ABSENT = Observation.ABSENT
PENDING = Observation.PENDING

#: Module-level aliases for the three device-level conclusions.
AFFECTED = Decision.AFFECTED
UNDETERMINED = Decision.UNDETERMINED
EXCLUDED = Decision.EXCLUDED

#: Module-level aliases for three-valued truth values.
TRUE = Truth.TRUE
FALSE = Truth.FALSE
UNKNOWN = Truth.UNKNOWN


_OBSERVATION_ALIASES = {
    "seen": Observation.SEEN,
    "present": Observation.SEEN,
    "observed": Observation.SEEN,
    "collected": Observation.SEEN,
    "installed": Observation.SEEN,
    "known": Observation.SEEN,
    "exists": Observation.SEEN,
    "已见": Observation.SEEN,
    "存在": Observation.SEEN,
    "已采集": Observation.SEEN,
    "absent": Observation.ABSENT,
    "missing": Observation.ABSENT,
    "not_present": Observation.ABSENT,
    "not-present": Observation.ABSENT,
    "nonexistent": Observation.ABSENT,
    "not_installed": Observation.ABSENT,
    "not-installed": Observation.ABSENT,
    "不存在": Observation.ABSENT,
    "未安装": Observation.ABSENT,
    "pending": Observation.PENDING,
    "unknown": Observation.PENDING,
    "uncollected": Observation.PENDING,
    "not_collected": Observation.PENDING,
    "not-collected": Observation.PENDING,
    "待补采": Observation.PENDING,
    "未采集": Observation.PENDING,
    "待采集": Observation.PENDING,
}

_CATEGORY_KEYS = OrderedDict((
    ("os", ("os", "system", "operating_system", "platform", "操作系统")),
    ("app", ("app", "application", "software", "plugin", "plugins",
             "component", "应用", "插件")),
    ("hw", ("hw", "hardware", "device", "设备")),
))

_CATEGORY_TO_PART = {
    "os": "o",
    "app": "a",
    "hw": "h",
}

_PART_TO_CATEGORY = {
    "o": "os",
    "a": "app",
    "h": "hw",
    "u": "undef",
}

_LOGICAL_OPERATORS = {
    "and": "AND",
    "all": "AND",
    "allof": "AND",
    "all_of": "AND",
    "every": "AND",
    "or": "OR",
    "any": "OR",
    "anyof": "OR",
    "any_of": "OR",
    "some": "OR",
    "not": "NOT",
    "negate": "NOT",
    "exclude": "EXCLUDE",
    "excluded": "EXCLUDE",
    "exclusion": "EXCLUDE",
}

_META_KEYS = frozenset((
    "id", "device_id", "deviceid", "name", "title", "description",
    "metadata", "meta", "advisory", "advisory_id",
))

_INVENTORY_WRAPPER_KEYS = (
    "components", "inventory", "observations", "assets", "items",
)

_RELATION_NAMES = {
    CPESet2_3.LOGICAL_VALUE_SUPERSET: "superset",
    CPESet2_3.LOGICAL_VALUE_SUBSET: "subset",
    CPESet2_3.LOGICAL_VALUE_EQUAL: "equal",
    CPESet2_3.LOGICAL_VALUE_DISJOINT: "disjoint",
    CPESet2_3.LOGICAL_VALUE_UNDEFINED: "undefined",
}

_MATCHING_RELATIONS = frozenset((
    CPESet2_3.LOGICAL_VALUE_SUPERSET,
    CPESet2_3.LOGICAL_VALUE_EQUAL,
))


def _plain(value):
    """Recursively turn explanation containers into plain Python values."""

    if isinstance(value, dict):
        return OrderedDict((k, _plain(v)) for k, v in value.items())
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value


class _AttrDict(dict):
    """A dict whose keys are also readable as attributes."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)

    def __setattr__(self, name, value):
        self[name] = value

    def to_dict(self):
        return _plain(self)


class EvidenceCollection(list):
    """List of evidence objects with lookup by clause id or component key."""

    def __getitem__(self, item):
        if isinstance(item, string_types):
            for evidence in self:
                if item in (evidence.get("id"),
                            evidence.get("clause_id"),
                            evidence.get("key")):
                    return evidence
            raise KeyError(item)
        return list.__getitem__(self, item)

    def get(self, item, default=None):
        try:
            return self[item]
        except KeyError:
            return default


class ClauseCollection(list):
    """List of clause explanations with lookup by clause id or key."""

    def __getitem__(self, item):
        if isinstance(item, string_types):
            for clause in self:
                if item in (clause.get("id"),
                            clause.get("key")):
                    return clause
            raise KeyError(item)
        return list.__getitem__(self, item)

    def get(self, item, default=None):
        try:
            return self[item]
        except KeyError:
            return default


def _as_unicode(value):
    if isinstance(value, bytes):
        return value.decode("utf-8")
    if isinstance(value, string_types):
        return value
    try:
        return unicode(value)  # noqa: F821 - Python 2
    except NameError:
        return str(value)


def normalize_observation(value):
    """Normalize an observation label to seen, absent or pending."""

    if value is None:
        return Observation.PENDING
    if isinstance(value, bool):
        return Observation.SEEN if value else Observation.ABSENT
    value = _as_unicode(value)
    key = value.strip().lower().replace(" ", "_")
    if key not in _OBSERVATION_ALIASES:
        raise ValueError("Unknown observation state: {0}".format(value))
    return _OBSERVATION_ALIASES[key]


def _truth_not(value):
    if value == Truth.TRUE:
        return Truth.FALSE
    if value == Truth.FALSE:
        return Truth.TRUE
    return Truth.UNKNOWN


def _truth_to_decision(value):
    if value == Truth.TRUE:
        return ClauseDecision.SATISFIED
    if value == Truth.FALSE:
        return ClauseDecision.NOT_SATISFIED
    return ClauseDecision.UNDETERMINED


def _truth_to_status(value):
    if value == Truth.TRUE:
        return Decision.AFFECTED
    if value == Truth.FALSE:
        return Decision.EXCLUDED
    return Decision.UNDETERMINED


def _first(mapping, names, default=None):
    for name in names:
        if name in mapping:
            return mapping[name]
    return default


def _looks_like_cpe(value):
    if isinstance(value, CPE):
        return True
    if not isinstance(value, string_types):
        return False
    lowered = value.strip().lower()
    return (lowered.startswith("cpe:") or
            lowered.startswith("cpe:/") or
            lowered.startswith("wfn:"))


def _category_for_key(key):
    if not isinstance(key, string_types):
        return None
    normalized = key.strip().lower().replace("-", "_")
    for category, aliases in _CATEGORY_KEYS.items():
        if normalized in aliases:
            return category
    return None


def _part_for_key(key):
    category = _category_for_key(key)
    if category is None:
        return None
    return _CATEGORY_TO_PART.get(category)


def _category_for_part(part):
    return _PART_TO_CATEGORY.get(part)


def _clean_component_value(value):
    if value is None:
        return None
    if isinstance(value, list):
        if not value:
            return None
        value = value[0]
    value = _as_unicode(value)
    if len(value) >= 2 and value[0] == chr(34) and value[-1] == chr(34):
        value = value[1:-1]
    cleaned = []
    escaped = False
    for character in value:
        if escaped:
            cleaned.append(character)
            escaped = False
        elif character == '\\':
            escaped = True
        else:
            cleaned.append(character)
    if escaped:
        cleaned.append('\\')
    return ''.join(cleaned)


def _component_values(cpe):
    values = OrderedDict()
    for attribute in CPEComponent.CPE_COMP_KEYS_EXTENDED:
        raw = cpe.get_attribute_values(attribute)
        values[attribute] = _clean_component_value(raw[0] if raw else None)
    return values


def _to_wfn(cpe):
    if isinstance(cpe, string_types):
        cpe = _coerce_cpe(cpe)
    if isinstance(cpe, CPE2_3_WFN):
        return cpe
    return CPE2_3_WFN(cpe.as_wfn())


def _escape_wfn_value(value):
    value = _as_unicode(value)
    special = '\\";!#$%&\'()+,-./:<=>@[]^`{|}~'
    pieces = []
    for character in value:
        if character in special:
            pieces.append("\\")
        pieces.append(character)
    return "".join(pieces)


def _components_to_wfn(components, default_part=None):
    """Build a WFN CPE Name from a component mapping."""

    values = OrderedDict()
    for attribute in CPEComponent.CPE_COMP_KEYS_EXTENDED:
        values[attribute] = components.get(attribute)

    if values.get("part") is None and default_part is not None:
        values["part"] = default_part
    if values.get("part") is None:
        values["part"] = "u"

    pieces = []
    for attribute in CPEComponent.CPE_COMP_KEYS_EXTENDED:
        value = values.get(attribute)
        if value is None or value == "":
            continue
        pieces.append('{0}="{1}"'.format(
            attribute, _escape_wfn_value(value)))

    return CPE2_3_WFN("wfn:[{0}]".format(", ".join(pieces)))


def _coerce_cpe(value, default_part=None, components=None):
    """Return a CPE instance for a string, CPE object or component mapping."""

    if isinstance(value, CPE):
        return value
    if isinstance(value, string_types) and value.strip():
        try:
            return CPE(value)
        except (NotImplementedError, ValueError) as exc:
            raise ValueError("Invalid CPE Name '{0}': {1}".format(value, exc))
    if components:
        return _components_to_wfn(components, default_part=default_part)
    return None


def _match_components(pattern, observed):
    """Compare a clause CPE with an observed CPE."""

    pattern_wfn = _to_wfn(pattern)
    observed_wfn = _to_wfn(observed)
    expected_values = _component_values(pattern_wfn)
    observed_values = _component_values(observed_wfn)

    components = OrderedDict()
    matched = True
    for attribute, relation in CPESet2_3.compare_wfns(
            pattern_wfn, observed_wfn):
        relation_name = _RELATION_NAMES.get(relation, str(relation))
        attribute_matched = relation in _MATCHING_RELATIONS
        if not attribute_matched:
            matched = False
        components[attribute] = OrderedDict((
            ("expected", expected_values.get(attribute)),
            ("observed", observed_values.get(attribute)),
            ("relation", relation_name),
            ("matched", attribute_matched),
        ))

    return matched, components


def _new_evidence(evidence_id, clause_id, key, observation,
                  pattern=None, observed=None, matched=None,
                  components=None, reason=None, metadata=None):
    evidence = _AttrDict()
    evidence["id"] = evidence_id
    evidence["clause_id"] = clause_id
    evidence["key"] = key
    evidence["observation"] = observation
    evidence["state"] = observation
    evidence["pattern"] = (pattern.cpe_str if isinstance(pattern, CPE)
                           else pattern)
    evidence["observed_cpe"] = (observed.cpe_str if isinstance(observed, CPE)
                                else observed)
    evidence["matched"] = matched
    if not components and isinstance(pattern, CPE):
        try:
            expected = _component_values(_to_wfn(pattern))
            components = OrderedDict()
            for attribute, value in expected.items():
                components[attribute] = OrderedDict((
                    ("expected", value),
                    ("observed", None),
                    ("relation", None),
                    ("matched", None),
                ))
        except (ValueError, TypeError):
            components = None
    evidence["components"] = components or OrderedDict()
    evidence["component_evidence"] = evidence["components"]
    evidence["reason"] = reason
    evidence["metadata"] = metadata or OrderedDict()
    return evidence


class InventoryRecord(object):
    """One component observation in a device inventory."""

    def __init__(self, key, cpe=None, observation=None, components=None,
                 evidence_id=None, metadata=None):
        self.key = key
        self.cpe = _coerce_cpe(
            cpe, default_part=_part_for_key(key),
            components=(components or None))
        self.components = components or OrderedDict()
        if observation is None:
            observation = (Observation.SEEN
                           if (self.cpe is not None or self.components)
                           else Observation.PENDING)
        self.observation = normalize_observation(observation)
        self.evidence_id = evidence_id
        self.metadata = metadata or OrderedDict()

    def to_dict(self):
        return OrderedDict((
            ("id", self.evidence_id),
            ("key", self.key),
            ("observation", self.observation),
            ("cpe", self.cpe.cpe_str if isinstance(self.cpe, CPE)
                    else self.cpe),
            ("components", copy.deepcopy(self.components)),
            ("metadata", copy.deepcopy(self.metadata)),
        ))

    def __repr__(self):
        return ("InventoryRecord(key={0!r}, observation={1!r}, cpe={2!r})"
                .format(self.key, self.observation,
                        self.cpe.cpe_str if isinstance(self.cpe, CPE)
                        else self.cpe))


def _replace_version(cpe, version):
    """Return a copy of a CPE Name with only its version replaced."""

    if not isinstance(cpe, CPE):
        cpe = _coerce_cpe(cpe)
    components = OrderedDict()
    for attribute, value in _component_values(cpe).items():
        if attribute == CPEComponent.ATT_VERSION:
            continue
        if value in (None, "", "ANY", "NA"):
            continue
        components[attribute] = value
    components[CPEComponent.ATT_VERSION] = _as_unicode(version)
    updated = _coerce_cpe(None, components=components)
    try:
        return CPE(updated.as_uri_2_3())
    except (TypeError, ValueError):
        return updated


class DeviceInventory(object):
    """A device and its component observations."""

    def __init__(self, device_id, records=None, metadata=None):
        self.device_id = device_id
        self.metadata = metadata or OrderedDict()
        self._records = OrderedDict()
        self._record_order = []
        if records:
            if isinstance(records, dict):
                for key, value in records.items():
                    self._add_value(key, value)
            else:
                for index, value in enumerate(records):
                    self._add_value(None, value, index=index)

    @classmethod
    def from_device(cls, device):
        """Build an inventory from a CPE-oriented device mapping/list."""

        if isinstance(device, cls):
            return device

        if isinstance(device, (list, tuple)):
            return cls(None, records=device)

        if not isinstance(device, dict):
            raise TypeError("Device inventory must be a mapping or a list")

        device_id = _first(device, ("device_id", "deviceId", "id", "name"))
        metadata = _first(device, ("metadata", "meta"), OrderedDict())
        wrapper_key = None
        for candidate in _INVENTORY_WRAPPER_KEYS:
            if candidate in device:
                wrapper_key = candidate
                break

        if wrapper_key is not None:
            records = device[wrapper_key]
            return cls(device_id, records=records, metadata=metadata)

        records = OrderedDict(
            (key, value) for key, value in device.items()
            if key not in _META_KEYS)
        return cls(device_id, records=records, metadata=metadata)

    def _add_value(self, key, value, index=None):
        if isinstance(value, (list, tuple)):
            for inner_index, item in enumerate(value):
                self._add_value(key, item,
                                index=inner_index if index is None else index)
            return

        record = self._record_from_value(key, value, index=index)
        self._record_order.append(record)
        self._records.setdefault(record.key, []).append(record)

    def _record_from_value(self, key, value, index=None):
        components = OrderedDict()
        metadata = OrderedDict()
        observation = None
        cpe = None
        evidence_id = None

        if isinstance(value, InventoryRecord):
            record = value
            if key is not None:
                record.key = key
            if record.evidence_id is None:
                record.evidence_id = self._evidence_id(record.key, index)
            return record

        if _looks_like_cpe(value) or isinstance(value, CPE):
            cpe = _coerce_cpe(value, default_part=_part_for_key(key))
            observation = Observation.SEEN
        elif isinstance(value, bool):
            observation = Observation.SEEN if value else Observation.ABSENT
        elif value is None:
            observation = Observation.PENDING
        elif isinstance(value, dict):
            evidence_id = _first(
                value, ("evidence_id", "observation_id", "evidence", "id"))
            key = _first(
                value, ("inventory_key", "slot", "component", "ref",
                        "key", "source"), key)

            state_value = _first(
                value, ("observation", "state", "status", "presence",
                        "collection_status", "collected"))
            if state_value is None:
                if "exists" in value:
                    state_value = (Observation.SEEN if value["exists"]
                                   else Observation.ABSENT)
                elif "present" in value:
                    state_value = (Observation.SEEN if value["present"]
                                   else Observation.ABSENT)
                elif ("observed" in value and
                      not _looks_like_cpe(value["observed"])):
                    state_value = (Observation.SEEN if value["observed"]
                                   else Observation.PENDING)
            if state_value is not None:
                observation = normalize_observation(state_value)

            cpe_value = _first(
                value, ("cpe", "cpe_name", "cpeName", "fact_ref",
                        "fact-ref", "wfn", "match"))
            observed_value = value.get("observed")
            if cpe_value is None and _looks_like_cpe(observed_value):
                cpe_value = observed_value
            record_name = value.get("name")
            if cpe_value is None and _looks_like_cpe(record_name):
                cpe_value = record_name
            elif key is None and isinstance(record_name, string_types):
                key = record_name
            raw_components = _first(value, ("components", "attributes",
                                            "fields"))
            if isinstance(raw_components, dict):
                components.update(raw_components)
            else:
                for attribute in CPEComponent.CPE_COMP_KEYS_EXTENDED:
                    if attribute in value:
                        components[attribute] = value[attribute]

            if cpe_value is not None:
                cpe = _coerce_cpe(
                    cpe_value,
                    default_part=(components.get("part") or
                                  _part_for_key(key)))
            elif components:
                cpe = _coerce_cpe(
                    None,
                    default_part=(components.get("part") or
                                  _part_for_key(key)),
                    components=components)

            metadata = _first(value, ("metadata", "meta"), OrderedDict())
            if observation is None:
                observation = (Observation.SEEN
                               if (cpe is not None or components)
                               else Observation.PENDING)
        else:
            raise TypeError(
                "Unsupported inventory value for {0!r}: {1!r}"
                .format(key, value))

        if key is None:
            key = self._key_from_cpe(cpe, index)
        if evidence_id is None:
            evidence_id = self._evidence_id(key, index)

        return InventoryRecord(
            key, cpe=cpe, observation=observation, components=components,
            evidence_id=evidence_id, metadata=metadata)

    def _key_from_cpe(self, cpe, index):
        if cpe is not None:
            parts = cpe.get_part()
            if parts:
                category = _category_for_part(parts[0])
                if category is not None:
                    if index is None:
                        return category
                    return "{0}:{1}".format(category, index)
        if index is None:
            return "component"
        return "component:{0}".format(index)

    def _evidence_id(self, key, index):
        if index is None:
            index = len(self._record_order)
        return "{0}:{1}:{2}".format(
            self.device_id if self.device_id is not None else "device",
            key, index)

    @property
    def records(self):
        return list(self._record_order)

    def get_record(self, key):
        records = self._records.get(key)
        return records[0] if records else None

    def get_records(self, key, part=None):
        """Return records for a component key.

        An exact inventory key wins.  Otherwise the key is treated as a
        component category (os/application/hardware) and records belonging to
        that category are returned.  If nothing suitable exists, an empty list
        means the component is pending, never absent.
        """

        if key is not None and key in self._records:
            return list(self._records[key])

        category = _category_for_key(key)
        wanted_part = _part_for_key(key) or part

        if wanted_part is None and category is not None:
            wanted_part = _CATEGORY_TO_PART.get(category)

        matches = []
        for record in self._record_order:
            record_category = _category_for_key(record.key)
            if category is not None and record_category == category:
                matches.append(record)
                continue
            if wanted_part is not None and record.cpe is not None:
                parts = record.cpe.get_part()
                if parts and parts[0] == wanted_part:
                    matches.append(record)

        return matches

    def state_for(self, key):
        records = self.get_records(key)
        if not records:
            return Observation.PENDING
        states = [record.observation for record in records]
        if Observation.SEEN in states:
            return Observation.SEEN
        if Observation.PENDING in states:
            return Observation.PENDING
        return Observation.ABSENT

    def observation(self, key):
        """Return the aggregate observation for one component key."""

        return self.state_for(key)

    def set(self, key, cpe=None, observation=None, components=None,
            evidence_id=None, metadata=None, version=None):
        """Replace the evidence for one component and return (old, new)."""

        if cpe is None and version is not None:
            cpe = version
        old_records = list(self._records.get(key, []))
        old = old_records[0] if old_records else None
        if (cpe is not None and not isinstance(cpe, CPE) and
                not _looks_like_cpe(cpe)):
            if old is None or old.cpe is None:
                raise ValueError(
                    "A bare version update needs existing CPE evidence "
                    "for {0!r}".format(key))
            cpe = _replace_version(old.cpe, cpe)
        record = InventoryRecord(
            key, cpe=_coerce_cpe(cpe, default_part=_part_for_key(key)),
            observation=observation, components=components,
            evidence_id=(evidence_id or
                         (old.evidence_id if old is not None else
                          self._evidence_id(key, None))),
            metadata=metadata)
        self._records[key] = [record]
        self._record_order = [
            item for item in self._record_order if item.key != key]
        self._record_order.append(record)
        return old, record

    update = set
    update_component = set
    set_component = set
    get_observation = state_for

    def set_system_version(self, cpe, key="os", observation=None):
        """Convenience helper for the common system-version update."""

        return self.set(key, cpe=cpe, observation=observation)

    def snapshot(self):
        """Return the inventory state grouped by component key."""

        result = OrderedDict()
        for key, records in self._records.items():
            states = [record.observation for record in records]
            if Observation.SEEN in states:
                state = Observation.SEEN
            elif Observation.PENDING in states:
                state = Observation.PENDING
            else:
                state = Observation.ABSENT
            result[key] = OrderedDict((
                ("state", state),
                ("observation", state),
                ("cpes", [record.cpe.cpe_str
                          for record in records if record.cpe is not None]),
            ))
        return result


class _Node(object):
    """Internal parsed configuration node."""

    def __init__(self, operator, clause_id, children=None, cpe=None,
                 key=None, exclusion=False, negate=False, title=None,
                 metadata=None):
        self.operator = operator
        self.clause_id = clause_id
        self.children = children or []
        self.cpe = cpe
        self.key = key
        self.exclusion = exclusion
        self.negate = negate
        self.title = title
        self.metadata = metadata or OrderedDict()

    @property
    def part(self):
        if self.cpe is None:
            return _part_for_key(self.key)
        parts = self.cpe.get_part()
        return parts[0] if parts else _part_for_key(self.key)


class Configuration(object):
    """Parsed advisory configuration tree."""

    def __init__(self, raw):
        self.raw = raw
        self._ids = set()
        self.root = _parse_config_node(raw, self, is_root=True)

    def _unique_id(self, wrapper, preferred):
        if preferred is None or not isinstance(preferred, string_types):
            preferred = wrapper
        base = preferred.strip() or wrapper
        candidate = base
        suffix = 2
        while candidate in self._ids:
            candidate = "{0}#{1}".format(base, suffix)
            suffix += 1
        self._ids.add(candidate)
        return candidate

    def to_dict(self):
        return _node_to_dict(self.root)


def _node_children(raw):
    for key in ("children", "clauses", "conditions", "subtests", "of",
                "operands", "all", "any"):
        if key in raw:
            value = raw[key]
            if isinstance(value, (list, tuple)):
                return list(value)
            return [value]
    return None


def _parse_config_node(raw, configuration, is_root=False):
    if isinstance(raw, _Node):
        return raw

    if raw is None:
        return _Node("CONST", configuration._unique_id(
            "root" if is_root else "const", None), metadata={"value": None})

    if isinstance(raw, bool):
        return _Node("CONST", configuration._unique_id(
            "root" if is_root else "const", None), metadata={"value": raw})

    if _looks_like_cpe(raw) or isinstance(raw, CPE):
        clause_id = configuration._unique_id(
            "root" if is_root else "clause", None)
        return _Node("CPE", clause_id, cpe=_coerce_cpe(raw))

    if isinstance(raw, (list, tuple)):
        children = [_parse_config_node(item, configuration)
                    for item in raw]
        return _Node("AND", configuration._unique_id(
            "root" if is_root else "and", None), children=children)

    if not isinstance(raw, dict):
        raise TypeError("Configuration node must be a mapping: {0!r}"
                        .format(raw))

    raw = OrderedDict(raw)
    clause_id = _first(
        raw, ("id", "clause_id", "clauseId", "conclusion_id"))
    title = _first(raw, ("title", "description", "reason"))
    metadata = _first(raw, ("metadata", "meta"), OrderedDict())

    nested_exclusions = None
    for key in ("exclusions", "excludes", "exclude", "exclude_children"):
        if key not in raw:
            continue
        value = raw[key]
        if isinstance(value, (list, tuple)):
            nested_exclusions = list(value)
            break
        if (isinstance(value, dict) or isinstance(value, CPE) or
                _looks_like_cpe(value)):
            nested_exclusions = [value]
            break

    def wrap_with_exclusions(node):
        if not nested_exclusions:
            return node
        children = [node]
        for item in nested_exclusions:
            child = _parse_config_node(item, configuration)
            if child.operator == "EXCLUDE" or child.exclusion:
                children.append(child)
            else:
                children.append(_Node(
                    "EXCLUDE",
                    configuration._unique_id("exclude", None),
                    children=[child],
                    exclusion=True))
        if is_root:
            if node.clause_id == "root":
                node.clause_id = configuration._unique_id("body", "body")
            else:
                node.clause_id = configuration._unique_id(
                    "body", node.clause_id)
            wrapper_id = "root"
        else:
            wrapper_id = configuration._unique_id("and", clause_id)
        return _Node(
            "AND",
            wrapper_id,
            children=children,
            title=title, metadata=metadata)

    operator_value = _first(raw, ("operator", "op", "type", "kind"))
    if operator_value is not None and isinstance(operator_value, string_types):
        operator = _LOGICAL_OPERATORS.get(operator_value.strip().lower())
    else:
        operator = None

    if operator is None and "exclude" in raw and (
            isinstance(raw["exclude"], dict) or
            isinstance(raw["exclude"], CPE) or
            _looks_like_cpe(raw["exclude"])):
        child = _parse_config_node(raw["exclude"], configuration)
        node = _Node(
            "EXCLUDE", configuration._unique_id(
                "root" if is_root else "exclude", clause_id),
            children=[child], exclusion=True, negate=True,
            title=title, metadata=metadata)
        return wrap_with_exclusions(node)

    if operator is None and "not" in raw:
        child = _parse_config_node(raw["not"], configuration)
        node = _Node(
            "NOT", configuration._unique_id(
                "root" if is_root else "not", clause_id),
            children=[child], negate=True, title=title, metadata=metadata)
        return wrap_with_exclusions(node)

    if operator is None and "all" in raw:
        operator = "AND"

    if operator is None and "any" in raw:
        operator = "OR"

    if operator is None and any(
            key in raw for key in
            ("cpe", "cpe_name", "cpeName", "fact_ref", "fact-ref",
             "wfn", "match")):
        operator = "CPE"

    if operator is None and _node_children(raw) is None and any(
            attribute in raw
            for attribute in CPEComponent.CPE_COMP_KEYS_EXTENDED):
        operator = "CPE"

    if operator is None and _node_children(raw) is not None:
        operator = "AND"

    if operator in ("AND", "OR"):
        children_raw = _node_children(raw)
        if children_raw is None:
            raise ValueError(
                "{0} configuration node needs children".format(operator))
        children = [_parse_config_node(item, configuration)
                    for item in children_raw]
        node = _Node(
            operator,
            configuration._unique_id(
                "root" if is_root else operator.lower(), clause_id),
            children=children,
            title=title, metadata=metadata)
    elif operator in ("NOT", "EXCLUDE"):
        children_raw = _node_children(raw)
        if children_raw is None:
            child_raw = _first(raw, ("child", "clause"))
            if child_raw is None:
                # Some advisory formats attach the negated CPE directly to
                # the logical node, e.g. {"operator": "EXCLUDE",
                # "key": "patch", "cpe": "..."}.  Parse that payload as the
                # single child rather than turning the node into a constant.
                child_raw = OrderedDict(
                    (key, value) for key, value in raw.items()
                    if key not in ("operator", "op", "type", "kind",
                                   "negate", "exclude", "excluded",
                                   "exclusion", "exclusions", "excludes",
                                   "title", "description", "reason",
                                   "metadata", "meta", "id",
                                   "clause_id", "clauseId",
                                   "conclusion_id"))
                if not child_raw:
                    raise ValueError(
                        "{0} configuration node needs a child"
                        .format(operator))
            children_raw = [child_raw]
        if len(children_raw) != 1:
            raise ValueError(
                "{0} configuration node needs exactly one child"
                .format(operator))
        child = _parse_config_node(children_raw[0], configuration)
        node = _Node(
            operator,
            configuration._unique_id(
                "root" if is_root else operator.lower(), clause_id),
            children=[child],
            exclusion=(operator == "EXCLUDE" or bool(raw.get("exclude"))),
            negate=True,
            title=title, metadata=metadata)
    elif operator == "CPE":
        cpe_value = _first(
            raw, ("cpe", "cpe_name", "cpeName", "fact_ref", "fact-ref",
                  "wfn", "match"))
        raw_components = _first(raw, ("components", "attributes"))
        components = None
        if isinstance(raw_components, dict):
            components = raw_components
        else:
            components = dict(
                (attribute, raw[attribute])
                for attribute in CPEComponent.CPE_COMP_KEYS_EXTENDED
                if attribute in raw)

        key = _first(
            raw, ("inventory_key", "slot", "component", "ref", "source",
                  "field", "key"))
        part = _first(raw, ("part",))
        default_part = part or _part_for_key(key)

        if isinstance(cpe_value, (list, tuple)):
            children = []
            for item in cpe_value:
                child = _parse_config_node(
                    dict(raw, cpe=item), configuration)
                child.key = key
                children.append(child)
            node = _Node(
                "OR",
                configuration._unique_id(
                    "root" if is_root else "or", clause_id),
                children=children, title=title, metadata=metadata)
        else:
            cpe = _coerce_cpe(cpe_value,
                              default_part=default_part,
                              components=components or None)
            if cpe is None:
                raise ValueError(
                    "CPE clause needs a cpe name or component values")
            preferred = clause_id or key
            node = _Node(
                "CPE",
                configuration._unique_id(
                    "root" if is_root else "clause", preferred),
                cpe=cpe, key=key,
                exclusion=bool(raw.get("exclude") or
                               raw.get("excluded") or
                               raw.get("exclusion")),
                title=title, metadata=metadata)
    else:
        raise ValueError(
            "Unsupported configuration node: {0!r}".format(raw))

    if raw.get("negate") and node.operator not in ("NOT", "EXCLUDE"):
        node = _Node(
            "NOT",
            configuration._unique_id(
                "root" if is_root else "not", clause_id),
            children=[node], negate=True, title=title, metadata=metadata)

    if is_root and not node.clause_id.startswith("root"):
        # A stable root id makes dependency reports easy to consume.
        node.clause_id = configuration._unique_id("root", "root")

    return wrap_with_exclusions(node)


class _NodeEvaluation(object):
    def __init__(self, node, truth, evidence, children,
                 dependencies=None, supporting=None, reason=None,
                 exclusion_triggered=None):
        self.node = node
        self.truth = truth
        self.evidence = evidence
        self.children = children
        self.dependencies = dependencies or []
        self.supporting = supporting or []
        self.reason = reason
        self.exclusion_triggered = exclusion_triggered

    @property
    def keys(self):
        keys = []
        for evidence in self.evidence:
            if evidence.get("key") is not None:
                keys.append(evidence["key"])
        for child in self.children:
            keys.extend(child.keys)
        return _unique(keys)

    def to_explanation(self):
        explanation = _AttrDict()
        explanation["id"] = self.node.clause_id
        explanation["clause_id"] = self.node.clause_id
        explanation["operator"] = self.node.operator
        explanation["key"] = self.node.key
        explanation["truth"] = self.truth
        explanation["decision"] = _truth_to_decision(self.truth)
        if self.node.operator == "CPE":
            observations = [item.get("observation")
                            for item in self.evidence]
            if Observation.SEEN in observations:
                explanation["observation"] = Observation.SEEN
            elif Observation.PENDING in observations:
                explanation["observation"] = Observation.PENDING
            elif Observation.ABSENT in observations:
                explanation["observation"] = Observation.ABSENT
            explanation["inventory_state"] = explanation.get("observation")
        explanation["exclusion"] = bool(self.node.exclusion)
        explanation["exclusion_triggered"] = self.exclusion_triggered
        explanation["reason"] = self.reason
        explanation["dependencies"] = list(self.dependencies)
        explanation["supporting_evidence"] = list(self.supporting)
        explanation["keys"] = list(self.keys)
        explanation["evidence"] = EvidenceCollection(self.evidence)
        explanation["children"] = ClauseCollection(
            [child.to_explanation() for child in self.children])
        if self.node.title is not None:
            explanation["title"] = self.node.title
        if self.node.metadata:
            explanation["metadata"] = copy.deepcopy(self.node.metadata)
        return explanation


def _unique(values):
    result = []
    seen = set()
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _evidence_ids(evidence):
    return [item["id"] for item in evidence]


def _evaluate_leaf(node, inventory):
    key = node.key
    records = inventory.get_records(key, part=node.part)
    clause_id = node.clause_id
    pattern = node.cpe
    evidence = EvidenceCollection()

    if not records:
        evidence.append(_new_evidence(
            "{0}:{1}:not_collected".format(
                inventory.device_id if inventory.device_id is not None
                else "device", key or "component"),
            clause_id, key, Observation.PENDING, pattern=pattern,
            reason="not_collected"))
        return _NodeEvaluation(
            node, Truth.UNKNOWN, evidence, [],
            dependencies=_evidence_ids(evidence),
            supporting=_evidence_ids(evidence),
            reason="inventory item has not been collected")

    true_evidence = []
    pending_evidence = []
    false_evidence = []

    for index, record in enumerate(records):
        evidence_id = record.evidence_id or "{0}:{1}:{2}".format(
            inventory.device_id if inventory.device_id is not None
            else "device", record.key, index)

        if record.observation == Observation.PENDING:
            item = _new_evidence(
                evidence_id, clause_id, record.key, Observation.PENDING,
                pattern=pattern, observed=record.cpe,
                reason="inventory item has not been collected",
                metadata=record.metadata)
            evidence.append(item)
            pending_evidence.append(item)
            continue

        if record.observation == Observation.ABSENT:
            item = _new_evidence(
                evidence_id, clause_id, record.key, Observation.ABSENT,
                pattern=pattern, observed=record.cpe, matched=False,
                reason="inventory explicitly reports the component absent",
                metadata=record.metadata)
            evidence.append(item)
            false_evidence.append(item)
            continue

        observed = record.cpe
        if observed is None and record.components:
            observed = _coerce_cpe(
                None, default_part=node.part, components=record.components)

        if observed is None:
            item = _new_evidence(
                evidence_id, clause_id, record.key, Observation.SEEN,
                pattern=pattern, matched=None,
                reason="component was seen but has no identifying CPE",
                metadata=record.metadata)
            evidence.append(item)
            pending_evidence.append(item)
            continue

        matched, components = _match_components(pattern, observed)
        item = _new_evidence(
            evidence_id, clause_id, record.key, Observation.SEEN,
            pattern=pattern, observed=observed, matched=matched,
            components=components,
            reason=("observed CPE matches the clause" if matched else
                    "observed CPE does not match the clause"),
            metadata=record.metadata)
        evidence.append(item)
        if matched:
            true_evidence.append(item)
        else:
            false_evidence.append(item)

    if true_evidence:
        truth = Truth.TRUE
        supporting = true_evidence
        reason = "at least one collected component matches"
    elif pending_evidence:
        truth = Truth.UNKNOWN
        supporting = pending_evidence
        reason = "matching component evidence is pending"
    else:
        truth = Truth.FALSE
        supporting = false_evidence
        reason = "collected components do not match"

    return _NodeEvaluation(
        node, truth, evidence, [],
        dependencies=_evidence_ids(evidence),
        supporting=_evidence_ids(supporting),
        reason=reason)


def _evaluate_node(node, inventory):
    if node.operator == "CONST":
        value = node.metadata.get("value")
        if value is None:
            truth = Truth.UNKNOWN
        else:
            truth = Truth.TRUE if value else Truth.FALSE
        return _NodeEvaluation(node, truth, EvidenceCollection(), [],
                               reason="constant")

    if node.operator == "CPE":
        evaluation = _evaluate_leaf(node, inventory)
        if node.exclusion:
            child = evaluation
            truth = _truth_not(child.truth)
            return _NodeEvaluation(
                node, truth, child.evidence, [],
                dependencies=child.dependencies,
                supporting=child.supporting,
                exclusion_triggered=(child.truth == Truth.TRUE),
                reason=("exclusion matched" if child.truth == Truth.TRUE
                        else ("exclusion evidence pending"
                              if child.truth == Truth.UNKNOWN
                              else "exclusion not present")))
        return evaluation

    child_evaluations = [_evaluate_node(child, inventory)
                         for child in node.children]
    evidence = EvidenceCollection()
    dependencies = []
    for child in child_evaluations:
        evidence.extend(child.evidence)
        dependencies.extend(child.dependencies)
    dependencies = _unique(dependencies)

    if node.operator == "AND":
        false_children = [child for child in child_evaluations
                          if child.truth == Truth.FALSE]
        unknown_children = [child for child in child_evaluations
                            if child.truth == Truth.UNKNOWN]
        if false_children:
            truth = Truth.FALSE
            decisive = false_children
            reason = "at least one required clause is not satisfied"
        elif unknown_children:
            truth = Truth.UNKNOWN
            decisive = unknown_children
            reason = "at least one required clause is pending"
        else:
            truth = Truth.TRUE
            decisive = child_evaluations
            reason = "all required clauses are satisfied"
    elif node.operator == "OR":
        true_children = [child for child in child_evaluations
                         if child.truth == Truth.TRUE]
        unknown_children = [child for child in child_evaluations
                            if child.truth == Truth.UNKNOWN]
        if true_children:
            truth = Truth.TRUE
            decisive = true_children
            reason = "at least one alternative clause is satisfied"
        elif unknown_children:
            truth = Truth.UNKNOWN
            decisive = unknown_children
            reason = "no alternative is satisfied and one is pending"
        else:
            truth = Truth.FALSE
            decisive = child_evaluations
            reason = "all alternative clauses are not satisfied"
    elif node.operator in ("NOT", "EXCLUDE"):
        child = child_evaluations[0]
        truth = _truth_not(child.truth)
        decisive = [child]
        exclusion_triggered = child.truth == Truth.TRUE
        if truth == Truth.FALSE:
            reason = "exclusion matched"
        elif truth == Truth.UNKNOWN:
            reason = "exclusion evidence is pending"
        else:
            reason = "exclusion not present"
    else:
        raise ValueError("Unknown configuration operator {0}"
                         .format(node.operator))

    supporting = []
    for child in decisive:
        supporting.extend(child.supporting)
    supporting = _unique(supporting)

    return _NodeEvaluation(
        node, truth, evidence, child_evaluations,
        dependencies=dependencies, supporting=supporting, reason=reason,
        exclusion_triggered=(
            exclusion_triggered if node.operator in ("NOT", "EXCLUDE")
            else None))


def _all_clauses(root_explanation):
    clauses = ClauseCollection()

    def visit(clause):
        if clause.get("operator") == "CPE":
            clauses.append(clause)
        for child in clause.get("children", ()):
            visit(child)

    visit(root_explanation)
    return clauses


def _all_nodes(root_explanation):
    nodes = ClauseCollection()

    def visit(node):
        nodes.append(node)
        for child in node.get("children", ()):
            visit(child)

    visit(root_explanation)
    return nodes


class ConfigurationExplanation(_AttrDict):
    """Result of interpreting one configuration against one device."""

    def to_dict(self):
        return _plain(self)

    def to_json(self, **kwargs):
        import json
        kwargs.setdefault("indent", 2)
        kwargs.setdefault("sort_keys", False)
        return json.dumps(self.to_dict(), **kwargs)


def _pending_keys(root_explanation):
    keys = []
    for clause in _all_clauses(root_explanation):
        if clause.get("truth") != Truth.UNKNOWN:
            continue
        for evidence in clause.get("evidence", ()):
            if evidence.get("observation") == Observation.PENDING:
                keys.append(evidence.get("key"))
    return _unique([key for key in keys if key is not None])


def _excluded_by(root_explanation):
    evidence_ids = []
    for node in _all_nodes(root_explanation):
        if not node.get("exclusion"):
            continue
        if node.get("exclusion_triggered"):
            evidence_ids.extend(node.get("supporting_evidence", ()))
        if (node.get("operator") in ("NOT", "EXCLUDE") and
                node.get("truth") == Truth.FALSE):
            evidence_ids.extend(node.get("supporting_evidence", ()))
    return _unique(evidence_ids)


def explain(config, device):
    """Interpret an advisory configuration for one device.

    :param config: configuration tree (mapping, list, raw CPE or Configuration)
    :param device: device inventory (mapping, DeviceInventory or record list)
    :returns: :class:`ConfigurationExplanation`
    """

    configuration = config if isinstance(config, Configuration) \
        else Configuration(config)
    inventory = DeviceInventory.from_device(device)
    evaluation = _evaluate_node(configuration.root, inventory)
    root = evaluation.to_explanation()
    status = _truth_to_status(evaluation.truth)
    clauses = _all_clauses(root)
    nodes = _all_nodes(root)

    all_evidence = EvidenceCollection()
    for clause in clauses:
        all_evidence.extend(clause.get("evidence", ()))

    if status == Decision.UNDETERMINED:
        pending = _pending_keys(root)
        if pending:
            reason = "pending inventory evidence: {0}".format(
                ", ".join(pending))
        else:
            reason = "configuration cannot be proven"
    elif status == Decision.EXCLUDED:
        if _excluded_by(root):
            reason = "an exclusion clause is satisfied"
        else:
            reason = "a required clause is not satisfied"
    else:
        reason = "the configuration is satisfied"

    result = ConfigurationExplanation()
    result["device_id"] = inventory.device_id
    result["status"] = status
    result["decision"] = status
    result["verdict"] = status
    result["truth"] = evaluation.truth
    result["reason"] = reason
    result["root"] = root
    result["nodes"] = nodes
    result["clauses"] = clauses
    result["evidence"] = all_evidence
    result["evidence_by_key"] = _evidence_by_key(all_evidence)
    result["dependencies"] = list(evaluation.dependencies)
    result["pending_keys"] = _pending_keys(root)
    result["excluded_by"] = _excluded_by(root)
    snapshot = inventory.snapshot()
    for clause in clauses:
        for item in clause.get("evidence", ()):
            key = item.get("key")
            if key is not None and key not in snapshot:
                snapshot[key] = OrderedDict((
                    ("state", item.get("observation")),
                    ("observation", item.get("observation")),
                    ("cpes", []),
                ))
    result["inventory"] = snapshot
    result["observations"] = snapshot
    result["states"] = snapshot
    result["affected"] = status == Decision.AFFECTED
    result["is_affected"] = status == Decision.AFFECTED
    result["excluded"] = status == Decision.EXCLUDED
    result["is_excluded"] = status == Decision.EXCLUDED
    result["not_affected"] = status == Decision.EXCLUDED
    result["undetermined"] = status == Decision.UNDETERMINED
    result["is_undetermined"] = status == Decision.UNDETERMINED
    result["pending"] = status == Decision.UNDETERMINED
    result["confirmed"] = status != Decision.UNDETERMINED
    result["all_clauses"] = nodes
    result["conclusions"] = nodes
    if isinstance(configuration.raw, dict):
        result["advisory_id"] = configuration.raw.get("id")
        result["configuration_id"] = configuration.raw.get("id")
    return result


def _evidence_by_key(evidence):
    result = OrderedDict()
    for item in evidence:
        key = item.get("key")
        if key is None:
            continue
        result.setdefault(key, EvidenceCollection()).append(item)
    return result


interpret = explain
evaluate = explain
evaluate_configuration = explain
evaluate_device = explain
explain_config = explain
interpret_config = explain
interpret_configuration = explain
offline_explain = explain

ConfigExplanation = ConfigurationExplanation
ComponentState = Observation
Inventory = DeviceInventory


class RevisionResult(_AttrDict):
    """Outcome of changing one evidence item and re-evaluating a device."""

    def to_dict(self):
        return _plain(self)


class ConfigurationExplainer(object):
    """Stateful helper for repeated offline explanations and revisions."""

    def __init__(self, config):
        self.config = config if isinstance(config, Configuration) \
            else Configuration(config)
        self.devices = OrderedDict()
        self._explanations = OrderedDict()

    def add_device(self, device, device_id=None):
        inventory = DeviceInventory.from_device(device)
        if device_id is not None:
            inventory.device_id = device_id
        if inventory.device_id is None:
            inventory.device_id = device_id or "device-{0}".format(
                len(self.devices) + 1)
        self.devices[inventory.device_id] = inventory
        return inventory

    def get_device(self, device_id):
        return self.devices[device_id]

    def explain(self, device):
        if isinstance(device, string_types) and device in self.devices:
            inventory = self.devices[device]
        else:
            inventory = DeviceInventory.from_device(device)
            if inventory.device_id is not None:
                self.devices.setdefault(inventory.device_id, inventory)

        result = explain(self.config, inventory)
        if inventory.device_id is not None:
            self._explanations[inventory.device_id] = result
        return result

    def interpret(self, device):
        """Alias for explain."""

        return self.explain(device)

    def explain_device(self, device):
        """Alias for explain."""

        return self.explain(device)

    def explain_all(self):
        results = OrderedDict()
        for device_id in self.devices:
            results[device_id] = self.explain(device_id)
        return results

    def revise(self, device_id, key, cpe=None, observation=None,
               components=None, version=None):
        """Replace one component's evidence and report dependent conclusions.

        Conclusions are addressed by clause id.  ``revoked`` contains the
        nodes whose evidence set included ``key`` before the update;
        ``preserved`` contains conclusions that did not depend on it.
        """

        inventory = self.devices[device_id]
        if device_id in self._explanations:
            previous = self._explanations[device_id]
        else:
            previous = self.explain(inventory)

        if cpe is None and version is not None:
            cpe = version
        old_record, new_record = inventory.set(
            key, cpe=cpe, observation=observation, components=components)
        current = explain(self.config, inventory)
        if device_id is not None:
            self._explanations[device_id] = current

        revoked = []
        preserved = []
        for node in _all_nodes(previous["root"]):
            if key in node.get("keys", ()):
                revoked.append(_conclusion_summary(
                    node, current, revoked=True))
            else:
                preserved.append(_conclusion_summary(
                    node, current, revoked=False))

        result = RevisionResult()
        result["device_id"] = device_id
        result["component_key"] = key
        result["old"] = old_record
        result["new"] = new_record
        result["previous"] = previous
        result["current"] = current
        result["previous_status"] = previous["status"]
        result["current_status"] = current["status"]
        result["status"] = current["status"]
        result["changed"] = previous["status"] != current["status"]
        result["revoked"] = [item["id"] for item in revoked]
        result["revoked_conclusions"] = revoked
        result["preserved"] = [item["id"] for item in preserved]
        result["preserved_conclusions"] = preserved
        # Aliases commonly used by callers that model conclusions as a set.
        result["withdrawn"] = result["revoked"]
        result["still_supported"] = result["preserved"]
        changed_conclusions = [
            item for item in revoked
            if item["truth_before"] != item["truth_after"]]
        result["invalidated"] = [item["id"]
                                 for item in changed_conclusions]
        result["changed_conclusions"] = changed_conclusions
        result["revalidated"] = [
            item["id"] for item in revoked
            if item["truth_before"] == item["truth_after"]]
        return result

    def revise_system_version(self, device_id, cpe=None, key="os",
                              observation=None, version=None):
        return self.revise(
            device_id, key, cpe=cpe, observation=observation,
            version=version)


ConfigurationInterpreter = ConfigurationExplainer
ConfigInterpreter = ConfigurationExplainer
ConfigExplainer = ConfigurationExplainer


def _conclusion_summary(previous_node, current, revoked):
    current_node = current["nodes"].get(previous_node["id"])
    summary = _AttrDict()
    summary["id"] = previous_node["id"]
    summary["key"] = previous_node.get("key")
    summary["truth_before"] = previous_node.get("truth")
    summary["truth_after"] = (current_node.get("truth")
                              if current_node is not None else None)
    summary["status_before"] = _truth_to_decision(
        previous_node.get("truth"))
    summary["status_after"] = (
        _truth_to_decision(current_node.get("truth"))
        if current_node is not None else None)
    summary["revoked"] = revoked
    summary["dependencies"] = list(previous_node.get("dependencies", ()))
    summary["keys"] = list(previous_node.get("keys", ()))
    return summary


def explain_configuration(config, devices):
    """Interpret a configuration for one device or a collection of devices.

    A list/tuple returns a list of explanations.  A mapping whose values look
    like devices returns an OrderedDict keyed by device id.  Any other mapping
    is treated as a single device inventory.
    """

    if isinstance(devices, (list, tuple)):
        explainer = ConfigurationExplainer(config)
        return [explainer.explain(device) for device in devices]

    if isinstance(devices, dict):
        values = list(devices.values())
        def _looks_like_device(value):
            if isinstance(value, DeviceInventory):
                return True
            if not isinstance(value, dict):
                return False
            if any(key in value for key in
                   ("components", "inventory", "observations", "assets")):
                return True
            if any(key in value for key in ("device_id", "deviceId")):
                return True
            return ("id" in value and not any(
                key in value for key in
                ("cpe", "observation", "state", "status", "presence")))

        is_device_collection = bool(values) and all(
            _looks_like_device(value) for value in values)
        if is_device_collection:
            explainer = ConfigurationExplainer(config)
            results = OrderedDict()
            for device_key, device in devices.items():
                if isinstance(device, DeviceInventory):
                    if device.device_id is None:
                        device.device_id = device_key
                    results[device_key] = explainer.explain(device)
                    continue
                results[device_key] = explainer.explain(
                    dict(device, device_id=device.get(
                        "device_id", device.get("deviceId",
                                                device.get("id",
                                                           device_key)))))
            return results

    return explain(config, devices)


# ---------------------------------------------------------------------------
# Synthetic fixtures used by the tests and documentation.
# ---------------------------------------------------------------------------

EXAMPLE_CONFIG = OrderedDict((
    ("id", "advisory-2026-0001"),
    ("operator", "AND"),
    ("children", [
        OrderedDict((
            ("id", "system-clause"),
            ("key", "os"),
            ("cpe", "cpe:/o:acme:linux:1.2"),
        )),
        OrderedDict((
            ("id", "plugin-clause"),
            ("key", "plugin"),
            ("cpe", "cpe:/a:acme:backup_agent:3.1"),
        )),
        OrderedDict((
            ("id", "mitigation-clause"),
            ("operator", "EXCLUDE"),
            ("key", "mitigation"),
            ("cpe", "cpe:/a:acme:backup_agent:3.1:patched"),
        )),
    ]),
))


def synthetic_devices():
    """Return affected, pending and excluded synthetic devices."""

    affected = OrderedDict((
        ("device_id", "device-affected"),
        ("components", OrderedDict((
            ("os", OrderedDict((
                ("cpe", "cpe:/o:acme:linux:1.2"),
                ("observation", Observation.SEEN),
            ))),
            ("plugin", OrderedDict((
                ("cpe", "cpe:/a:acme:backup_agent:3.1"),
                ("observation", Observation.SEEN),
            ))),
            ("mitigation", OrderedDict((
                ("observation", Observation.ABSENT),
            ))),
        ))),
    ))

    pending = OrderedDict((
        ("device_id", "device-pending"),
        ("components", OrderedDict((
            ("os", OrderedDict((
                ("cpe", "cpe:/o:acme:linux:1.2"),
                ("observation", Observation.SEEN),
            ))),
            ("plugin", OrderedDict((
                ("observation", Observation.PENDING),
            ))),
            ("mitigation", OrderedDict((
                ("observation", Observation.PENDING),
            ))),
        ))),
    ))

    excluded = OrderedDict((
        ("device_id", "device-excluded"),
        ("components", OrderedDict((
            ("os", OrderedDict((
                ("cpe", "cpe:/o:acme:linux:1.2"),
                ("observation", Observation.SEEN),
            ))),
            ("plugin", OrderedDict((
                ("cpe", "cpe:/a:acme:backup_agent:3.1"),
                ("observation", Observation.SEEN),
            ))),
            ("mitigation", OrderedDict((
                ("cpe", "cpe:/a:acme:backup_agent:3.1:patched"),
                ("observation", Observation.SEEN),
            ))),
        ))),
    ))

    return OrderedDict((
        ("affected", affected),
        ("pending", pending),
        ("excluded", excluded),
    ))


_SYNTHETIC_DEVICES = synthetic_devices()
AFFECTED_DEVICE = _SYNTHETIC_DEVICES["affected"]
UNDETERMINED_DEVICE = _SYNTHETIC_DEVICES["pending"]
PENDING_DEVICE = _SYNTHETIC_DEVICES["pending"]
EXCLUDED_DEVICE = _SYNTHETIC_DEVICES["excluded"]
EXAMPLE_DEVICES = _SYNTHETIC_DEVICES
