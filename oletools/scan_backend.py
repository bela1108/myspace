#!/usr/bin/env python
"""
Budget-aware Office object scanning backend.

The backend in this module turns the accounting primitives from
:mod:`oletools.common.scan_budget` into a resumable scanner.  It is deliberately
independent from the command-line tools: a gateway can provide a list (or a
:class:`SyntheticContainer`) of objects and receive structured results without
parsing stdout.

The scanner processes objects in order and charges three independent stages:

``container``
    Opening and walking the OLE/OpenXML/RTF container.
``macro``
    Detecting projects and extracting/decompressing macro code.
``attachment``
    Decoding OLE package/embedded attachment streams.

A stage is charged before it is executed.  If a stage does not fit, the
scanner stops *before* that stage and returns:

* every finding already proven,
* the completed object prefix (only objects whose stages all completed),
* the exact unprocessed object range,
* the category and shortfall that paused the scan.

Completed verdicts are cached by object id and content fingerprint.  Resuming
with more quota for one object therefore reuses all other completed verdicts
instead of re-interpreting them under a different global budget.

Example::

    from oletools.scan_backend import ScanBudget, OfficeScanBackend

    container = SyntheticContainer([
        {'id': 'large.docx', 'costs': {'container': 10, 'macro': 10,
                                       'attachment': 10}},
        {'id': 'small.doc', 'costs': {'container': 2, 'macro': 2,
                                      'attachment': 2}},
    ])
    budget = ScanBudget(container=10, macro=10, attachment=10)
    backend = OfficeScanBackend()

    first = backend.scan(container, budget)
    assert first.paused
    assert first.covered_prefix == ('large.docx',)

    budget.top_up('small.doc', container=2, macro=2, attachment=2)
    second = backend.resume(first)
    assert second.complete
"""

from __future__ import print_function

import copy
import hashlib

try:
    from collections.abc import Mapping
except ImportError:  # pragma: no cover - Python 2 compatibility
    from collections import Mapping

from oletools.common.scan_budget import (
    ATTACHMENT,
    CATEGORIES,
    CONTAINER,
    MACRO,
    BudgetAccount,
    BudgetCategory,
    BudgetError,
    BudgetExhausted,
    ScanBudget,
    normalize_categories,
    normalize_category,
)


# ---------------------------------------------------------------------------
# Result status constants
# ---------------------------------------------------------------------------

STATUS_COMPLETE = 'complete'
STATUS_PARTIAL = 'partial'
STATUS_PENDING = 'pending'
STATUS_ERROR = 'error'

STAGE_ORDER = CATEGORIES


class IdSequence(list):
    """
    List of object ids that also compares naturally with tuples and counts.

    This keeps the public result friendly to callers that treat a covered
    prefix as either an ordered id list or a count.
    """

    def __eq__(self, other):
        if isinstance(other, int) and not isinstance(other, bool):
            return len(self) == other
        if isinstance(other, tuple):
            return list(self) == list(other)
        return list.__eq__(self, other)

    def __ne__(self, other):
        return not self == other

    __hash__ = None


class IdPrefix(IdSequence):
    """Leading ids that were fully covered by the scanner."""


class ObjectRange(object):
    """Half-open object index range with tuple/range/slice comparisons."""

    def __init__(self, start, end):
        self.start = start
        self.end = end

    def __iter__(self):
        return iter(range(self.start, self.end))

    def __len__(self):
        return max(0, self.end - self.start)

    def __getitem__(self, index):
        return list(self)[index]

    def __contains__(self, value):
        return self.start <= value < self.end

    def __eq__(self, other):
        if isinstance(other, ObjectRange):
            return (self.start, self.end) == (other.start, other.end)
        if isinstance(other, range):
            return (self.start, self.end) == (other.start, other.stop)
        if isinstance(other, slice):
            return (self.start, self.end) == (other.start, other.stop)
        if isinstance(other, (tuple, list)) and len(other) == 2:
            return (self.start, self.end) == tuple(other)
        return False

    def __ne__(self, other):
        return not self == other

    __hash__ = None

    def __repr__(self):
        return 'ObjectRange({0}, {1})'.format(self.start, self.end)


class UnitRange(tuple):
    """Two-unit ``(start, end)`` range with tuple/range/slice comparisons."""

    def __new__(cls, start, end=None):
        if end is None and isinstance(start, (tuple, list)) and \
                len(start) == 2:
            start, end = start
        value = tuple.__new__(cls, (start, end))
        value.start = start
        value.end = end
        return value

    def __getnewargs__(self):
        return (self.start, self.end)

    def __eq__(self, other):
        if isinstance(other, UnitRange):
            return tuple(self) == tuple(other)
        if isinstance(other, range):
            return tuple(self) == (other.start, other.stop)
        if isinstance(other, slice):
            return tuple(self) == (other.start, other.stop)
        return tuple.__eq__(self, other)

    def __ne__(self, other):
        return not self == other

    __hash__ = tuple.__hash__


def _as_findings(value):
    """Normalize one stage's finding value to a list."""
    if value is None:
        return []
    if isinstance(value, list):
        return list(value)
    if isinstance(value, (tuple, set, frozenset)):
        # A tuple is commonly one finding such as ("IOC", "url"); a set is
        # usually a collection.  Keep the distinction predictable.
        if isinstance(value, set) or isinstance(value, frozenset):
            return list(value)
        return [value]
    return [value]


def _normalize_findings(findings):
    """
    Return ``(by_category, generic)`` for a findings argument.

    A mapping associates a category with one finding or a list of findings.
    A flat list is kept as generic object-level evidence.  A list of
    ``(category, finding)`` pairs is also accepted.
    """
    by_category = dict((category, []) for category in CATEGORIES)
    generic = []
    if findings is None:
        return by_category, generic
    if isinstance(findings, Mapping):
        for category, value in findings.items():
            by_category[normalize_category(category)].extend(
                _as_findings(value))
        return by_category, generic
    if isinstance(findings, (list, tuple)):
        paired = True
        pairs = []
        for item in findings:
            if not isinstance(item, (list, tuple)) or len(item) != 2:
                paired = False
                break
            try:
                category = normalize_category(item[0])
            except (TypeError, ValueError):
                paired = False
                break
            pairs.append((category, item[1]))
        if paired:
            for category, value in pairs:
                by_category[category].extend(_as_findings(value))
            return by_category, generic
        generic.extend(findings)
        return by_category, generic
    generic.append(findings)
    return by_category, generic


def _normalize_costs(costs):
    """Normalize a cost argument to a category mapping."""
    if costs is None:
        return {}
    if isinstance(costs, (int, float)) and not isinstance(costs, bool):
        return dict((category, costs) for category in CATEGORIES)
    if isinstance(costs, (list, tuple)):
        if len(costs) == len(CATEGORIES):
            return dict(zip(CATEGORIES, costs))
        raise ValueError('cost tuple must contain container, macro and '
                         'attachment values')
    if not isinstance(costs, Mapping):
        raise TypeError('costs must be a number, mapping or 3-tuple')
    result = {}
    for category, value in costs.items():
        result[normalize_category(category)] = value
    return result


def _number(value, what):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError('{0} must be a number, not {1!r}'.format(what, value))
    if value < 0:
        raise ValueError('{0} cannot be negative'.format(what))
    return value


def _findings_dict():
    return dict((category, []) for category in CATEGORIES)


def _costs_dict():
    return dict((category, 0) for category in CATEGORIES)


class ScanObject(object):
    """
    One object that a backend can process.

    Parameters
    ----------
    object_id:
        Stable identifier used by top-ups and resume.  Required unless
        ``filename`` is given.
    data:
        Optional bytes.  When no explicit container cost is supplied, the
        length of ``data`` is used as the container cost.
    costs:
        Number, 3-tuple or mapping with ``container``, ``macro`` and
        ``attachment`` work units.  Values may be callables.
    findings:
        Mapping of stage to finding(s), a flat list of object-level evidence,
        or a list of ``(stage, finding)`` pairs.  These are the findings
        proven once the corresponding stage completes.
    processors:
        Optional mapping of stage to ``callable(object, stage)``.  The
        callable returns a finding, a list of findings, a mapping of stage to
        findings, or ``(findings, units_covered)``.

    Extra keyword arguments ``container_cost``, ``macro_cost`` and
    ``attachment_cost`` are accepted as a convenience.
    """

    def __init__(self, object_id=None, data=None, filename=None,
                 costs=None, findings=None, processors=None, metadata=None,
                 stages=None, **kwargs):
        if object_id is None:
            object_id = kwargs.pop('id', None)
        if object_id is None:
            object_id = filename
        if object_id is None:
            raise ValueError('ScanObject requires object_id or filename')

        self.object_id = object_id
        self.data = data
        self.filename = filename
        self.metadata = dict(metadata or {})
        self.stages = (normalize_categories(stages)
                       if stages is not None else None)

        cost_kwargs = {
            CONTAINER: kwargs.pop('container_cost', None),
            MACRO: kwargs.pop('macro_cost', None),
            ATTACHMENT: kwargs.pop('attachment_cost', None),
        }
        for category in CATEGORIES:
            if category in kwargs:
                cost_kwargs[category] = kwargs.pop(category)
        if kwargs.get('cost') is not None:
            cost_kwargs[CONTAINER] = kwargs.pop('cost')
            cost_kwargs[MACRO] = cost_kwargs[CONTAINER]
            cost_kwargs[ATTACHMENT] = cost_kwargs[CONTAINER]
        if cost_kwargs[CONTAINER] is None and kwargs.get('size') is not None:
            cost_kwargs[CONTAINER] = kwargs.pop('size')
        if kwargs:
            raise TypeError('unexpected ScanObject argument(s): {0}'
                            .format(', '.join(sorted(kwargs))))

        self.costs = _normalize_costs(costs)
        for category, value in cost_kwargs.items():
            if value is not None:
                self.costs[category] = value
        # Convenience: size only implies container work; macro/attachment
        # bytes must be supplied by the caller if they should be charged.
        if data is not None and CONTAINER not in self.costs:
            self.costs[CONTAINER] = len(data)

        self.findings_by_category, self.generic_findings = \
            _normalize_findings(findings)
        self.processors = dict(processors or {})
        self._fingerprint = None

    @property
    def id(self):
        return self.object_id

    @property
    def fingerprint(self):
        """Stable content fingerprint used to validate cached verdicts."""
        if self._fingerprint is None:
            digest = hashlib.sha1()
            digest.update(repr(self.object_id).encode('utf-8', 'replace'))
            digest.update(repr(sorted(self.costs.items())).encode(
                'utf-8', 'replace'))
            digest.update(repr(self.findings_by_category).encode(
                'utf-8', 'replace'))
            digest.update(repr(self.generic_findings).encode(
                'utf-8', 'replace'))
            digest.update(repr(sorted(
                (category, repr(processor))
                for category, processor in self.processors.items()
            )).encode('utf-8', 'replace'))
            if self.data is not None:
                digest.update(self.data)
            self._fingerprint = digest.hexdigest()
        return self._fingerprint

    def cost(self, category):
        """Return the cost for *category*, resolving callable estimates."""
        category = normalize_category(category)
        value = self.costs.get(category, 0)
        if callable(value):
            try:
                value = value(self)
            except TypeError:
                value = value()
        return _number(value, 'cost for {0}'.format(category))

    def processor(self, category):
        return self.processors.get(normalize_category(category))

    def finding_values(self, category):
        return list(self.findings_by_category.get(
            normalize_category(category), []))

    def to_dict(self):
        return {
            'object_id': self.object_id,
            'filename': self.filename,
            'costs': dict(self.costs),
            'findings': dict((category, list(values))
                             for category, values in
                             self.findings_by_category.items()),
            'generic_findings': list(self.generic_findings),
            'metadata': dict(self.metadata),
            'stages': self.stages,
        }

    @classmethod
    def from_dict(cls, value):
        return cls(
            object_id=value.get('object_id', value.get('id')),
            filename=value.get('filename'),
            costs=value.get('costs'),
            findings=value.get('findings'),
            metadata=value.get('metadata'),
            stages=value.get('stages'),
        )

    @classmethod
    def from_any(cls, value):
        if isinstance(value, cls):
            return value
        if isinstance(value, Mapping):
            data = dict(value)
            if 'id' in data and 'object_id' not in data:
                data['object_id'] = data.pop('id')
            return cls(**data)
        if isinstance(value, (tuple, list)) and len(value) == 2:
            return cls(object_id=value[0], costs=value[1])
        raise TypeError('cannot convert {0!r} to ScanObject'
                        .format(value))

    def __repr__(self):
        return 'ScanObject(object_id={0!r}, costs={1!r})'\
            .format(self.object_id, self.costs)


#: Descriptive aliases used by different callers.
OfficeObject = ScanObject
ScanItem = ScanObject


class SyntheticContainer(object):
    """Ordered, in-memory container used for tests and gateway dry-runs."""

    def __init__(self, objects, name=None):
        self.name = name
        self.objects = [ScanObject.from_any(value) for value in objects]
        self._by_id = dict((obj.object_id, obj) for obj in self.objects)
        if len(self._by_id) != len(self.objects):
            raise ValueError('object ids in a container must be unique')

    @property
    def object_ids(self):
        return tuple(obj.object_id for obj in self.objects)

    ids = object_ids

    def append(self, value):
        obj = ScanObject.from_any(value)
        if obj.object_id in self._by_id:
            raise ValueError('duplicate object id {0!r}'.format(obj.object_id))
        self.objects.append(obj)
        self._by_id[obj.object_id] = obj
        return obj

    def get(self, object_id, default=None):
        return self._by_id.get(object_id, default)

    def __iter__(self):
        return iter(self.objects)

    def __len__(self):
        return len(self.objects)

    def __getitem__(self, item):
        if isinstance(item, str):
            return self._by_id[item]
        return self.objects[item]

    def __repr__(self):
        return 'SyntheticContainer(name={0!r}, objects={1!r})'\
            .format(self.name, list(self.object_ids))


class PauseInfo(object):
    """Details about why a scan stopped at an object boundary."""

    def __init__(self, object_id=None, category=None, stage=None,
                 needed=None, available=None, index=None, message=None):
        self.object_id = object_id
        self.category = normalize_category(category)
        self.stage = self.category if stage is None else normalize_category(
            stage)
        self.needed = needed
        self.available = available
        self.index = index
        self.message = message or (
            'insufficient {0} budget for object {1!r}'
            .format(self.category, object_id))

    def to_dict(self):
        return {
            'object_id': self.object_id,
            'category': self.category,
            'stage': self.stage,
            'needed': self.needed,
            'available': self.available,
            'index': self.index,
            'message': self.message,
        }

    def __repr__(self):
        return 'PauseInfo(object_id={0!r}, category={1!r}, needed={2!r}, ' \
               'available={3!r})'.format(self.object_id, self.category,
                                         self.needed, self.available)


class ObjectScanResult(object):
    """Per-object status, findings and accounting."""

    def __init__(self, object_id, status=STATUS_PENDING,
                 findings_by_category=None, generic_findings=None,
                 used=None, limits=None, remaining=None, costs=None,
                 covered_units=None, unprocessed=None, error=None,
                 metadata=None, attempts=0, fingerprint=None, pause=None):
        self.object_id = object_id
        self.status = status
        self.findings_by_category = _findings_dict()
        for category, values in (findings_by_category or {}).items():
            self.findings_by_category[normalize_category(category)] = \
                _as_findings(values)
        self.generic_findings = list(generic_findings or [])
        self.used = dict((category, 0) for category in CATEGORIES)
        self.used.update(used or {})
        self.limits = dict(limits or {})
        self.remaining = dict(remaining or {})
        self.costs = dict((category, 0) for category in CATEGORIES)
        self.costs.update(costs or {})
        self.covered_units = dict((category, 0) for category in CATEGORIES)
        self.covered_units.update(covered_units or {})
        self.unprocessed = {}
        for category, value in (unprocessed or {}).items():
            if isinstance(value, (tuple, list)) and len(value) == 2:
                value = UnitRange(value[0], value[1])
            self.unprocessed[normalize_category(category)] = value
        self.error = error
        self.metadata = dict(metadata or {})
        self.attempts = attempts
        self.fingerprint = fingerprint
        self.pause = pause
        self.covered_categories = set()
        for category in CATEGORIES:
            if category in self.unprocessed:
                continue
            if self.covered_units.get(category, 0) >= \
                    self.costs.get(category, 0):
                if self.costs.get(category, 0) or status == STATUS_COMPLETE:
                    self.covered_categories.add(category)

    @property
    def id(self):
        return self.object_id

    @property
    def complete(self):
        return self.status == STATUS_COMPLETE

    @property
    def partial(self):
        return self.status == STATUS_PARTIAL

    @property
    def pending(self):
        return self.status == STATUS_PENDING

    @property
    def failed(self):
        return self.status == STATUS_ERROR

    @property
    def findings(self):
        """All proven findings, generic evidence first, then stages."""
        result = list(self.generic_findings)
        for category in CATEGORIES:
            result.extend(self.findings_by_category.get(category, []))
        return result

    @property
    def proven(self):
        return self.findings

    evidence = proven

    @property
    def covered(self):
        """Stage names fully covered for this object."""
        return tuple(category for category in CATEGORIES
                     if category in self.covered_categories)

    @property
    def unprocessed_stages(self):
        return tuple(category for category in CATEGORIES
                     if category in self.unprocessed)

    @property
    def unprocessed_range(self):
        """First non-empty unprocessed ``(start, end)`` unit range."""
        for category in CATEGORIES:
            unit_range = self.unprocessed.get(category)
            if unit_range and unit_range[0] != unit_range[1]:
                return unit_range
        return (0, 0)

    @property
    def complete_findings(self):
        """Alias highlighting that only proven findings are included."""
        return self.findings

    def add_findings(self, category, findings):
        self.findings_by_category.setdefault(
            normalize_category(category), []).extend(_as_findings(findings))

    def to_dict(self):
        return {
            'object_id': self.object_id,
            'status': self.status,
            'complete': self.complete,
            'findings': self.findings,
            'generic_findings': list(self.generic_findings),
            'findings_by_category': dict(
                (category, list(values))
                for category, values in self.findings_by_category.items()),
            'covered': self.covered,
            'unprocessed': dict((category, value)
                                for category, value in
                                self.unprocessed.items()),
            'unprocessed_stages': self.unprocessed_stages,
            'unprocessed_range': self.unprocessed_range,
            'used': dict(self.used),
            'limits': dict(self.limits),
            'remaining': dict(self.remaining),
            'costs': dict(self.costs),
            'covered_units': dict(self.covered_units),
            'attempts': self.attempts,
            'error': self.error,
            'metadata': dict(self.metadata),
            'fingerprint': self.fingerprint,
            'pause': self.pause.to_dict() if self.pause is not None else None,
        }

    @classmethod
    def from_dict(cls, value):
        result = cls(
            object_id=value.get('object_id', value.get('id')),
            status=value.get('status', STATUS_PENDING),
            findings_by_category=value.get('findings_by_category'),
            generic_findings=value.get('generic_findings'),
            used=value.get('used'),
            limits=value.get('limits'),
            remaining=value.get('remaining'),
            costs=value.get('costs'),
            covered_units=value.get('covered_units'),
            unprocessed=value.get('unprocessed'),
            error=value.get('error'),
            metadata=value.get('metadata'),
            attempts=value.get('attempts', 0),
            fingerprint=value.get('fingerprint'),
        )
        pause = value.get('pause')
        if pause:
            result.pause = PauseInfo(**pause)
        return result

    def clone(self):
        return copy.deepcopy(self)

    def __getitem__(self, key):
        key = normalize_category(key)
        return list(self.findings_by_category.get(key, []))

    def __repr__(self):
        return 'ObjectScanResult(object_id={0!r}, status={1!r}, ' \
               'findings={2!r})'.format(self.object_id, self.status,
                                        self.findings)


class ScanResult(object):
    """
    Batch result returned by :class:`OfficeScanBackend`.

    Only a leading run of fully completed objects belongs to
    :attr:`covered_prefix`.  A partially processed object keeps its proven
    findings in :attr:`results`, but starts :attr:`unprocessed` because its
    verdict cannot be treated as final.
    """

    def __init__(self, results, status=STATUS_COMPLETE, pause=None,
                 object_specs=None, budget=None, backend=None):
        self.object_results = list(results)
        self.status = status
        self.pause = pause
        self.object_specs = list(object_specs or [])
        self._budget = budget
        self._backend = backend

    @property
    def results(self):
        return self.object_results

    @property
    def objects(self):
        """Alias for :attr:`results`."""
        return self.object_results

    @property
    def results_by_id(self):
        return dict((result.object_id, result)
                    for result in self.object_results)

    def items(self):
        return self.results_by_id.items()

    @property
    def completed(self):
        return dict((result.object_id, result)
                    for result in self.object_results if result.complete)

    @property
    def paused(self):
        return self.status == STATUS_PAUSED

    @property
    def complete(self):
        return self.status == STATUS_COMPLETE

    @property
    def exhausted(self):
        return self.paused

    @property
    def covered_prefix(self):
        """Ids of the leading, fully completed objects."""
        prefix = IdPrefix()
        for result in self.object_results:
            if not result.complete:
                break
            prefix.append(result.object_id)
        return prefix

    @property
    def covered_prefix_count(self):
        return len(self.covered_prefix)

    # Common spelling.
    covered_count = covered_prefix_count

    @property
    def covered(self):
        return self.covered_prefix

    coverage_prefix = covered
    processed_prefix = covered

    @property
    def prefix(self):
        return self.covered_prefix

    @property
    def prefix_count(self):
        return self.covered_prefix_count

    @property
    def covered_range(self):
        return ObjectRange(0, self.covered_prefix_count)

    @property
    def unprocessed_range(self):
        """Index range ``(start, end)`` of objects not fully covered."""
        start = self.covered_prefix_count
        return ObjectRange(start, len(self.object_results))

    @property
    def unprocessed(self):
        """Ids from the first non-complete object to the end of the batch."""
        return IdSequence(result.object_id
                          for result in self.object_results[
                              self.covered_prefix_count:])

    @property
    def pending(self):
        """Ids that have not reached a final verdict."""
        return tuple(result.object_id for result in self.object_results
                     if not result.complete)

    @property
    def remaining(self):
        return self.pending

    unprocessed_objects = unprocessed

    @property
    def partial(self):
        return tuple(result.object_id for result in self.object_results
                     if result.partial)

    @property
    def failed(self):
        return tuple(result.object_id for result in self.object_results
                     if result.failed)

    @property
    def paused_on(self):
        return self.pause.object_id if self.pause is not None else None

    paused_at = paused_on

    @property
    def budget_exhausted(self):
        return self.paused

    @property
    def stop_reason(self):
        return 'budget' if self.paused else None

    @property
    def next_object(self):
        unprocessed = self.unprocessed
        return unprocessed[0] if unprocessed else None

    @property
    def covered_by_category(self):
        return dict(
            (category, tuple(result.object_id
                             for result in self.object_results
                             if category in result.covered_categories))
            for category in CATEGORIES
        )

    @property
    def unprocessed_by_category(self):
        return dict(
            (category, tuple(result.object_id
                             for result in self.object_results
                             if category not in result.covered_categories))
            for category in CATEGORIES
        )

    @property
    def coverage(self):
        """Stage-level coverage for every object."""
        return dict(
            (result.object_id,
             dict((category, {
                 'covered': result.covered_units.get(category, 0),
                 'cost': result.costs.get(category, 0),
                 'unprocessed': result.unprocessed.get(category),
             }) for category in CATEGORIES))
            for result in self.object_results
        )

    @property
    def budget(self):
        return self._budget.snapshot() if self._budget is not None else None

    budget_state = budget

    @property
    def budget_object(self):
        return self._budget

    @property
    def state(self):
        return self

    @property
    def findings(self):
        return dict((result.object_id, result.findings)
                    for result in self.object_results)

    def get(self, object_id, default=None):
        return self.results_by_id.get(object_id, default)

    def __getitem__(self, item):
        if isinstance(item, str):
            return self.results_by_id[item]
        return self.object_results[item]

    def __iter__(self):
        return iter(self.object_results)

    def __len__(self):
        return len(self.object_results)

    def resume(self, top_ups=None, budget=None, objects=None, targets=None):
        """Resume this scan, optionally with a new budget/top-ups."""
        if self._backend is None:
            backend = OfficeScanBackend()
        else:
            backend = self._backend
        return backend.resume(self, top_ups=top_ups, budget=budget,
                              objects=objects, targets=targets)

    def to_dict(self):
        return {
            'status': self.status,
            'complete': self.complete,
            'paused': self.paused,
            'covered_prefix': list(self.covered_prefix),
            'covered_prefix_count': self.covered_prefix_count,
            'unprocessed': list(self.unprocessed),
            'pending': list(self.pending),
            'remaining': list(self.remaining),
            'unprocessed_range': list(self.unprocessed_range),
            'pause': self.pause.to_dict() if self.pause is not None else None,
            'objects': [result.to_dict() for result in self.object_results],
            'object_specs': [spec.to_dict() for spec in self.object_specs],
            'budget': self.budget,
        }

    @classmethod
    def from_dict(cls, value):
        results = [ObjectScanResult.from_dict(item)
                   for item in value.get('objects', value.get('results', []))]
        specs = [ScanObject.from_dict(item)
                 for item in value.get('object_specs', [])]
        pause_value = value.get('pause')
        pause = PauseInfo(**pause_value) if pause_value else None
        return cls(
            results=results,
            status=value.get('status', STATUS_COMPLETE),
            pause=pause,
            object_specs=specs,
        )

    def __repr__(self):
        return 'ScanResult(status={0!r}, covered_prefix={1!r}, ' \
               'unprocessed={2!r})'.format(self.status, self.covered_prefix,
                                           self.unprocessed)


# The scanner uses a distinct word here to avoid confusing a result status
# with the object-level status constants.
STATUS_PAUSED = 'paused'


class OfficeScanBackend(object):
    """
    Object-boundary scanner with independent container/macro/attachment
    accounting.

    Parameters
    ----------
    stages:
        Optional ordered stage subset.  Defaults to all three stages.
    cost_unit:
        Informational label included in repr/JSON, e.g. ``"bytes"``.
    """

    def __init__(self, stages=None, cost_unit='work-unit'):
        self.stages = (normalize_categories(stages)
                       if stages is not None else STAGE_ORDER)
        self.cost_unit = cost_unit

    def scan(self, container=None, budget=None, state=None, top_ups=None,
             preserve_completed=True, objects=None, targets=None):
        """
        Scan *container* and return a :class:`ScanResult`.

        ``container`` may be a :class:`SyntheticContainer`, an iterable of
        :class:`ScanObject`/mappings, or a single object.
        ``state`` may be an earlier :class:`ScanResult` (or its ``to_dict``
        output) to resume from.
        """
        if container is None:
            container = objects
        if isinstance(budget, Mapping):
            budget = ScanBudget(budget)
        specs = self._normalize_container(container)
        if budget is None:
            budget = ScanBudget()
        elif not isinstance(budget, ScanBudget):
            raise TypeError('budget must be a ScanBudget')

        prior = self._prior_results(state, preserve_completed)
        if top_ups is not None:
            self._apply_top_ups(budget, top_ups, state)
        if targets is not None:
            targets = set(targets)

        results = []
        for index, spec in enumerate(specs):
            previous = prior.get(spec.object_id)
            if previous is not None and \
                    previous.fingerprint not in (None, spec.fingerprint):
                # Same id, different content: do not reuse a stale verdict.
                previous = None

            result = ObjectScanResult(
                object_id=spec.object_id,
                status=STATUS_PENDING,
                metadata=spec.metadata,
                fingerprint=spec.fingerprint,
            )
            account = budget.account_for(spec.object_id)
            self._fill_account_view(result, account, spec)

            stages = spec.stages if spec.stages is not None else self.stages
            if targets is not None and spec.object_id not in targets:
                if previous is not None:
                    results.append(previous.clone())
                else:
                    results.append(self._pending_results([spec], budget)[0])
                continue
            if previous is not None and previous.complete:
                # Completed verdicts are immutable.  Reuse them even if the
                # batch budget changed, so a top-up for another object cannot
                # alter what was already proven here.
                result = previous.clone()
                results.append(result)
                continue

            if previous is not None:
                result = previous.clone()
                result.attempts = previous.attempts + 1
                result.pause = None
                if result.status == STATUS_ERROR:
                    result.status = STATUS_PARTIAL
            else:
                result.attempts = 1

            for stage in stages:
                category = normalize_category(stage)
                if category in result.covered_categories:
                    continue

                cost = spec.cost(category)
                result.costs[category] = cost
                already = result.covered_units.get(category, 0)
                remaining_cost = max(0, cost - already)
                account = budget.account_for(spec.object_id)
                self._fill_account_view(result, account, spec)

                if not account.can_afford(category, remaining_cost):
                    available = account.remaining(category)
                    needed = (remaining_cost if available is None
                              else remaining_cost - available)
                    result.unprocessed[category] = UnitRange(already, cost)
                    self._mark_rest_unprocessed(result, spec, stages,
                                                category)
                    result.status = (STATUS_PARTIAL
                                     if (result.findings or
                                         result.covered_categories)
                                     else STATUS_PENDING)
                    pause = PauseInfo(
                        object_id=spec.object_id,
                        category=category,
                        stage=category,
                        needed=needed,
                        available=available,
                        index=index,
                    )
                    result.pause = pause
                    results.append(result)
                    results.extend(self._pending_results(
                        specs[index + 1:], budget))
                    return self._result(results, STATUS_PAUSED, pause,
                                        specs, budget)

                if remaining_cost:
                    account.charge(category, remaining_cost)
                self._fill_account_view(result, account, spec)
                result.used[category] = result.used.get(category, 0) + \
                    remaining_cost
                result.covered_units[category] = already + remaining_cost
                result.unprocessed.pop(category, None)

                try:
                    produced, covered = self._run_processor(
                        spec, category, result)
                except BudgetExhausted as exc:
                    consumed = exc.consumed
                    if consumed is None:
                        consumed = 0
                    consumed = min(max(0, consumed), remaining_cost)
                    if consumed != remaining_cost:
                        account.refund(category,
                                       remaining_cost - consumed)
                        result.used[category] = \
                            result.used.get(category, 0) - \
                            (remaining_cost - consumed)
                    result.covered_units[category] = already + consumed
                    exc_findings = getattr(exc, 'findings', None)
                    if exc_findings is not None:
                        result.add_findings(category, exc_findings)
                    result.unprocessed[category] = UnitRange(
                        already + consumed, cost)
                    self._mark_rest_unprocessed(result, spec, stages,
                                                category)
                    result.status = (STATUS_PARTIAL
                                     if (result.findings or
                                         result.covered_categories)
                                     else STATUS_PENDING)
                    pause = PauseInfo(
                        object_id=spec.object_id,
                        category=category,
                        stage=category,
                        needed=cost - (already + consumed),
                        available=account.remaining(category),
                        index=index,
                    )
                    result.pause = pause
                    results.append(result)
                    results.extend(self._pending_results(
                        specs[index + 1:], budget))
                    return self._result(results, STATUS_PAUSED, pause,
                                        specs, budget)
                except Exception as exc:  # keep other objects scannable
                    result.error = '{0}: {1}'.format(
                        type(exc).__name__, exc)
                    result.unprocessed[category] = UnitRange(already, cost)
                    self._mark_rest_unprocessed(result, spec, stages,
                                                category)
                    result.status = STATUS_ERROR
                    break

                if produced is not None:
                    self._merge_findings(result, category, produced)
                if covered is not None:
                    covered = min(cost, max(0, covered))
                    result.covered_units[category] = covered
                    if covered < cost:
                        if remaining_cost > covered - already:
                            new_units = max(0, covered - already)
                            unused = max(0, remaining_cost - new_units)
                            account.refund(category, unused)
                            result.used[category] = \
                                result.used.get(category, 0) - unused
                        result.unprocessed[category] = UnitRange(covered, cost)
                        self._mark_rest_unprocessed(result, spec, stages,
                                                    category)
                        result.status = (STATUS_PARTIAL
                                         if (result.findings or
                                             result.covered_categories)
                                         else STATUS_PENDING)
                        pause = PauseInfo(
                            object_id=spec.object_id,
                            category=category,
                            stage=category,
                            needed=cost - covered,
                            available=account.remaining(category),
                            index=index,
                        )
                        result.pause = pause
                        self._fill_account_view(result, account, spec)
                        results.append(result)
                        results.extend(self._pending_results(
                            specs[index + 1:], budget))
                        return self._result(results, STATUS_PAUSED, pause,
                                            specs, budget)
                self._fill_account_view(result, account, spec)
                result.covered_categories.add(category)
                result.unprocessed.pop(category, None)

            if result.status != STATUS_ERROR:
                if all(category in result.covered_categories
                       for category in stages):
                    result.status = STATUS_COMPLETE
                    for finding in spec.generic_findings:
                        if finding not in result.generic_findings:
                            result.generic_findings.append(finding)
                elif result.findings or result.covered_categories:
                    result.status = STATUS_PARTIAL
                else:
                    result.status = STATUS_PENDING
            results.append(result)

        incomplete = [result for result in results if not result.complete]
        if not incomplete:
            return self._result(results, STATUS_COMPLETE, None, specs,
                                budget)
        pause = incomplete[0].pause
        if pause is None:
            stages_left = incomplete[0].unprocessed_stages
            pause = PauseInfo(
                object_id=incomplete[0].object_id,
                category=stages_left[0] if stages_left else None,
                needed=None,
                available=incomplete[0].remaining.get(
                    stages_left[0]) if stages_left else None,
                index=results.index(incomplete[0]),
            )
        return self._result(results, STATUS_PAUSED, pause, specs, budget)

    # Convenient aliases for gateway/backend integrations.
    process = scan
    scan_container = scan
    process_container = scan

    def resume(self, previous, top_ups=None, budget=None, objects=None,
               targets=None):
        """Resume a previous result, optionally applying targeted top-ups."""
        if isinstance(previous, Mapping):
            previous = ScanResult.from_dict(previous)
        if not isinstance(previous, ScanResult):
            raise TypeError('previous must be a ScanResult or its dict form')
        if budget is None:
            budget = previous._budget
        if budget is None:
            budget = ScanBudget()
        specs = objects if objects is not None else previous.object_specs
        if not specs:
            raise ValueError('cannot resume without object specifications')
        if targets is None:
            topped_ids = self._top_up_object_ids(top_ups)
            first_pending = previous.next_object
            if topped_ids and first_pending not in topped_ids:
                targets = topped_ids
        return self.scan(specs, budget, state=previous, top_ups=top_ups,
                         targets=targets)

    def _normalize_container(self, container):
        if isinstance(container, SyntheticContainer):
            return list(container)
        if isinstance(container, ScanObject):
            return [container]
        if isinstance(container, Mapping):
            object_keys = set(('id', 'object_id', 'costs',
                               'findings', 'processors',
                               'metadata', 'filename', 'data',
                               'stages'))
            if object_keys.intersection(container):
                return [ScanObject.from_any(container)]
            return [ScanObject.from_any({'id': key, 'costs': value})
                    for key, value in container.items()]
        try:
            return [ScanObject.from_any(value) for value in container]
        except TypeError:
            return [ScanObject.from_any(container)]

    @staticmethod
    def _prior_results(state, preserve_completed):
        if state is None:
            return {}
        if isinstance(state, Mapping):
            state = ScanResult.from_dict(state)
        if isinstance(state, ScanResult):
            values = state.object_results
        elif isinstance(state, ObjectScanResult):
            values = [state]
        else:
            values = state
        prior = {}
        for result in values:
            if not isinstance(result, ObjectScanResult):
                result = ObjectScanResult.from_dict(result)
            if preserve_completed or not result.complete:
                prior[result.object_id] = result
        return prior

    @staticmethod
    def _fill_account_view(result, account, spec):
        for category in CATEGORIES:
            result.limits[category] = account.limits.get(category)
            result.remaining[category] = account.remaining(category)
        for category in CATEGORIES:
            result.costs.setdefault(category, spec.cost(category))

    @staticmethod
    def _mark_rest_unprocessed(result, spec, stages, from_category):
        found = False
        for stage in stages:
            category = normalize_category(stage)
            if category == from_category:
                found = True
            if not found:
                continue
            if category not in result.unprocessed:
                start = result.covered_units.get(category, 0)
                result.unprocessed[category] = UnitRange(
                    start, spec.cost(category))

    @staticmethod
    def _pending_results(specs, budget):
        results = []
        for spec in specs:
            account = budget.account_for(spec.object_id)
            result = ObjectScanResult(
                object_id=spec.object_id,
                status=STATUS_PENDING,
                metadata=spec.metadata,
                fingerprint=spec.fingerprint,
            )
            OfficeScanBackend._fill_account_view(result, account, spec)
            for stage in (spec.stages or STAGE_ORDER):
                category = normalize_category(stage)
                result.unprocessed[category] = UnitRange(
                    0, spec.cost(category))
            results.append(result)
        return results

    def _run_processor(self, spec, category, result):
        processor = spec.processor(category)
        if processor is None:
            return list(spec.finding_values(category)), None
        produced = processor(spec, category)
        covered = None
        if (isinstance(produced, tuple) and len(produced) == 2 and
                isinstance(produced[1], (int, float)) and
                not isinstance(produced[1], bool)):
            produced, covered = produced
        return produced, covered

    def _merge_findings(self, result, stage, produced):
        if produced is None:
            return
        if isinstance(produced, Mapping):
            for category, value in produced.items():
                category = normalize_category(category)
                result.add_findings(category, value)
            return
        result.add_findings(stage, produced)

    def _result(self, results, status, pause, specs, budget):
        return ScanResult(
            results=results,
            status=status,
            pause=pause,
            object_specs=specs,
            budget=budget,
            backend=self,
        )

    @staticmethod
    def _apply_top_ups(budget, top_ups, previous):
        if top_ups is None:
            return
        if callable(top_ups):
            top_ups(budget)
            return

        pause = getattr(previous, 'pause', None)
        paused_category = pause.category if pause is not None else None
        items = top_ups.items() if isinstance(top_ups, Mapping) else top_ups
        for item in items:
            if isinstance(item, Mapping):
                object_id = item.get('object_id', item.get('id'))
                category = item.get('category', item.get('stage'))
                amount = item.get('amount')
                if amount is not None:
                    budget.top_up(object_id, category, amount)
                else:
                    quota = dict(
                        (key, value) for key, value in item.items()
                        if key not in ('object_id', 'id', 'category',
                                       'stage', 'amount')
                    )
                    budget.top_up(object_id, **quota)
                continue

            if isinstance(item, (list, tuple)) and len(item) == 3:
                object_id, category, amount = item
                budget.top_up(object_id, category, amount)
                continue

            key, value = item
            if isinstance(key, tuple):
                object_id, category = key
                budget.top_up(object_id, category, value)
            elif isinstance(value, Mapping):
                budget.top_up(key, **value)
            elif isinstance(key, str):
                try:
                    category = normalize_category(key)
                except (TypeError, ValueError):
                    category = paused_category
                if category is key or category is not None:
                    # The key was itself a category: top up the shared pool.
                    if category == key:
                        budget.top_up(None, category, value)
                        continue
                budget.top_up(key, category, value)
            else:
                raise TypeError('unsupported top-up entry {0!r}'
                                .format(item))

    @staticmethod
    def _top_up_object_ids(top_ups):
        """Infer object ids referenced by a top-up mapping/sequence."""
        if top_ups is None or callable(top_ups):
            return set()
        items = top_ups.items() if isinstance(top_ups, Mapping) else top_ups
        result = set()
        for item in items:
            if isinstance(item, Mapping):
                object_id = item.get('object_id', item.get('id'))
                if object_id is not None:
                    result.add(object_id)
                continue
            if isinstance(item, (list, tuple)) and len(item) == 3:
                result.add(item[0])
                continue
            key, value = item
            if isinstance(key, tuple):
                result.add(key[0])
            elif isinstance(key, str):
                try:
                    normalize_category(key)
                except (TypeError, ValueError):
                    result.add(key)
        return result


#: Alternative spelling used in some gateway integrations.
OletoolsBackend = OfficeScanBackend
ScanBackend = OfficeScanBackend
OletoolsScanBackend = OfficeScanBackend
ScanBatchBackend = OfficeScanBackend
OfficeScanner = OfficeScanBackend
OletoolsScanner = OfficeScanBackend
Scanner = OfficeScanBackend
ScanSession = OfficeScanBackend


def scan_objects(objects, budget=None, stages=None, state=None, top_ups=None):
    """Convenience wrapper around :meth:`OfficeScanBackend.scan`."""
    return OfficeScanBackend(stages=stages).scan(
        objects, budget=budget, state=state, top_ups=top_ups)


scan_container = scan_objects
process_objects = scan_objects
scan_batch = scan_objects
scan = scan_objects
scan_documents = scan_objects
process = scan_objects


__all__ = [
    'ATTACHMENT',
    'CATEGORIES',
    'CONTAINER',
    'MACRO',
    'BudgetAccount',
    'BudgetCategory',
    'BudgetError',
    'BudgetExhausted',
    'ObjectScanResult',
    'OfficeObject',
    'OfficeScanBackend',
    'OfficeScanner',
    'OletoolsBackend',
    'OletoolsScanBackend',
    'OletoolsScanner',
    'PauseInfo',
    'STATUS_COMPLETE',
    'STATUS_ERROR',
    'STATUS_PARTIAL',
    'STATUS_PAUSED',
    'STATUS_PENDING',
    'ScanBackend',
    'ScanBatchBackend',
    'ScanSession',
    'ScanBudget',
    'ScanItem',
    'ScanObject',
    'ScanResult',
    'Scanner',
    'SyntheticContainer',
    'process_objects',
    'process',
    'scan',
    'scan_container',
    'scan_batch',
    'scan_documents',
    'scan_objects',
]
