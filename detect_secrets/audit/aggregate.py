"""
Offline aggregation and disclosure review for audited secrets.

This module deliberately does not talk to any external service.  It takes
baselines (or already-aggregated reports), applies existing manual decisions
and team boundaries, and decides whether a set of group counts may be released.

Two constraints are applied to every release:

1. A group is only included when it contains at least ``minimum_group_size``
   distinct people.
2. A group may not be differenced against a previously released (or historical)
   report to reveal a sub-threshold number of people.

The second constraint is why release history matters.  Two individually safe
reports can still disclose a single person's change when one is subtracted from
the other.  A release request therefore has to be checked against every report
that has already been exposed.  Merging groups into a new, coarser disclosure
scope intentionally prevents that sub-group differencing.
"""
import fnmatch
import hashlib
import json
import os
from collections import defaultdict
from dataclasses import dataclass
from dataclasses import field
from typing import Any
from typing import Dict
from typing import Iterable
from typing import List
from typing import Mapping
from typing import Optional
from typing import Sequence
from typing import Set
from typing import Tuple
from typing import Union


DEFAULT_GROUP = 'unassigned'
DEFAULT_MINIMUM_GROUP_SIZE = 5

_PERSON_FIELDS = (
    'person',
    'owner',
    'author',
    'author_email',
    'author_name',
    'owner_email',
    'owner_name',
    'user',
    'user_id',
    'username',
    'login',
    'principal',
    'identity',
    'identity_id',
    'email',
    'email_address',
    'actor',
    'assignee',
    'developer',
    'employee',
    'account_id',
    'created_by',
)

_GROUP_FIELDS = (
    'group',
    'team',
    'team_name',
    'team_id',
    'owner_team',
    'group_name',
    'org',
    'organization',
    'department',
    'business_unit',
)

_ALERT_LIST_FIELDS = (
    'alerts',
    'findings',
    'records',
    'items',
    'decisions',
)

_MINIMUM_GROUP_SIZE_FIELDS = (
    'minimum_group_size',
    'min_group_size',
    'minimumGroupSize',
    'minimum_count',
    'min_count',
    'minimum_people',
    'threshold',
    'k',
)

_DECISION_FIELDS = (
    'is_secret',
    'isSecret',
    'decision',
    'label',
    'manual_decision',
    'manualDecision',
    'adjudication',
    'status',
    'value',
)

_HISTORY_FIELDS = (
    'history',
    'reports',
    'versions',
    'historical_reports',
    'historical_versions',
    'previous_reports',
    'previous_versions',
    'prior_reports',
    'past_reports',
    'published_reports',
    'delayed_reports',
    'pending_reports',
    'checked_out_versions',
    'checkouts',
    'signed_versions',
)


@dataclass
class Alert:
    alert_id: str
    person: str
    filename: str
    is_secret: Optional[bool] = None
    group: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GroupCount:
    name: str
    count: int
    people: Set[str] = field(default_factory=set)
    alert_ids: Set[str] = field(default_factory=set)

    @property
    def people_count(self) -> int:
        return len(self.people)


@dataclass
class HistoricalReport:
    report_id: str
    digest: str
    groups: List[GroupCount]


def aggregate(
    *sources: Union[str, os.PathLike, Mapping[str, Any], Sequence[Any]],
    team_boundaries: Optional[Union[str, os.PathLike, Mapping[str, Any]]] = None,
    minimum_group_size: Optional[int] = None,
    min_group_size: Optional[int] = None,
    history: Optional[Union[str, os.PathLike, Mapping[str, Any], Sequence[Any]]] = None,
    previous_reports: Optional[Union[str, os.PathLike, Mapping[str, Any], Sequence[Any]]] = None,
    report_id: Optional[str] = None,
    merge_groups: Optional[Any] = None,
    include_unlabelled: bool = False,
    **kwargs: Any,
) -> Dict[str, Any]:
    """
    Build an offline aggregate and review it for public release.

    ``sources`` may be baseline paths, parsed baselines, audit bundles, or
    already-aggregated reports.  At least one source is required, unless the
    caller supplies ``alerts``/``groups`` through keyword arguments.

    The return value contains two deliberately separate views:

    * ``external`` (also available as ``report``): the only data permitted to
      leave the review boundary.
    * ``receipt`` (also available as ``internal``): the restricted groups and
      the historical report identities that caused those restrictions.
    """
    if 'alerts' in kwargs or 'groups' in kwargs:
        inline: Dict[str, Any] = {
            key: kwargs[key]
            for key in (
                'alerts',
                'groups',
                'results',
                'teams',
                'team_boundaries',
                'report_id',
            )
            if key in kwargs
        }
        sources = (*sources, inline)

    if not sources:
        raise ValueError('At least one baseline, report, or alert source is required.')

    if team_boundaries is None:
        team_boundaries = (
            kwargs.get('boundaries')
            or kwargs.get('team_config')
            or kwargs.get('teams')
        )
    if report_id is None:
        report_id = kwargs.get('release_id')
    if merge_groups is None:
        merge_groups = (
            kwargs.get('merged_groups')
            or kwargs.get('group_merges')
            or kwargs.get('group_merge')
        )
    if history is None:
        for key in (
            'release_history',
            'historical_reports',
            'historical_versions',
            'prior_reports',
            'previous_versions',
        ):
            if kwargs.get(key) is not None:
                history = kwargs[key]
                break
    if min_group_size is not None:
        minimum_group_size = min_group_size
    for key in (
        'minimum_people',
        'min_people',
        'minimum_count',
        'min_count',
        'threshold',
        'k',
    ):
        if minimum_group_size is None and kwargs.get(key) is not None:
            minimum_group_size = _optional_int(kwargs[key])
    if previous_reports is not None:
        if history is not None:
            history = _as_list(history) + _as_list(previous_reports)
        else:
            history = previous_reports

    normalized_sources = _normalize_sources(sources)
    if not normalized_sources:
        raise ValueError('At least one baseline, report, or alert source is required.')

    boundaries_data: Any = team_boundaries
    source_report_id: Optional[str] = None
    source_groups: Optional[List[GroupCount]] = None
    embedded_history: List[Any] = []
    alerts: List[Alert] = []
    decisions: Dict[str, bool] = {}
    source_digests: List[str] = []

    for source in normalized_sources:
        payload = _load_source(source)
        if payload is None:
            continue

        source_digests.append(_digest(payload))
        source_report_id = source_report_id or _payload_report_id(payload)

        if boundaries_data is None:
            boundaries_data = _first_value(
                payload,
                ('team_boundaries', 'teamBoundaries', 'boundaries', 'teams', 'groups'),
            )

        embedded_history.extend(_history_from_payload(payload))

        payload_alerts, payload_decisions, payload_groups = _alerts_from_payload(payload)
        alerts.extend(payload_alerts)
        decisions.update(payload_decisions)
        if payload_groups:
            source_groups = payload_groups

        if minimum_group_size is None:
            minimum_group_size = _optional_int(
                _first_value(
                    payload,
                    _MINIMUM_GROUP_SIZE_FIELDS,
                ),
            )

    alerts = _apply_decisions(alerts, decisions)
    if boundaries_data is None and normalized_sources:
        boundaries_data = _boundaries_embedded_in_team_argument(normalized_sources)

    boundaries = TeamBoundaries.from_data(boundaries_data)
    threshold = (
        minimum_group_size
        if minimum_group_size is not None
        else boundaries.minimum_group_size
    )
    if threshold is None:
        threshold = DEFAULT_MINIMUM_GROUP_SIZE
    if threshold < 1:
        raise ValueError('minimum_group_size must be greater than zero.')

    effective_merge_groups = _merge_group_mapping(
        merge_groups if merge_groups is not None else boundaries.merge_groups,
    )
    if source_groups is not None and not alerts:
        groups = _clone_groups(source_groups, effective_merge_groups)
    else:
        alerts = _filter_alerts(alerts, include_unlabelled=include_unlabelled)
        groups = _aggregate_alerts(alerts, boundaries, effective_merge_groups)

    history_items = _dedupe_items(_as_list(history) + embedded_history)
    historical_reports = _load_history(
        history_items,
        boundaries=boundaries,
        merge_groups=effective_merge_groups,
        include_unlabelled=include_unlabelled,
    )

    resolved_report_id = (
        report_id
        or source_report_id
        or _digest({
            'sources': source_digests,
            'groups': _groups_for_digest(groups),
        })
    )

    external_groups: List[Dict[str, Any]] = []
    restricted_groups: List[Dict[str, Any]] = []
    blocked = False

    for group in sorted(groups, key=lambda item: (item.name, sorted(item.people))):
        reasons: List[Dict[str, Any]] = []
        if group.people_count < threshold:
            reasons.append({
                'code': 'below_minimum_group_size',
                'minimum_group_size': threshold,
                'contributors': group.people_count,
            })

        difference = None
        if group.people_count >= threshold:
            difference = _find_differencing_risk(group, historical_reports, threshold)
        if difference is not None:
            reasons.append(difference)
            blocked = True

        if reasons:
            restricted_groups.append({
                'group': group.name,
                'count': group.count,
                'contributors': group.people_count,
                'reasons': reasons,
                'history_report_ids': _history_ids_from_reasons(reasons),
            })
        else:
            external_groups.append({
                'group': group.name,
                'count': group.count,
                'contributors': group.people_count,
            })

    external: Dict[str, Any] = {
        'report_id': str(resolved_report_id),
        'groups': external_groups,
        'results': external_groups,
        'group_counts': {
            item['group']: item['count']
            for item in external_groups
        },
        'counts': {
            item['group']: item['count']
            for item in external_groups
        },
        'approved_groups': external_groups,
    }

    history_report_ids: List[str] = []
    for report in historical_reports:
        if report.report_id not in history_report_ids:
            history_report_ids.append(report.report_id)
    receipt: Dict[str, Any] = {
        'report_id': str(resolved_report_id),
        'minimum_group_size': threshold,
        'restricted_groups': restricted_groups,
        'history_report_ids': history_report_ids,
        'history_reports': [
            {
                'report_id': report.report_id,
                'digest': report.digest,
                'groups': [
                    {
                        'group': group.name,
                        'count': group.count,
                        'contributors': group.people_count,
                    }
                    for group in report.groups
                ],
            }
            for report in historical_reports
        ],
    }
    receipt['history'] = history_report_ids
    receipt['historical_report_ids'] = history_report_ids
    receipt['blocked_groups'] = restricted_groups
    receipt['limited_groups'] = restricted_groups
    receipt['suppressed_groups'] = restricted_groups
    receipt['restricted_group_names'] = [
        item['group'] for item in restricted_groups
    ]

    status = 'blocked' if blocked else 'approved'
    return {
        'approved': not blocked,
        'allowed': not blocked,
        'releasable': not blocked,
        'can_release': not blocked,
        'can_publish': not blocked,
        'status': status,
        'approval_status': 'approved' if not blocked else 'rejected',
        'release_status': status,
        'decision': 'allow' if not blocked else 'deny',
        'report_id': str(resolved_report_id),
        'report': external,
        'external': external,
        'external_report': external,
        'public': external,
        'receipt': receipt,
        'internal': receipt,
        'internal_receipt': receipt,
        'restricted_groups': restricted_groups,
        'blocked_groups': restricted_groups,
        'history_report_ids': history_report_ids,
    }


def aggregate_baselines(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    """Compatibility alias for :func:`aggregate`."""
    return aggregate(*args, **kwargs)


def generate_aggregate_report(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    """Compatibility alias for :func:`aggregate`."""
    return aggregate(*args, **kwargs)


def build_aggregate_report(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    """Compatibility alias for :func:`aggregate`."""
    return aggregate(*args, **kwargs)


def review_release(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    """Alias used by callers that treat aggregation as a release review."""
    return aggregate(*args, **kwargs)


def build_report(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    """Compatibility alias for aggregate."""
    return aggregate(*args, **kwargs)


def aggregate_alerts(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    """Compatibility alias for aggregate."""
    return aggregate(*args, **kwargs)


def review_publication(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    """Alias used by callers that treat aggregation as a publication review."""
    return aggregate(*args, **kwargs)


def summarize_alerts(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    """Compatibility alias for :func:`aggregate`."""
    return aggregate(*args, **kwargs)


class TeamBoundaries:
    """Resolve an alert to a disclosure group using people and file boundaries."""

    def __init__(self) -> None:
        self.person_to_group: Dict[str, str] = {}
        self.file_rules: List[Tuple[str, str]] = []
        self.group_members: Dict[str, Set[str]] = defaultdict(set)
        self.merge_groups: Any = None
        self.minimum_group_size: Optional[int] = None

    @classmethod
    def from_data(cls, data: Any) -> 'TeamBoundaries':
        output = cls()
        if data is None:
            return output

        if isinstance(data, str):
            stripped = data.lstrip()
            if stripped.startswith('{') or stripped.startswith('['):
                data = json.loads(data)
            else:
                data = _read_json(data)
        elif isinstance(data, os.PathLike):
            data = _read_json(str(data))

        if isinstance(data, list):
            output._load_team_list(data)
            return output

        if not isinstance(data, Mapping):
            return output

        payload: Mapping[str, Any] = data
        output.minimum_group_size = _optional_int(
            _first_value(
                payload,
                _MINIMUM_GROUP_SIZE_FIELDS,
            ),
        )
        output.merge_groups = _first_value(
            payload,
            ('merge_groups', 'mergeGroups', 'merged_groups', 'merge'),
        )

        teams = _first_value(
            payload,
            ('teams', 'groups', 'team_boundaries', 'teamBoundaries', 'boundaries'),
        )
        if teams is not None:
            output._load_team_container(teams)

        owner_map = _first_value(
            payload,
            ('owners', 'people', 'identities', 'members', 'person_to_group'),
        )
        if isinstance(owner_map, Mapping):
            output._load_person_map(owner_map)

        file_map = _first_value(
            payload,
            ('files', 'paths', 'filenames', 'file_to_group'),
        )
        if isinstance(file_map, Mapping):
            output._load_file_map(file_map)

        if not teams and not owner_map and not file_map:
            output._load_team_container(payload)

        return output

    def _load_team_container(self, teams: Any) -> None:
        if isinstance(teams, list):
            self._load_team_list(teams)
            return

        if not isinstance(teams, Mapping):
            return

        # Either {group: [members]} or a flat owner/file -> group map.
        if teams and all(isinstance(value, str) for value in teams.values()):
            for owner_or_file, group in teams.items():
                self._add_member(str(owner_or_file), str(group))
                self.file_rules.append((str(owner_or_file), str(group)))
            return

        for group, value in teams.items():
            if isinstance(value, str):
                self._add_member(str(value), str(group))
                continue

            if isinstance(value, Mapping):
                members = _first_value(
                    value,
                    ('members', 'people', 'users', 'identities', 'owners'),
                )
                if members is not None:
                    self._add_members(group, members)

                files = _first_value(value, ('files', 'paths', 'filenames'))
                if files is not None:
                    self._add_files(group, files)

                if 'minimum_group_size' in value or 'min_group_size' in value:
                    self.minimum_group_size = _optional_int(
                        _first_value(value, _MINIMUM_GROUP_SIZE_FIELDS),
                    )
            elif isinstance(value, Iterable):
                self._add_members(group, value)

    def _load_team_list(self, teams: Sequence[Any]) -> None:
        for item in teams:
            if not isinstance(item, Mapping):
                continue

            group = _first_string(item, ('group', 'team', 'name', 'id'))
            if not group:
                continue

            members = _first_value(
                item,
                ('members', 'people', 'users', 'identities', 'owners'),
            )
            if members is not None:
                self._add_members(group, members)

            files = _first_value(item, ('files', 'paths', 'filenames'))
            if files is not None:
                self._add_files(group, files)

    def _load_person_map(self, mapping: Mapping[Any, Any]) -> None:
        for person, group in mapping.items():
            if isinstance(group, str):
                self._add_member(str(person), group)

    def _load_file_map(self, mapping: Mapping[Any, Any]) -> None:
        for filename, group in mapping.items():
            if isinstance(group, str):
                self.file_rules.append((str(filename), group))

    def _add_members(self, group: Any, members: Any) -> None:
        if isinstance(members, str):
            members = [members]
        elif isinstance(members, int):
            members = [f'{group}:member:{index}' for index in range(members)]
        for person in members:
            self._add_member(str(person), str(group))

    def _add_member(self, person: str, group: str) -> None:
        self.person_to_group[person] = group
        self.person_to_group[person.lower()] = group
        self.person_to_group[person.lower().split('@', 1)[0]] = group
        self.group_members[group].add(person)

    def _add_files(self, group: Any, files: Any) -> None:
        if isinstance(files, str):
            files = [files]
        for filename in files:
            self.file_rules.append((str(filename), str(group)))

    def resolve(self, alert: Alert) -> str:
        if alert.group:
            return alert.group

        group = self._lookup_person(alert.person)
        if group:
            return group

        group = self._lookup_file(alert.filename)
        if group:
            return group

        return DEFAULT_GROUP

    def _lookup_person(self, person: str) -> Optional[str]:
        for key in (
            person,
            person.lower(),
            person.lower().split('@', 1)[0],
        ):
            if key in self.person_to_group:
                return self.person_to_group[key]
        return None

    def _lookup_file(self, filename: str) -> Optional[str]:
        normalized = filename.replace(os.sep, '/')
        matches: List[Tuple[int, str]] = []
        for pattern, group in self.file_rules:
            normalized_pattern = pattern.replace(os.sep, '/')
            if (
                normalized == normalized_pattern
                or fnmatch.fnmatch(normalized, normalized_pattern)
                or normalized.startswith(normalized_pattern.rstrip('/') + '/')
            ):
                matches.append((len(normalized_pattern), group))
        if not matches:
            return None
        return max(matches, key=lambda item: item[0])[1]


def _normalize_sources(sources: Sequence[Any]) -> List[Any]:
    output: List[Any] = []
    for source in sources:
        if source is None:
            continue
        if isinstance(source, (list, tuple)) and not _looks_like_alert_list(source):
            output.extend(_normalize_sources(source))
        else:
            output.append(source)
    return output


def _looks_like_alert_list(source: Sequence[Any]) -> bool:
    if not source or not all(isinstance(item, Mapping) for item in source):
        return False

    # A list of baseline/report documents is a list of sources, not a list of
    # individual alerts.  Alert rows themselves may contain a filename, but
    # they do not contain one of these report-level containers.
    report_level_keys = {
        'results',
        'alerts',
        'findings',
        'groups',
        'history',
        'reports',
        'versions',
        'external',
        'report',
        'decisions',
        'labels',
        'team_boundaries',
        'teams',
    }
    return not any(
        any(key in item for key in report_level_keys)
        for item in source
    )


def _load_source(source: Any) -> Optional[Dict[str, Any]]:
    if isinstance(source, str):
        stripped = source.lstrip()
        if stripped.startswith('{') or stripped.startswith('['):
            data = json.loads(source)
            if isinstance(data, list):
                return {'alerts': data}
            return data
        return _read_json(source)
    if isinstance(source, os.PathLike):
        return _read_json(str(source))
    if isinstance(source, Mapping):
        return dict(source)
    if isinstance(source, list):
        return {'alerts': source}
    return None


def _read_json(filename: str) -> Dict[str, Any]:
    if os.path.isdir(filename):
        output: Dict[str, Any] = {'history': []}
        for name in sorted(os.listdir(filename)):
            if not name.endswith('.json'):
                continue
            output['history'].append(os.path.join(filename, name))
        return output

    with open(filename) as f:
        data = json.loads(f.read())
    if isinstance(data, list):
        return {'alerts': data}
    if not isinstance(data, dict):
        raise ValueError(f'Unsupported aggregation input: {filename}')
    return data


def _alerts_from_payload(
    payload: Mapping[str, Any],
) -> Tuple[List[Alert], Dict[str, bool], Optional[List[GroupCount]]]:
    alerts: List[Alert] = []
    decisions: Dict[str, bool] = {}
    groups: Optional[List[GroupCount]] = None

    results = payload.get('results')
    if isinstance(results, Mapping):
        for filename, items in results.items():
            if not isinstance(items, list):
                continue
            for item in items:
                if not isinstance(item, Mapping):
                    continue
                if _looks_like_group_count(item):
                    continue
                alerts.append(_alert_from_item(item, filename=str(filename)))
    elif isinstance(results, list):
        for item in results:
            if isinstance(item, Mapping) and not _looks_like_group_count(item):
                alerts.append(_alert_from_item(item))

    for key in _ALERT_LIST_FIELDS:
        items = payload.get(key)
        if key == 'decisions' and isinstance(items, Mapping):
            decisions.update(_decisions_from_mapping(items))
            continue
        if isinstance(items, list):
            for item in items:
                if not isinstance(item, Mapping):
                    continue
                if key == 'decisions':
                    decision = _label_from_item(item, {})
                    identifier = _first_string(
                        item,
                        ('alert_id', 'alertId', 'secret_id', 'finding_id', 'id'),
                    )
                    if identifier is not None and decision is not None:
                        decisions[str(identifier)] = decision
                    if not _has_full_alert_data(item):
                        continue
                if _looks_like_group_count(item):
                    continue
                alerts.append(_alert_from_item(item))
        elif isinstance(items, Mapping) and key == 'decisions':
            decisions.update(_decisions_from_mapping(items))

    for key in ('labels', 'manual_decisions', 'adjudications'):
        items = payload.get(key)
        if isinstance(items, Mapping):
            decisions.update(_decisions_from_mapping(items))
        elif isinstance(items, list):
            decide = {
                str(_first_value(item, ('alert_id', 'id', 'secret_id'))): bool(
                    _first_value(item, _DECISION_FIELDS),
                )
                for item in items
                if isinstance(item, Mapping)
                and _first_value(item, ('alert_id', 'id', 'secret_id')) is not None
            }
            decisions.update(decide)

    group_source = _first_value(
        payload,
        ('groups', 'group_counts', 'counts', 'external', 'report', 'public'),
    )
    if not alerts and group_source is not None:
        groups = _groups_from_any(group_source)
    if not alerts and groups is None and 'results' in payload:
        candidate_groups = _groups_from_any(payload['results'])
        if candidate_groups:
            groups = candidate_groups

    return alerts, decisions, groups


def _looks_like_group_count(item: Mapping[str, Any]) -> bool:
    """Distinguish aggregate group rows from individual alert rows."""
    has_group = any(key in item for key in ('group', 'team', 'team_name', 'name'))
    has_count = any(key in item for key in ('count', 'alerts', 'value', 'total'))
    has_alert_data = any(
        key in item
        for key in (
            'person', 'owner', 'author', 'is_secret', 'decision', 'category',
            'hashed_secret', 'secret_hash', 'type', 'line_number',
        )
    )
    return has_group and has_count and not has_alert_data


def _alert_from_item(item: Mapping[str, Any], filename: Optional[str] = None) -> Alert:
    metadata = _first_value(item, ('metadata', 'meta', 'attributes'))
    if not isinstance(metadata, Mapping):
        metadata = {}

    filename_value = str(
        _first_value(item, ('filename', 'file', 'path'))
        or filename
        or '',
    )

    alert_id = _first_string(
        item,
        (
            'alert_id',
            'alertId',
            'secret_id',
            'finding_id',
            'id',
            'hashed_secret',
            'secret_hash',
        ),
    )
    if not alert_id:
        alert_id = _first_string(
            metadata,
            (
                'alert_id',
                'alertId',
                'secret_id',
                'finding_id',
                'id',
                'hashed_secret',
                'secret_hash',
            ),
        )
    if not alert_id:
        alert_id = _digest({
            'filename': filename_value,
            'line': item.get('line_number', item.get('line')),
            'type': item.get('type', item.get('secret_type')),
            'hash': item.get('hashed_secret', item.get('secret_hash')),
        })

    person = _first_string(item, _PERSON_FIELDS) or _first_string(metadata, _PERSON_FIELDS)
    if not person:
        person = f'alert:{alert_id}'

    group = _first_string(item, _GROUP_FIELDS) or _first_string(metadata, _GROUP_FIELDS)

    return Alert(
        alert_id=str(alert_id),
        person=str(person),
        filename=filename_value,
        is_secret=_label_from_item(item, metadata),
        group=str(group) if group else None,
        metadata=dict(item),
    )


def _label_from_item(item: Mapping[str, Any], metadata: Mapping[str, Any]) -> Optional[bool]:
    for source in (item, metadata):
        value = _first_value(source, ('is_secret', 'isSecret'))
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized_secret = value.strip().lower()
            if normalized_secret in {'true', 'real', 'yes', 'y', 'secret', 'accepted'}:
                return True
            if normalized_secret in {'false', 'fake', 'no', 'n', 'false_positive', 'rejected'}:
                return False

        value = _first_value(source, _DECISION_FIELDS)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {'true', 'real', 'yes', 'y', 'secret', 'accepted', 'approve'}:
                return True
            if normalized in {'false', 'fake', 'no', 'n', 'false_positive', 'rejected'}:
                return False

        category = _first_value(source, ('category', 'classification'))
        if isinstance(category, str):
            normalized = category.strip().lower()
            if normalized in {
                'verified_true',
                'real_secret',
                'true_positive',
                'verified-true',
                'real',
            }:
                return True
            if normalized in {
                'verified_false',
                'false_positive',
                'verified-false',
                'false',
            }:
                return False

    return None


def _decisions_from_mapping(items: Mapping[Any, Any]) -> Dict[str, bool]:
    output: Dict[str, bool] = {}
    for key, value in items.items():
        if isinstance(value, bool):
            output[str(key)] = value
        elif isinstance(value, Mapping):
            decision = _first_value(value, _DECISION_FIELDS)
            if isinstance(decision, bool):
                output[str(key)] = decision
        elif isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {'true', 'real', 'yes', 'secret', 'accepted'}:
                output[str(key)] = True
            elif normalized in {'false', 'fake', 'no', 'false_positive', 'rejected'}:
                output[str(key)] = False
    return output


def _apply_decisions(alerts: List[Alert], decisions: Mapping[str, bool]) -> List[Alert]:
    if not decisions:
        return alerts

    output: List[Alert] = []
    for alert in alerts:
        for identifier in _alert_identifiers(alert):
            if identifier in decisions:
                alert.is_secret = decisions[identifier]
                break
        output.append(alert)
    return output


def _filter_alerts(alerts: List[Alert], include_unlabelled: bool) -> List[Alert]:
    if include_unlabelled:
        return [alert for alert in alerts if alert.is_secret is not False]

    labelled = [alert for alert in alerts if alert.is_secret is not None]
    if labelled:
        return [alert for alert in labelled if alert.is_secret is True]

    # A freshly generated baseline may not have been manually audited yet.  It is
    # still useful to summarize it, but explicit false positives are always excluded.
    return [alert for alert in alerts if alert.is_secret is not False]


def _alert_identifiers(alert: Alert) -> List[str]:
    identifiers = [alert.alert_id]
    for key in ('hashed_secret', 'secret_hash', 'id', 'alert_id'):
        value = alert.metadata.get(key)
        if value is not None and str(value) not in identifiers:
            identifiers.append(str(value))
    return identifiers


def _alert_identity(alert: Alert) -> Tuple[str, str, str]:
    # The same finding can be represented with different alert ids by
    # different exports.  Keep file and group in the identity so the same
    # hashed value in two files still counts as two occurrences.
    return (alert.filename, alert.alert_id, alert.group or '')


def _aggregate_alerts(
    alerts: Sequence[Alert],
    boundaries: TeamBoundaries,
    merge_groups: Mapping[str, str],
) -> List[GroupCount]:
    output: Dict[str, GroupCount] = {}
    seen_alert_ids: Set[str] = set()

    for alert in alerts:
        group_name = boundaries.resolve(alert)
        group_name = merge_groups.get(group_name, group_name)
        group = output.setdefault(group_name, GroupCount(name=group_name, count=0))

        # A duplicated alert id represents the same finding, not a second
        # contributor.  Some report formats repeat an alert for multiple lines.
        identity = _alert_identity(alert)
        if identity in seen_alert_ids:
            continue
        seen_alert_ids.add(identity)

        group.count += 1
        group.people.add(alert.person)
        group.alert_ids.add(alert.alert_id)

    return list(output.values())


def _clone_groups(
    groups: Sequence[GroupCount],
    merge_groups: Mapping[str, str],
) -> List[GroupCount]:
    output: Dict[str, GroupCount] = {}
    for item in groups:
        name = merge_groups.get(item.name, item.name)
        group = output.setdefault(name, GroupCount(name=name, count=0))
        group.count += item.count
        group.people.update(item.people)
        group.alert_ids.update(item.alert_ids)
    return list(output.values())


def _groups_from_any(data: Any) -> List[GroupCount]:
    if isinstance(data, Mapping):
        for key in ('groups', 'results', 'group_counts', 'counts'):
            if key in data:
                groups = _groups_from_any(data[key])
                if groups:
                    return groups

        output: List[GroupCount] = []
        for name, value in data.items():
            if isinstance(value, Mapping):
                count = _optional_int(
                    _first_value(value, ('count', 'alerts', 'value', 'total')),
                )
                people = _first_value(
                    value,
                    ('members', 'people', 'contributors', 'users', 'identities'),
                )
            elif isinstance(value, bool):
                continue
            else:
                count = _optional_int(value)
                people = None

            if count is None:
                continue
            output.append(_group_count(str(name), count, people))
        return output

    if isinstance(data, list):
        output = []
        for item in data:
            if not isinstance(item, Mapping):
                continue
            name = _first_string(item, ('group', 'team', 'name', 'id'))
            count = _optional_int(
                _first_value(item, ('count', 'alerts', 'value', 'total')),
            )
            if not name or count is None:
                continue
            people = _first_value(item, ('members', 'people', 'contributors'))
            output.append(_group_count(name, count, people))
        return output

    return []


def _group_count(name: str, count: int, people: Any) -> GroupCount:
    member_set: Set[str] = set()
    if isinstance(people, str):
        member_set.add(people)
    elif isinstance(people, Iterable):
        member_set.update(str(person) for person in people)

    # Already-aggregated reports sometimes only carry a count.  In that case the
    # count is the only available contributor measure, so use it for the
    # threshold check rather than suppressing a legitimately sized group.
    if not member_set and count > 0:
        member_set.update(f'{name}:{index}' for index in range(count))

    return GroupCount(
        name=name,
        count=count,
        people=member_set,
    )


def _history_from_payload(payload: Mapping[str, Any]) -> List[Any]:
    output: List[Any] = []
    for key in _HISTORY_FIELDS:
        value = payload.get(key)
        if value is None:
            continue
        if isinstance(value, Mapping):
            output.extend(_history_items_from_mapping(value))
        else:
            output.extend(_as_list(value))
    return output


def _history_items_from_mapping(value: Mapping[str, Any]) -> List[Any]:
    for key in _HISTORY_FIELDS:
        if key in value:
            nested = value[key]
            if isinstance(nested, Mapping):
                return _history_items_from_mapping(nested)
            return _as_list(nested)
    if 'groups' in value or 'results' in value or 'report' in value:
        return [value]

    output: List[Any] = []
    for report_id, report in value.items():
        if isinstance(report, Mapping):
            if _has_inline_report_data(report) or any(
                key in report for key in ('report_id', 'reportId', 'version', 'revision')
            ):
                item = dict(report)
                item.setdefault('report_id', str(report_id))
                output.append(item)
            else:
                output.append({
                    'report_id': str(report_id),
                    'groups': report,
                })
        elif isinstance(report, (str, os.PathLike)):
            output.append({
                'report_id': str(report_id),
                'path': str(report),
            })
    return output or [value]


def _load_history(
    items: Sequence[Any],
    boundaries: TeamBoundaries,
    merge_groups: Mapping[str, str],
    include_unlabelled: bool,
) -> List[HistoricalReport]:
    output: List[HistoricalReport] = []
    for index, item in enumerate(_expand_history_items(items)):
        report = _historical_report_from_item(
            item,
            index=index,
            boundaries=boundaries,
            merge_groups=merge_groups,
            include_unlabelled=include_unlabelled,
        )
        if report is not None:
            output.append(report)
    return output


def _expand_history_items(items: Sequence[Any]) -> List[Any]:
    """Expand report directories and history-container documents."""
    output: List[Any] = []
    for item in items:
        if isinstance(item, (str, os.PathLike)):
            path = str(item)
            stripped = path.lstrip()
            if stripped.startswith('['):
                output.extend(_expand_history_items(json.loads(path)))
                continue
            if os.path.isdir(path):
                output.extend(
                    os.path.join(path, name)
                    for name in sorted(os.listdir(path))
                    if name.endswith('.json')
                )
                continue

            if not os.path.exists(path):
                output.append(item)
                continue

            if path.endswith('.json') and os.path.isfile(path):
                with open(path) as f:
                    raw_payload = json.load(f)
                if isinstance(raw_payload, list):
                    output.extend(_expand_history_items(raw_payload))
                    continue

            payload = _read_json(path)
            expanded = _history_values_only(payload)
            if expanded is not None:
                output.extend(_expand_history_items(expanded))
            else:
                output.append(item)
            continue

        if isinstance(item, Mapping):
            expanded = _history_values_only(item)
            if expanded is not None:
                output.extend(_expand_history_items(expanded))
            else:
                output.append(item)
            continue

        output.append(item)

    return output


def _history_values_only(item: Mapping[str, Any]) -> Optional[List[Any]]:
    if _has_inline_report_data(item):
        return None

    for key in _HISTORY_FIELDS:
        if key in item and item[key] is not None:
            nested = item[key]
            if isinstance(nested, Mapping):
                return _history_items_from_mapping(nested)
            return _as_list(nested)
    return None


def _historical_report_from_item(
    item: Any,
    index: int,
    boundaries: TeamBoundaries,
    merge_groups: Mapping[str, str],
    include_unlabelled: bool,
) -> Optional[HistoricalReport]:
    if isinstance(item, str) or isinstance(item, os.PathLike):
        path = str(item)
        if not os.path.exists(path):
            return HistoricalReport(
                report_id=path,
                digest=_digest(path),
                groups=[],
            )
        payload = _read_json(path)
        report_id = _payload_report_id(payload) or path
        return _historical_report_from_payload(
            payload,
            report_id=report_id,
            boundaries=boundaries,
            merge_groups=merge_groups,
            include_unlabelled=include_unlabelled,
        )

    if not isinstance(item, Mapping):
        return None

    path = _first_value(item, ('baseline', 'baseline_file', 'path', 'file', 'filename'))
    if isinstance(path, str) and path and not _has_inline_report_data(item):
        if not os.path.exists(path):
            return HistoricalReport(
                report_id=_first_string(
                    item,
                    ('report_id', 'reportId', 'id', 'version', 'revision', 'commit', 'name'),
                ) or path,
                digest=_digest(path),
                groups=[],
            )
        payload = _read_json(path)
        report_id = _first_string(
            item,
            ('report_id', 'reportId', 'id', 'version', 'revision', 'commit', 'name'),
        ) or path
        return _historical_report_from_payload(
            payload,
            report_id=report_id,
            boundaries=boundaries,
            merge_groups=merge_groups,
            include_unlabelled=include_unlabelled,
        )

    report_id = _first_string(
        item,
        ('report_id', 'reportId', 'id', 'version', 'revision', 'commit', 'name'),
    ) or f'history-{index + 1}'
    return _historical_report_from_payload(
        item,
        report_id=report_id,
        boundaries=boundaries,
        merge_groups=merge_groups,
        include_unlabelled=include_unlabelled,
    )


def _historical_report_from_payload(
    payload: Mapping[str, Any],
    report_id: str,
    boundaries: TeamBoundaries,
    merge_groups: Mapping[str, str],
    include_unlabelled: bool,
) -> Optional[HistoricalReport]:
    report_payload = payload
    external = _first_value(payload, ('external', 'public', 'report'))
    if external is None:
        external = payload.get('receipt', {}).get('external') \
            if isinstance(payload.get('receipt'), Mapping) else None

    if external is not None:
        groups = _groups_from_any(external)
    else:
        groups = _groups_from_any(payload)

    alerts, decisions, payload_groups = _alerts_from_payload(report_payload)
    if alerts:
        alerts = _apply_decisions(alerts, decisions)
        alerts = _filter_alerts(alerts, include_unlabelled=include_unlabelled)
        groups = _aggregate_alerts(alerts, boundaries, merge_groups)
    elif payload_groups:
        groups = payload_groups

    if not groups:
        groups = []

    return HistoricalReport(
        report_id=str(report_id),
        digest=_digest(_groups_for_digest(groups)),
        groups=groups,
    )


def _has_inline_report_data(item: Mapping[str, Any]) -> bool:
    return any(
        key in item
        for key in (*_ALERT_LIST_FIELDS, 'results', 'groups', 'external', 'report')
    )


def _find_differencing_risk(
    group: GroupCount,
    historical_reports: Sequence[HistoricalReport],
    minimum_group_size: int,
) -> Optional[Dict[str, Any]]:
    risks: List[Dict[str, Any]] = []
    for report in historical_reports:
        composite = _matching_composite_group(group, report.groups)
        if composite:
            # A merged (coarser) group is a new disclosure scope.  There is no
            # corresponding fine-grained historical group to subtract from it.
            continue

        for historical_group in report.groups:
            if not _same_disclosure_scope(group, historical_group):
                continue

            delta = abs(group.count - historical_group.count)
            if not 0 < delta < minimum_group_size:
                continue

            risks.append({
                'history_report_id': report.report_id,
                'historical_group': historical_group.name,
                'count_delta': delta,
            })

    if not risks:
        return None

    history_report_ids: List[str] = []
    for risk in risks:
        report_id = str(risk['history_report_id'])
        if report_id not in history_report_ids:
            history_report_ids.append(report_id)

    deltas = [int(risk['count_delta']) for risk in risks]
    return {
        'code': 'differencing',
        'reason': 'single_person_change' if min(deltas) == 1 else 'small_group_change',
        'history_report_ids': history_report_ids,
        'historical_group': risks[0]['historical_group'],
        'count_delta': min(deltas),
        'minimum_group_size': minimum_group_size,
    }

def _matching_composite_group(
    group: GroupCount,
    historical_groups: Sequence[GroupCount],
) -> bool:
    if len(historical_groups) < 2:
        return False

    if group.people:
        union: Set[str] = set()
        for historical_group in historical_groups:
            if not historical_group.people:
                continue
            union.update(historical_group.people)
            if union == group.people and historical_group is not historical_groups[0]:
                return True

    components = _group_name_components(group.name)
    historical_names: Set[str] = set()
    for historical_group in historical_groups:
        historical_names.update(_group_name_components(historical_group.name))
    return len(components) >= 2 and components <= historical_names


def _same_disclosure_scope(left: GroupCount, right: GroupCount) -> bool:
    if left.name == right.name:
        return True
    if left.people and right.people:
        return left.people == right.people
    return False


def _group_name_components(name: str) -> Set[str]:
    normalized = name
    for prefix in ('merged:', 'merged:', 'merge:'):
        if normalized.lower().startswith(prefix):
            normalized = normalized[len(prefix):]
    for separator in ('+', ',', '|', '/'):
        normalized = normalized.replace(separator, '\x00')
    return {
        component.strip()
        for component in normalized.split('\x00')
        if component.strip()
    }


def _history_ids_from_reasons(reasons: Sequence[Mapping[str, Any]]) -> List[str]:
    output: List[str] = []
    for reason in reasons:
        for report_id in reason.get('history_report_ids', []):
            if report_id not in output:
                output.append(str(report_id))
    return output


def _merge_group_mapping(value: Any) -> Dict[str, str]:
    if not value:
        return {}

    if isinstance(value, str):
        value = [value]

    if isinstance(value, Mapping):
        output: Dict[str, str] = {}
        for key, group in value.items():
            if isinstance(group, str):
                output[str(key)] = group
            elif isinstance(group, Iterable):
                target = str(key)
                for item in group:
                    output[str(item)] = target
        return output

    output = {}
    for item in value:
        if isinstance(item, str):
            output.update(_parse_merge_group_string(item))
        elif isinstance(item, Mapping):
            target = _first_string(item, ('as', 'name', 'group', 'merged_group'))
            groups = _first_value(item, ('groups', 'from', 'members', 'merge'))
            if not target or groups is None:
                continue
            for group in _as_list(groups):
                output[str(group)] = target
        elif isinstance(item, Iterable):
            groups = [str(group) for group in item]
            if len(groups) >= 2:
                target = '+'.join(groups)
                for group in groups:
                    output[group] = target
    return output


def _parse_merge_group_string(value: str) -> Dict[str, str]:
    if '=' in value:
        groups_part, target = value.split('=', 1)
    else:
        groups_part, target = value, ''
    groups = [group.strip() for group in groups_part.split(',') if group.strip()]
    if not groups:
        return {}
    if not target.strip():
        target = '+'.join(groups)
    return {
        group: target.strip()
        for group in groups
    }


def _boundaries_embedded_in_team_argument(sources: Sequence[Any]) -> Any:
    for source in sources:
        if not isinstance(source, Mapping):
            continue
        value = _first_value(
            source,
            ('team_boundaries', 'teamBoundaries', 'boundaries'),
        )
        if value is not None:
            return value
    return None


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, (str, os.PathLike, Mapping)):
        return [value]
    if isinstance(value, Iterable):
        return list(value)
    return [value]


def _dedupe_items(items: Sequence[Any]) -> List[Any]:
    """Keep history entries unique while preserving their original order."""
    output: List[Any] = []
    seen: Set[str] = set()
    for item in items:
        try:
            key = json.dumps(item, sort_keys=True, default=str)
        except TypeError:
            key = str(item)
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    return output


def _first_value(source: Any, keys: Sequence[str]) -> Any:
    if not isinstance(source, Mapping):
        return None
    for key in keys:
        if key in source and source[key] is not None:
            return source[key]
    return None


def _first_string(source: Any, keys: Sequence[str]) -> Optional[str]:
    value = _first_value(source, keys)
    if value is None:
        return None
    if isinstance(value, (str, int)):
        return str(value)
    return None


def _optional_int(value: Any) -> Optional[int]:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _groups_for_digest(groups: Sequence[GroupCount]) -> List[Dict[str, Any]]:
    return [
        {
            'group': group.name,
            'count': group.count,
            'people': sorted(group.people),
        }
        for group in sorted(groups, key=lambda item: item.name)
    ]


def _digest(value: Any) -> str:
    serialized = json.dumps(value, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(serialized.encode('utf-8')).hexdigest()


def _has_full_alert_data(item: Mapping[str, Any]) -> bool:
    return any(
        key in item
        for key in (
            'person', 'owner', 'author', 'filename', 'file', 'path',
            'hashed_secret', 'secret_hash', 'type', 'line_number', 'group',
        )
    )


def _has_identity(item: Mapping[str, Any]) -> bool:
    return any(
        key in item
        for key in ('alert_id', 'alertId', 'secret_id', 'finding_id', 'id', 'hashed_secret')
    )


def _payload_report_id(payload: Mapping[str, Any]) -> Optional[str]:
    """Return an explicit report identity, without treating baseline format versions as IDs."""
    explicit = _first_string(
        payload,
        (
            'report_id',
            'reportId',
            'release_id',
            'releaseId',
            'revision',
            'commit',
            'sha',
            'digest',
        ),
    )
    if explicit:
        return explicit

    if not _is_baseline_payload(payload):
        return _first_string(payload, ('id', 'version', 'name'))

    return None


def _is_baseline_payload(payload: Mapping[str, Any]) -> bool:
    results = payload.get('results')
    if not isinstance(results, Mapping):
        return False
    return (
        'plugins_used' in payload
        or 'generated_at' in payload
        or 'version' in payload
        or bool(results)
    )


def aggregate_offline(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    """Compatibility alias for aggregate."""
    return aggregate(*args, **kwargs)


def offline_aggregate(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    """Compatibility alias for aggregate."""
    return aggregate(*args, **kwargs)


def review(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    """Compatibility alias for aggregate."""
    return aggregate(*args, **kwargs)


class OfflineAggregator:
    """Reusable wrapper around offline aggregation and release review."""

    def __init__(self, **defaults: Any) -> None:
        self.defaults = defaults

    def aggregate(self, *sources: Any, **kwargs: Any) -> Dict[str, Any]:
        options = dict(self.defaults)
        options.update(kwargs)
        return aggregate(*sources, **options)

    def review(self, *sources: Any, **kwargs: Any) -> Dict[str, Any]:
        return self.aggregate(*sources, **kwargs)


def generate_summary(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    """Compatibility alias for aggregate."""
    return aggregate(*args, **kwargs)


def summarize(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    """Compatibility alias for aggregate."""
    return aggregate(*args, **kwargs)


def review_release_request(*args: Any, **kwargs: Any) -> Dict[str, Any]:
    """Compatibility alias for aggregate."""
    return aggregate(*args, **kwargs)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Standalone offline aggregation entry point."""
    import sys

    from ..main import handle_aggregate_action
    from ..main import parse_args

    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == 'aggregate':
        arguments = arguments[1:]
    args = parse_args(['aggregate', *arguments])
    handle_aggregate_action(args)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
