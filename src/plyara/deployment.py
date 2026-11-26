"""Offline review of file-grouped YARA rule deployments.

The deployment framework can ship several YARA files (file groups) together
and use a metadata field shared by many rules to decide which rules are
enabled for a particular deployment.  This module resolves that decision
without executing any rule: it only inspects the dictionaries produced by
Plyara, matches the resulting rules against a deployment manifest and an
approval ledger, and builds a legal subset of the approved rules.

The subset is rendered with :func:`plyara.utils.rebuild_yara_rule`, reparsed
with Plyara, and checked for unresolved rule references.  Rules that are
needed as dependencies are pulled into the subset when an approval covers
them; otherwise the report names the exact missing approval.
"""
from __future__ import annotations

import fnmatch
import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from plyara.core import Plyara
from plyara.exceptions import ParseError
from plyara.utils import generate_hash, rebuild_yara_rule

ACTIVE_STATUSES = frozenset({'active', 'approved', 'authorised', 'authorized', 'valid'})

_IDENTIFIER = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')
_BUILTIN_IDENTIFIERS = (
    frozenset(Plyara.KEYWORDS)
    | frozenset(Plyara.IMPORT_OPTIONS)
    | frozenset(Plyara.FUNCTION_KEYWORDS)
    | frozenset({
        'entrypoint',
        'extension',
        'filename',
        'filepath',
        'filesize',
        'filetype',
        'int8',
        'int8be',
        'int16',
        'int16be',
        'int32',
        'int32be',
        'uint8',
        'uint8be',
        'uint16',
        'uint16be',
        'uint32',
        'uint32be',
    })
)


def _text(value: Any) -> str:
    """Return a stable text form used for metadata comparisons."""
    if isinstance(value, bool):
        return 'true' if value else 'false'
    return str(value)


def _read_text(path: Any) -> str:
    """Read text from a path-like object or an importlib resource."""
    if isinstance(path, (str, bytes, os.PathLike)):
        return Path(path).read_text(encoding='utf-8')
    read_text = getattr(path, 'read_text', None)
    if callable(read_text):
        return read_text(encoding='utf-8')
    raise TypeError(f'unsupported path value: {path!r}')


def _as_tuple(value: Any) -> tuple[str, ...]:
    """Normalize a string or iterable into a tuple of text values."""
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(item) for item in value)


def _allowed_values(value: Any) -> frozenset[str] | None:
    """Normalize a manifest selector value to a set or ``None``."""
    if value is None:
        return None
    if isinstance(value, (str, bytes, bool, int, float)):
        return frozenset({_text(value)})
    if isinstance(value, Mapping):
        return frozenset(_text(item) for item in value)
    return frozenset(_text(item) for item in value)


def _iter_approvals(approvals: Any) -> Iterable['Approval']:
    """Flatten approvals and reviews into a single approval stream."""
    if approvals is None:
        return
    if isinstance(approvals, (Approval, Review, Mapping)):
        approvals = (approvals,)
    for entry in approvals:
        if isinstance(entry, Review):
            for approval in entry.approvals:
                if isinstance(approval, Mapping):
                    approval = Approval.from_mapping(approval)
                yield replace(
                    approval,
                    review_id=approval.review_id or entry.review_id,
                    combination=approval.combination or entry.combination,
                    source=approval.source or entry.source,
                )
        elif isinstance(entry, Approval):
            yield entry
        elif isinstance(entry, Mapping):
            yield Approval.from_mapping(entry)
        else:
            raise TypeError(f'unsupported approval entry: {entry!r}')


def _iteration_variables(condition_terms: Sequence[str]) -> set[str]:
    """Find names introduced by a YARA ``for`` loop."""
    variables: set[str] = set()
    for index, term in enumerate(condition_terms):
        if term != 'for':
            continue
        cursor = index + 1
        while cursor < len(condition_terms) and condition_terms[cursor] not in ('in', ':'):
            token = condition_terms[cursor]
            if (
                isinstance(token, str)
                and _IDENTIFIER.fullmatch(token)
                and token not in _BUILTIN_IDENTIFIERS
            ):
                variables.add(token)
            cursor += 1
    return variables


def _extract_reference_names(condition_terms: Sequence[str]) -> tuple[str, ...]:
    """Return bare identifiers that may reference another YARA rule.

    String variables, keywords, module-qualified names, numeric values and
    loop variables are discarded.  Unresolved identifiers are handled later,
    where they can be classified as external variables or real misses.
    """
    terms = list(condition_terms)
    variables = _iteration_variables(terms)
    references: list[str] = []
    for index, term in enumerate(terms):
        if not isinstance(term, str) or not _IDENTIFIER.fullmatch(term):
            continue
        if term in _BUILTIN_IDENTIFIERS or term in variables:
            continue
        if index + 1 < len(terms) and terms[index + 1] == '(':
            continue
        if term not in references:
            references.append(term)
    return tuple(references)


def _record_from_parsed(
    parsed: Mapping[str, Any],
    *,
    group: str,
    source: str | None,
    order: int,
) -> 'RuleRecord':
    """Build a :class:`RuleRecord` from one Plyara rule dictionary."""
    metadata_items: list[tuple[str, Any]] = []
    for entry in parsed.get('metadata') or []:
        if isinstance(entry, Mapping):
            metadata_items.extend((str(key), value) for key, value in entry.items())
    if not metadata_items:
        metadata_items.extend((str(key), value) for key, value in (parsed.get('metadata_kv') or {}).items())

    try:
        fingerprint = generate_hash(dict(parsed))
    except Exception:  # noqa: BLE001 - a fallback is preferable to losing the rule
        canonical = json.dumps(parsed, ensure_ascii=False, sort_keys=True, default=str)
        fingerprint = 'sha256_' + hashlib.sha256(canonical.encode('utf-8')).hexdigest()

    definition = json.dumps(
        {
            'rule_name': parsed.get('rule_name'),
            'condition_terms': parsed.get('condition_terms') or [],
            'strings': parsed.get('strings') or [],
            'metadata': parsed.get('metadata') or [],
            'tags': parsed.get('tags') or [],
            'scopes': parsed.get('scopes') or [],
        },
        ensure_ascii=False,
        sort_keys=True,
        default=str,
    )
    definition_hash = hashlib.sha256(definition.encode('utf-8')).hexdigest()

    return RuleRecord(
        group=group,
        name=str(parsed['rule_name']),
        parsed=dict(parsed),
        source=source,
        order=order,
        fingerprint=fingerprint,
        definition_hash=definition_hash,
        metadata_items=tuple(metadata_items),
        references=_extract_reference_names(parsed.get('condition_terms') or ()),
        imports=tuple(dict.fromkeys(str(item) for item in parsed.get('imports') or ())),
        includes=tuple(dict.fromkeys(str(item) for item in parsed.get('includes') or ())),
    )


@dataclass(frozen=True)
class RuleRecord:
    """One parsed rule together with its file-group identity."""

    group: str
    name: str
    parsed: Mapping[str, Any] = field(repr=False)
    source: str | None = None
    order: int = 0
    fingerprint: str = ''
    definition_hash: str = ''
    metadata_items: tuple[tuple[str, Any], ...] = ()
    references: tuple[str, ...] = ()
    imports: tuple[str, ...] = ()
    includes: tuple[str, ...] = ()

    @property
    def rule_id(self) -> str:
        """Return the file-group-qualified rule identity."""
        return f'{self.group}/{self.name}'

    @property
    def start_line(self) -> int | None:
        """Return the first source line of the rule, if known."""
        return self.parsed.get('start_line')

    def metadata_values(self, key: str) -> tuple[Any, ...]:
        """Return every value recorded for ``key``, preserving duplicates."""
        return tuple(value for item_key, value in self.metadata_items if item_key == key)

    def metadata_values_text(self, key: str) -> tuple[str, ...]:
        """Return the selector values for ``key`` as comparable text."""
        return tuple(_text(value) for value in self.metadata_values(key))

    def selector_values(self, keys: Iterable[str]) -> dict[str, tuple[str, ...]]:
        """Return the rule's values for each manifest selector key."""
        return {key: self.metadata_values_text(key) for key in keys}


@dataclass(frozen=True)
class FileGroup:
    """A YARA file and the rules parsed from it."""

    name: str
    rules: tuple[RuleRecord, ...]
    source: str | None = None
    optional: bool = False
    version: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def rule(self, name: str) -> RuleRecord | None:
        """Return a rule by name, if it exists in this group."""
        for record in self.rules:
            if record.name == name:
                return record
        return None


def _group_from_parsed(
    name: str,
    parsed_rules: Sequence[Mapping[str, Any]],
    *,
    source: str | None = None,
    optional: bool = False,
    version: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> FileGroup:
    """Build a file group from already parsed rule dictionaries."""
    records = tuple(
        _record_from_parsed(entry, group=name, source=source, order=index)
        for index, entry in enumerate(parsed_rules)
    )
    return FileGroup(
        name=name,
        rules=records,
        source=source,
        optional=optional,
        version=version,
        metadata=dict(metadata or {}),
    )


def parse_file_group(
    name: str,
    text: str,
    *,
    optional: bool = False,
    version: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> FileGroup:
    """Parse YARA source text into one named file group."""
    try:
        parsed = Plyara().parse_string(text)
    except ParseError as exc:
        raise ValueError(f'{name}: {exc}') from exc
    return _group_from_parsed(
        name,
        parsed,
        source=f'<{name}>',
        optional=optional,
        version=version,
        metadata=metadata,
    )


def load_file_group(
    name: str,
    path: Any,
    *,
    optional: bool = False,
    version: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> FileGroup:
    """Read and parse one YARA file into a named file group."""
    group = parse_file_group(
        name,
        _read_text(path),
        optional=optional,
        version=version,
        metadata=metadata,
    )
    source = str(path)
    return replace(
        group,
        source=source,
        rules=tuple(replace(record, source=source) for record in group.rules),
    )


def parse_file_groups(
    sources: Mapping[str, str],
    *,
    optional: Iterable[str] = (),
    versions: Mapping[str, str | None] | None = None,
    metadata: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, FileGroup]:
    """Parse a mapping of group name to YARA source text."""
    optional_names = set(optional)
    versions = versions or {}
    metadata = metadata or {}
    return {
        name: parse_file_group(
            name,
            text,
            optional=name in optional_names,
            version=versions.get(name),
            metadata=metadata.get(name),
        )
        for name, text in sources.items()
    }


def load_file_groups(
    paths: Mapping[str, str | os.PathLike[str]],
    *,
    optional: Iterable[str] = (),
    versions: Mapping[str, str | None] | None = None,
    metadata: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, FileGroup]:
    """Read a mapping of group name to YARA file path."""
    optional_names = set(optional)
    versions = versions or {}
    metadata = metadata or {}
    return {
        name: load_file_group(
            name,
            path,
            optional=name in optional_names,
            version=versions.get(name),
            metadata=metadata.get(name),
        )
        for name, path in paths.items()
    }


def upgrade_file_group(
    group: FileGroup,
    source: str | os.PathLike[str],
    *,
    version: str | None = None,
    optional: bool | None = None,
) -> FileGroup:
    """Replace an optional file group with an upgraded copy of its contents.

    ``source`` may be a path-like object, an existing path, or YARA source
    text.  The group's identity and optional flag are preserved unless they
    are overridden explicitly.
    """
    upgraded: FileGroup
    if isinstance(source, os.PathLike) or (
        not isinstance(source, str) and callable(getattr(source, 'read_text', None))
    ):
        upgraded = load_file_group(group.name, source)
    elif isinstance(source, str) and '\n' not in source and len(source) < 4096 and Path(source).exists():
        upgraded = load_file_group(group.name, source)
    else:
        upgraded = parse_file_group(group.name, source)  # type: ignore[arg-type]

    return replace(
        upgraded,
        optional=group.optional if optional is None else optional,
        version=group.version if version is None else version,
        metadata=dict(group.metadata),
    )


@dataclass(frozen=True)
class DeploymentManifest:
    """A specific list of file groups and metadata selectors to enable."""

    name: str
    groups: tuple[str, ...] = ()
    selectors: Mapping[str, frozenset[str] | None] = field(default_factory=dict)
    group_selectors: Mapping[str, Mapping[str, frozenset[str] | None]] = field(default_factory=dict)
    enabled_rules: tuple[str, ...] = ()
    disabled_rules: tuple[str, ...] = ()
    required_rules: tuple[str, ...] = ()
    optional_groups: tuple[str, ...] = ()
    include_unlabelled: bool = True
    external_variables: tuple[str, ...] = ()
    strict_references: bool = True
    combination: str | None = None
    description: str = ''

    def __post_init__(self) -> None:
        """Normalize compact constructor arguments."""
        object.__setattr__(self, 'groups', tuple(dict.fromkeys(_as_tuple(self.groups))))
        object.__setattr__(self, 'selectors', {
            str(key): _allowed_values(value) for key, value in dict(self.selectors or {}).items()
        })
        object.__setattr__(self, 'group_selectors', {
            str(group): {
                str(key): _allowed_values(value) for key, value in dict(selectors or {}).items()
            }
            for group, selectors in dict(self.group_selectors or {}).items()
        })
        object.__setattr__(self, 'enabled_rules', _as_tuple(self.enabled_rules))
        object.__setattr__(self, 'disabled_rules', _as_tuple(self.disabled_rules))
        object.__setattr__(self, 'required_rules', _as_tuple(self.required_rules))
        object.__setattr__(self, 'optional_groups', _as_tuple(self.optional_groups))
        object.__setattr__(self, 'external_variables', _as_tuple(self.external_variables))
        object.__setattr__(self, 'combination', self.combination or self.name)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> 'DeploymentManifest':
        """Build a manifest from a JSON-style mapping."""
        if not isinstance(data, Mapping):
            raise TypeError('deployment manifest must be a mapping')

        name = data.get('name') or data.get('id') or data.get('combination')
        if not name:
            raise ValueError('deployment manifest requires a name')

        groups_value = data.get('groups', data.get('file_groups', ()))
        group_selectors = {
            str(group): dict(selectors or {})
            for group, selectors in dict(data.get('group_selectors') or data.get('per_group') or {}).items()
        }
        optional_groups = list(data.get('optional_groups') or ())
        if isinstance(groups_value, Mapping):
            groups_list = []
            for group_name, config in groups_value.items():
                if isinstance(config, bool):
                    enabled = config
                elif isinstance(config, Mapping):
                    enabled = bool(config.get('enabled', True))
                    if config.get('optional'):
                        optional_groups.append(group_name)
                    selectors_value = config.get('selectors', config.get('select'))
                    if selectors_value is None:
                        selectors_value = {
                            key: value
                            for key, value in config.items()
                            if key not in ('enabled', 'optional', 'selectors', 'select')
                        }
                    if isinstance(selectors_value, Mapping):
                        group_selectors.setdefault(str(group_name), {}).update(selectors_value)
                else:
                    enabled = True
                if enabled:
                    groups_list.append(str(group_name))
            groups = tuple(groups_list)
        else:
            groups = _as_tuple(groups_value)

        selectors = {
            str(key): value
            for key, value in dict(data.get('selectors') or data.get('selection') or {}).items()
        }
        if 'selector' in data:
            selector_key = str(data['selector'])
            values = data.get('values', data.get('enabled_values', data.get('selector_values')))
            selectors[selector_key] = values

        return cls(
            name=str(name),
            groups=groups,
            selectors=selectors,
            group_selectors=group_selectors,
            enabled_rules=_as_tuple(data.get('enabled_rules')),
            disabled_rules=_as_tuple(data.get('disabled_rules')),
            required_rules=_as_tuple(data.get('required_rules')),
            optional_groups=tuple(optional_groups),
            include_unlabelled=bool(data.get('include_unlabelled', True)),
            external_variables=_as_tuple(data.get('external_variables')),
            strict_references=bool(data.get('strict_references', True)),
            combination=data.get('combination'),
            description=str(data.get('description') or ''),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return {
            'name': self.name,
            'combination': self.combination,
            'groups': list(self.groups),
            'selectors': {
                key: None if values is None else sorted(values)
                for key, values in self.selectors.items()
            },
            'group_selectors': {
                group: {
                    key: None if values is None else sorted(values)
                    for key, values in selectors.items()
                }
                for group, selectors in self.group_selectors.items()
            },
            'enabled_rules': list(self.enabled_rules),
            'disabled_rules': list(self.disabled_rules),
            'required_rules': list(self.required_rules),
            'optional_groups': list(self.optional_groups),
            'include_unlabelled': self.include_unlabelled,
            'external_variables': list(self.external_variables),
            'strict_references': self.strict_references,
            'description': self.description,
        }


def manifest_from_mapping(data: Mapping[str, Any]) -> DeploymentManifest:
    """Build a :class:`DeploymentManifest` from a mapping."""
    return DeploymentManifest.from_mapping(data)


def load_manifest(path: Any) -> DeploymentManifest:
    """Read a JSON deployment manifest from disk."""
    data = json.loads(_read_text(path))
    return DeploymentManifest.from_mapping(data)


@dataclass(frozen=True)
class Approval:
    """One approval row from an existing review record.

    An approval may constrain any combination of a specific rule, file group,
    metadata field/value and deployment combination.  Empty constraints make
    the approval broader.  ``review_id`` (and optionally ``review_ref``)
    identifies the existing review segment that supplied the approval.
    """

    approval_id: str
    review_id: str | None = None
    rule: str | None = None
    group: str | None = None
    selector_key: str | None = None
    selector_value: str | None = None
    combination: str | None = None
    status: str = 'active'
    source: str | None = None
    review_ref: str | None = None
    note: str | None = None

    @property
    def active(self) -> bool:
        """Return whether the approval is currently usable."""
        return str(self.status or '').strip().lower() in ACTIVE_STATUSES

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> 'Approval':
        """Build an approval from a JSON-style mapping."""
        approval_id = data.get('approval_id') or data.get('id') or data.get('approval')
        if not approval_id:
            raise ValueError('approval requires an approval_id')
        return cls(
            approval_id=str(approval_id),
            review_id=data.get('review_id') or data.get('review'),
            rule=data.get('rule') or data.get('rule_name'),
            group=data.get('group') or data.get('file_group'),
            selector_key=data.get('selector_key') or data.get('metadata_key') or data.get('key'),
            selector_value=data.get('selector_value', data.get('metadata_value', data.get('value'))),
            combination=data.get('combination') or data.get('manifest'),
            status=str(data.get('status') or 'active'),
            source=data.get('source'),
            review_ref=data.get('review_ref') or data.get('citation') or data.get('locator'),
            note=data.get('note'),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return asdict(self)


@dataclass(frozen=True)
class Review:
    """A collection of approvals that came from one existing review."""

    review_id: str
    approvals: tuple[Approval, ...]
    combination: str | None = None
    source: str | None = None

    def __post_init__(self) -> None:
        """Normalize approval mappings into approval objects."""
        object.__setattr__(self, 'approvals', tuple(
            Approval.from_mapping(approval) if isinstance(approval, Mapping) else approval
            for approval in self.approvals
        ))

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> 'Review':
        """Build a review from a JSON-style mapping."""
        review_id = data.get('review_id') or data.get('id') or data.get('review')
        if not review_id:
            raise ValueError('review requires a review_id')
        approvals = tuple(Approval.from_mapping(item) for item in data.get('approvals') or ())
        return cls(
            review_id=str(review_id),
            approvals=approvals,
            combination=data.get('combination') or data.get('manifest'),
            source=data.get('source'),
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return {
            'review_id': self.review_id,
            'combination': self.combination,
            'source': self.source,
            'approvals': [approval.to_dict() for approval in self.approvals],
        }


def load_approvals(path: Any) -> tuple[Approval | Review, ...]:
    """Read approvals or review records from a JSON file."""
    data = json.loads(_read_text(path))
    if isinstance(data, list):
        return tuple(Approval.from_mapping(item) for item in data)
    if not isinstance(data, Mapping):
        raise TypeError('approval ledger must be a list or mapping')
    reviews = tuple(Review.from_mapping(item) for item in data.get('reviews') or ())
    approvals = tuple(Approval.from_mapping(item) for item in data.get('approvals') or ())
    return reviews + approvals


@dataclass(frozen=True)
class ApprovalTrace:
    """The existing review basis that allowed one rule in one combination."""

    approval_id: str
    review_id: str | None
    matched_on: tuple[str, ...]
    status: str
    usable: bool
    combination: str | None = None
    source: str | None = None
    review_ref: str | None = None
    note: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return asdict(self)


@dataclass(frozen=True)
class MissingApproval:
    """A precise statement of the approval a combination is missing."""

    manifest: str
    subject: str
    reason: str
    message: str
    required_by: str | None = None
    required_selector: tuple[str, tuple[str, ...]] | None = None
    rejected_approvals: tuple[ApprovalTrace, ...] = ()

    @property
    def approval_ids(self) -> tuple[str, ...]:
        """Return the approval identifiers that were found but not usable."""
        return tuple(trace.approval_id for trace in self.rejected_approvals)

    @property
    def approval_id(self) -> str | None:
        """Return the first unusable approval identifier, if one was found."""
        return self.rejected_approvals[0].approval_id if self.rejected_approvals else None

    @property
    def review_id(self) -> str | None:
        """Return the first unusable approval's review identifier."""
        return self.rejected_approvals[0].review_id if self.rejected_approvals else None

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return asdict(self)


@dataclass(frozen=True)
class Finding:
    """A blocker or warning produced while resolving a deployment."""

    kind: str
    severity: str
    subject: str
    message: str
    details: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return asdict(self)


@dataclass(frozen=True)
class SelectedItem:
    """One rule selected by a manifest and its review decision."""

    rule_id: str
    group: str
    name: str
    allowed: bool
    role: str
    selector_values: Mapping[str, tuple[str, ...]]
    source: str | None = None
    approvals: tuple[ApprovalTrace, ...] = ()
    rejected_approvals: tuple[ApprovalTrace, ...] = ()
    reasons: tuple[str, ...] = ()
    dependencies: tuple[str, ...] = ()

    @property
    def approval_ids(self) -> tuple[str, ...]:
        """Return the usable approval identifiers for this item."""
        return tuple(trace.approval_id for trace in self.approvals)

    @property
    def review_ids(self) -> tuple[str, ...]:
        """Return the existing review identifiers for this item."""
        return tuple(
            trace.review_id for trace in self.approvals if trace.review_id is not None
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation."""
        return asdict(self)


@dataclass(frozen=True)
class DeploymentReport:
    """The result of resolving one deployment manifest offline."""

    manifest: DeploymentManifest
    selected_items: tuple[SelectedItem, ...]
    enabled_items: tuple[SelectedItem, ...]
    dependencies: tuple[SelectedItem, ...]
    missing_approvals: tuple[MissingApproval, ...]
    findings: tuple[Finding, ...]
    subset_text: str
    subset_rule_ids: tuple[str, ...]
    subset_imports: tuple[str, ...]
    verification_issues: tuple[str, ...]

    @property
    def reviewable(self) -> bool:
        """Return whether the deployment can be reviewed without a blocker."""
        return (
            not any(finding.severity == 'blocker' for finding in self.findings)
            and not self.missing_approvals
            and not self.verification_issues
        )

    @property
    def blockers(self) -> tuple[Finding, ...]:
        """Return only the blocking findings."""
        return tuple(finding for finding in self.findings if finding.severity == 'blocker')

    @property
    def excluded_items(self) -> tuple[SelectedItem, ...]:
        """Return selected rules that were not allowed into the subset."""
        return tuple(item for item in self.selected_items if not item.allowed)

    @property
    def effective_items(self) -> tuple[SelectedItem, ...]:
        """Return every item the manifest selected before approval filtering."""
        return self.selected_items

    @property
    def effective_enabled_items(self) -> tuple[SelectedItem, ...]:
        """Return every item the manifest selected before approval filtering."""
        return self.selected_items

    @property
    def legal_subset(self) -> str:
        """Return the rendered legal subset text."""
        return self.subset_text

    @property
    def missing(self) -> tuple[MissingApproval, ...]:
        """Return the missing-approval entries."""
        return self.missing_approvals

    @property
    def enabled_rule_ids(self) -> tuple[str, ...]:
        """Return the allowed rule identities, dependencies first."""
        return self.subset_rule_ids

    def item(self, rule_id: str) -> SelectedItem:
        """Return the decision for one rule identity."""
        for item in (*self.enabled_items, *self.dependencies, *self.excluded_items):
            if item.rule_id == rule_id:
                return item
        raise KeyError(rule_id)

    def missing_for(self, subject: str) -> MissingApproval | None:
        """Return the missing approval for one rule, group or pattern."""
        for missing in self.missing_approvals:
            if missing.subject == subject:
                return missing
        return None

    def approval_traces(self, rule_id: str) -> tuple[ApprovalTrace, ...]:
        """Return all existing-review traces for one rule identity."""
        return self.item(rule_id).approvals

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly report, including the rendered subset."""
        return {
            'manifest': self.manifest.to_dict(),
            'reviewable': self.reviewable,
            'selected_items': [item.to_dict() for item in self.selected_items],
            'enabled_items': [item.to_dict() for item in self.enabled_items],
            'dependencies': [item.to_dict() for item in self.dependencies],
            'excluded_items': [item.to_dict() for item in self.excluded_items],
            'missing_approvals': [item.to_dict() for item in self.missing_approvals],
            'findings': [finding.to_dict() for finding in self.findings],
            'subset': {
                'rule_ids': list(self.subset_rule_ids),
                'imports': list(self.subset_imports),
                'text': self.subset_text,
            },
            'verification_issues': list(self.verification_issues),
        }


def _normalize_groups(groups: Any) -> dict[str, FileGroup]:
    """Accept groups as a mapping or sequence and return a name-indexed map."""
    if isinstance(groups, FileGroup):
        return {groups.name: groups}
    if isinstance(groups, Mapping):
        result: dict[str, FileGroup] = {}
        for name, value in groups.items():
            group_name = str(name)
            if isinstance(value, FileGroup):
                result[group_name] = value
            elif isinstance(value, os.PathLike):
                result[group_name] = load_file_group(group_name, value)
            elif isinstance(value, str):
                if '\n' in value or value.lstrip().startswith(('rule ', 'import ', 'include ', '//', '/*')):
                    result[group_name] = parse_file_group(group_name, value)
                else:
                    result[group_name] = load_file_group(group_name, value)
            elif isinstance(value, Sequence):
                result[group_name] = _group_from_parsed(group_name, value)
            else:
                raise TypeError(f'unsupported file group value for {group_name!r}: {value!r}')
        return dict(sorted(result.items()))

    result = {}
    for group in groups:
        if not isinstance(group, FileGroup):
            raise TypeError(f'unsupported file group: {group!r}')
        result[group.name] = group
    return dict(sorted(result.items()))


def _rule_matches_pattern(record: RuleRecord, pattern: str) -> bool:
    """Match a rule name or group-qualified rule identity."""
    pattern = str(pattern)
    if ':' in pattern:
        group_pattern, name_pattern = pattern.split(':', 1)
        return fnmatch.fnmatchcase(record.group, group_pattern) and fnmatch.fnmatchcase(record.name, name_pattern)
    return (
        fnmatch.fnmatchcase(record.name, pattern)
        or fnmatch.fnmatchcase(record.rule_id, pattern)
    )


def _rule_matches_any(record: RuleRecord, patterns: Iterable[str]) -> bool:
    """Match a rule against a collection of patterns."""
    return any(_rule_matches_pattern(record, pattern) for pattern in patterns)


def _selector_matches(
    record: RuleRecord,
    selectors: Mapping[str, frozenset[str] | None],
    *,
    include_unlabelled: bool,
) -> bool:
    """Apply one set of metadata selectors to a rule."""
    for key, allowed in selectors.items():
        values = record.metadata_values_text(key)
        if not values:
            if not include_unlabelled:
                return False
            continue
        if allowed is None:
            continue
        if not any(value in allowed for value in values):
            return False
    return True


def _rule_is_selected(record: RuleRecord, manifest: DeploymentManifest) -> bool:
    """Return whether the manifest's metadata selectors enable a rule."""
    if not _selector_matches(
        record,
        manifest.selectors,
        include_unlabelled=manifest.include_unlabelled,
    ):
        return False
    group_selectors = manifest.group_selectors.get(record.group, {})
    return _selector_matches(
        record,
        group_selectors,
        include_unlabelled=manifest.include_unlabelled,
    )


def _selector_basis(
    record: RuleRecord,
    manifest: DeploymentManifest,
) -> tuple[str, tuple[str, ...]] | None:
    """Return the metadata field and matched values that enabled a rule."""
    selectors = dict(manifest.selectors)
    selectors.update(manifest.group_selectors.get(record.group, {}))
    for key, allowed in selectors.items():
        values = record.metadata_values_text(key)
        matched = tuple(value for value in values if allowed is None or value in allowed)
        if matched:
            return key, matched
    return None


def _selector_note(basis: tuple[str, tuple[str, ...]] | None) -> str:
    """Render a short metadata note for a missing approval message."""
    if basis is None:
        return ''
    key, values = basis
    return f' ({key}={"/".join(values)})'


def _approval_match(
    approval: Approval,
    record: RuleRecord,
    manifest: DeploymentManifest,
) -> tuple[str, ...] | None:
    """Return the dimensions an approval matched, or ``None``."""
    matched_on: list[str] = []

    if approval.combination:
        if approval.combination != '*' and approval.combination not in {
            manifest.name,
            manifest.combination,
        }:
            return None
        matched_on.append(f'combination:{approval.combination}')

    if approval.group:
        if not fnmatch.fnmatchcase(record.group, approval.group):
            return None
        matched_on.append(f'group:{approval.group}')

    if approval.rule:
        if not _rule_matches_pattern(record, approval.rule):
            return None
        matched_on.append(f'rule:{approval.rule}')

    if approval.selector_key:
        values = record.metadata_values_text(approval.selector_key)
        if not values:
            return None
        if approval.selector_value is not None:
            wanted = _text(approval.selector_value)
            if wanted not in values:
                return None
            matched_on.append(f'metadata:{approval.selector_key}={wanted}')
        else:
            matched_on.append(f'metadata:{approval.selector_key}')
    elif approval.selector_value is not None:
        wanted = _text(approval.selector_value)
        values = {_text(value) for _, value in record.metadata_items}
        if wanted not in values:
            return None
        matched_on.append(f'metadata:*={wanted}')

    if not matched_on:
        matched_on.append('approval-wide')
    return tuple(matched_on)


def _trace(
    approval: Approval,
    matched_on: tuple[str, ...],
    combination: str | None = None,
) -> ApprovalTrace:
    """Build an immutable trace for one approval match."""
    return ApprovalTrace(
        approval_id=approval.approval_id,
        review_id=approval.review_id,
        matched_on=matched_on,
        status=approval.status,
        usable=approval.active,
        combination=combination,
        source=approval.source,
        review_ref=approval.review_ref,
        note=approval.note,
    )


def _trace_rank(trace: ApprovalTrace) -> tuple[int, str]:
    """Rank traces so the most specific existing review comes first."""
    score = 0
    if any(item.startswith('rule:') for item in trace.matched_on):
        score += 8
    if any(item.startswith('group:') for item in trace.matched_on):
        score += 4
    if any(item.startswith('metadata:') for item in trace.matched_on):
        score += 2
    if any(item.startswith('combination:') for item in trace.matched_on):
        score += 1
    return (-score, trace.approval_id)


def _approval_state(
    record: RuleRecord,
    manifest: DeploymentManifest,
    approvals: Sequence[Approval],
) -> tuple[tuple[ApprovalTrace, ...], tuple[ApprovalTrace, ...]]:
    """Return usable and rejected approval traces for one rule."""
    usable: list[ApprovalTrace] = []
    rejected: list[ApprovalTrace] = []
    for approval in approvals:
        matched_on = _approval_match(approval, record, manifest)
        if matched_on is None:
            continue
        trace = _trace(approval, matched_on, manifest.combination or manifest.name)
        if approval.active:
            usable.append(trace)
        else:
            rejected.append(trace)
    usable.sort(key=_trace_rank)
    rejected.sort(key=_trace_rank)
    return tuple(usable), tuple(rejected)


def _resolve_reference(
    record: RuleRecord,
    reference: str,
    index_by_name: Mapping[str, tuple[RuleRecord, ...]],
) -> tuple[RuleRecord | None, str | None]:
    """Resolve a bare rule reference to one record, if unambiguous."""
    matches = index_by_name.get(reference, ())
    if not matches:
        return None, 'undefined'

    same_group = tuple(item for item in matches if item.group == record.group)
    if len(same_group) == 1:
        return same_group[0], None
    if len(matches) == 1:
        return matches[0], None
    if len({item.definition_hash for item in matches}) == 1:
        return sorted(matches, key=lambda item: (item.group, item.order, item.name))[0], None
    if len(same_group) > 1 and len({item.definition_hash for item in same_group}) == 1:
        return sorted(same_group, key=lambda item: item.order)[0], None
    return None, 'ambiguous'


def _deduplicate_records(
    records: Sequence[RuleRecord],
) -> tuple[tuple[RuleRecord, ...], tuple[Finding, ...]]:
    """Collapse identical same-name rules and exclude conflicting definitions."""
    by_name: dict[str, list[RuleRecord]] = {}
    for record in records:
        by_name.setdefault(record.name, []).append(record)

    kept: list[RuleRecord] = []
    findings: list[Finding] = []
    for name, candidates in sorted(by_name.items()):
        if len(candidates) == 1:
            kept.append(candidates[0])
            continue

        definitions = {item.definition_hash for item in candidates}
        if len(definitions) == 1:
            canonical = sorted(candidates, key=lambda item: (item.group, item.order))[0]
            kept.append(canonical)
            findings.append(Finding(
                kind='duplicate_rule_deduplicated',
                severity='warning',
                subject=name,
                message=f'identical definitions of {name} were collapsed',
                details={'groups': [item.group for item in candidates]},
            ))
        else:
            findings.append(Finding(
                kind='duplicate_rule_name',
                severity='blocker',
                subject=name,
                message=f'conflicting definitions of {name} cannot share one legal subset',
                details={'groups': [item.group for item in candidates]},
            ))

    return tuple(sorted(kept, key=lambda item: (item.group, item.order, item.name))), tuple(findings)


def _topological_order(
    records: Mapping[str, RuleRecord],
    edges: Mapping[str, tuple[str, ...]],
) -> tuple[tuple[str, ...], tuple[tuple[str, ...], ...]]:
    """Return dependency-first ordering and any cycles."""
    state: dict[str, int] = {}
    order: list[str] = []
    cycles: list[tuple[str, ...]] = []

    def visit(rule_id: str, stack: tuple[str, ...]) -> None:
        """Visit one rule after ordering its dependencies."""
        if state.get(rule_id) == 1:
            start = stack.index(rule_id) if rule_id in stack else 0
            cycles.append(tuple(stack[start:] + (rule_id,)))
            return
        if state.get(rule_id) == 2:
            return
        state[rule_id] = 1
        for dependency in edges.get(rule_id, ()):
            if dependency in records:
                visit(dependency, stack + (rule_id,))
        state[rule_id] = 2
        if rule_id not in order:
            order.append(rule_id)

    for rule_id in sorted(records, key=lambda item: (records[item].group, records[item].order, records[item].name)):
        visit(rule_id, ())
    return tuple(order), tuple(cycles)


def _render_subset(
    records: Sequence[RuleRecord],
    imports: Iterable[str],
    *,
    external_variables: Iterable[str] = (),
    strict: bool = True,
) -> tuple[str, tuple[str, ...], tuple[str, ...]]:
    """Render rules into self-contained YARA text and reparse it."""
    import_names = tuple(sorted(set(imports)))
    external = set(external_variables)
    parts: list[str] = []
    issues: list[str] = []

    if import_names:
        parts.append('\n'.join(f'import "{name}"' for name in import_names) + '\n')

    for record in records:
        clean = {key: value for key, value in record.parsed.items() if key not in ('imports', 'includes')}
        try:
            parts.append(rebuild_yara_rule(clean))
        except Exception as exc:  # noqa: BLE001 - keep reviewing the remaining rules
            issues.append(f'{record.rule_id}: could not render rule: {exc}')

    text = '\n'.join(part.rstrip('\n') for part in parts)
    if text:
        text += '\n'

    try:
        parsed = Plyara().parse_string(text)
    except ParseError as exc:
        issues.append(f'subset does not reparse: {exc}')
        return text, import_names, tuple(issues)

    names = [entry['rule_name'] for entry in parsed]
    if len(names) != len(set(names)):
        issues.append('subset defines the same rule name more than once')

    for entry in parsed:
        for reference in _extract_reference_names(entry.get('condition_terms') or ()):
            if reference not in names and reference not in external and strict:
                issues.append(
                    f"{entry['rule_name']} references {reference}, which is not in the subset"
                )

    return text, import_names, tuple(dict.fromkeys(issues))


def _build_missing(
    manifest: DeploymentManifest,
    subject: str,
    reason: str,
    message: str,
    *,
    required_by: str | None = None,
    required_selector: tuple[str, tuple[str, ...]] | None = None,
    rejected: Sequence[ApprovalTrace] = (),
) -> MissingApproval:
    """Construct one missing-approval entry."""
    return MissingApproval(
        manifest=manifest.name,
        subject=subject,
        reason=reason,
        message=message,
        required_by=required_by,
        required_selector=required_selector,
        rejected_approvals=tuple(rejected),
    )


def resolve_deployment(
    manifest: DeploymentManifest | Mapping[str, Any],
    groups: Mapping[str, FileGroup] | Sequence[FileGroup],
    approvals: Iterable[Approval | Review | Mapping[str, Any]] = (),
    *,
    strict_references: bool | None = None,
) -> DeploymentReport:
    """Resolve one deployment manifest against groups and existing reviews.

    Args:
        manifest: The deployment manifest, or a JSON-style mapping for one.
        groups: Installed file groups, keyed by name or supplied as a sequence.
        approvals: Existing approvals and/or review records.
        strict_references: Override the manifest's unresolved-reference policy.

    Returns:
        A report containing effective items, approval provenance, the exact
        missing approvals, and a reparsed legal subset of the allowed rules.
    """
    if not isinstance(manifest, DeploymentManifest):
        manifest = DeploymentManifest.from_mapping(manifest)
    group_map = _normalize_groups(groups)
    approval_list = tuple(_iter_approvals(approvals))
    strict = manifest.strict_references if strict_references is None else strict_references

    findings: list[Finding] = []
    missing: list[MissingApproval] = []
    missing_keys: set[tuple[str, str, str | None]] = set()

    def add_missing(entry: MissingApproval) -> None:
        """Record a missing approval once per subject and reason."""
        key = (entry.subject, entry.reason, entry.required_by)
        if key not in missing_keys:
            missing_keys.add(key)
            missing.append(entry)

    all_records = tuple(
        record for group in group_map.values() for record in group.rules
    )
    canonical_records, duplicate_findings = _deduplicate_records(all_records)
    findings.extend(duplicate_findings)

    selected_group_names = manifest.groups or tuple(group_map)
    for group_name in selected_group_names:
        if group_name in group_map:
            continue
        reason = 'optional_group_not_installed' if group_name in manifest.optional_groups else 'missing_group'
        message = (
            f'{manifest.name}: file group {group_name} is declared as optional but is not installed'
            if reason == 'optional_group_not_installed'
            else f'{manifest.name}: file group {group_name} is not installed'
        )
        findings.append(Finding(reason, 'blocker', f'group/{group_name}', message))
        add_missing(_build_missing(manifest, f'group/{group_name}', reason, message))

    index_by_name: dict[str, list[RuleRecord]] = {}
    for record in canonical_records:
        index_by_name.setdefault(record.name, []).append(record)
    frozen_index = {name: tuple(items) for name, items in index_by_name.items()}

    requested_patterns = tuple(manifest.enabled_rules) + tuple(manifest.required_rules)
    for pattern in requested_patterns:
        matches = [record for record in canonical_records if _rule_matches_pattern(record, pattern)]
        if matches:
            continue
        message = f'{manifest.name}: requested rule {pattern} is not present in the installed file groups'
        findings.append(Finding('rule_not_installed', 'blocker', pattern, message))
        add_missing(_build_missing(manifest, pattern, 'rule_not_installed', message))

    candidates: list[RuleRecord] = []
    for record in canonical_records:
        in_selected_group = record.group in selected_group_names
        selected = in_selected_group and _rule_is_selected(record, manifest)
        if _rule_matches_any(record, manifest.enabled_rules) or _rule_matches_any(record, manifest.required_rules):
            selected = True
        if _rule_matches_any(record, manifest.disabled_rules):
            selected = False
        if selected:
            candidates.append(record)

    roots: dict[str, RuleRecord] = {}
    root_traces: dict[str, tuple[tuple[ApprovalTrace, ...], tuple[ApprovalTrace, ...]]] = {}
    initial_reasons: dict[str, list[str]] = {}
    for record in candidates:
        usable, rejected = _approval_state(record, manifest, approval_list)
        root_traces[record.rule_id] = (usable, rejected)
        if usable:
            roots[record.rule_id] = record
            continue

        reason = 'inactive_approval' if rejected else 'no_approval'
        initial_reasons[record.rule_id] = [reason]
        basis = _selector_basis(record, manifest)
        note = _selector_note(basis)
        if rejected:
            approval_ids = ', '.join(trace.approval_id for trace in rejected)
            message = (
                f'{manifest.name}: approval(s) {approval_ids} for {record.rule_id}{note} are not active; '
                f'an active approval is required'
            )
        else:
            message = f'{manifest.name}: no active approval permits {record.rule_id}{note}'
        findings.append(Finding('missing_approval', 'blocker', record.rule_id, message))
        add_missing(_build_missing(
            manifest,
            record.rule_id,
            reason,
            message,
            required_selector=basis,
            rejected=rejected,
        ))

    allowed: dict[str, RuleRecord] = dict(roots)
    allowed_traces: dict[str, tuple[tuple[ApprovalTrace, ...], tuple[ApprovalTrace, ...]]] = dict(root_traces)
    dependency_ids: set[str] = set()
    edges: dict[str, tuple[str, ...]] = {}
    blocked: set[str] = set()
    queue = list(sorted(roots))
    processed: set[str] = set()

    while queue:
        rule_id = queue.pop(0)
        if rule_id in processed:
            continue
        processed.add(rule_id)
        record = allowed[rule_id]
        resolved_dependencies: list[str] = []

        for reference in record.references:
            dependency, problem = _resolve_reference(record, reference, frozen_index)
            if problem == 'undefined':
                if not strict or reference in manifest.external_variables:
                    continue
                message = f'{manifest.name}: {rule_id} references undefined rule {reference}'
                findings.append(Finding('undefined_reference', 'blocker', rule_id, message, {'reference': reference}))
                blocked.add(rule_id)
                continue
            if problem == 'ambiguous':
                message = f'{manifest.name}: {rule_id} references {reference}, which has conflicting definitions'
                findings.append(Finding('ambiguous_reference', 'blocker', rule_id, message, {'reference': reference}))
                blocked.add(rule_id)
                continue

            assert dependency is not None
            resolved_dependencies.append(dependency.rule_id)
            if dependency.rule_id in allowed:
                continue

            usable, rejected = _approval_state(dependency, manifest, approval_list)
            allowed_traces[dependency.rule_id] = (usable, rejected)
            if usable:
                allowed[dependency.rule_id] = dependency
                dependency_ids.add(dependency.rule_id)
                queue.append(dependency.rule_id)
                continue

            reason = 'inactive_approval' if rejected else 'no_approval'
            basis = _selector_basis(dependency, manifest)
            note = _selector_note(basis)
            if rejected:
                approval_ids = ', '.join(trace.approval_id for trace in rejected)
                message = (
                    f'{manifest.name}: dependency {dependency.rule_id}{note} of {rule_id} has no active '
                    f'approval ({approval_ids})'
                )
            else:
                message = (
                    f'{manifest.name}: dependency {dependency.rule_id}{note} of {rule_id} '
                    f'has no active approval'
                )
            findings.append(Finding(
                'missing_dependency_approval',
                'blocker',
                dependency.rule_id,
                message,
                {'required_by': rule_id},
            ))
            add_missing(_build_missing(
                manifest,
                dependency.rule_id,
                reason,
                message,
                required_by=rule_id,
                required_selector=basis,
                rejected=rejected,
            ))
            blocked.add(rule_id)

        edges[rule_id] = tuple(dict.fromkeys(resolved_dependencies))

    changed = True
    while changed:
        changed = False
        for rule_id in tuple(allowed):
            if rule_id in blocked:
                continue
            if any(dependency in blocked for dependency in edges.get(rule_id, ())):
                blocked.add(rule_id)
                changed = True

    allowed = {rule_id: record for rule_id, record in allowed.items() if rule_id not in blocked}
    dependency_ids = {rule_id for rule_id in dependency_ids if rule_id in allowed and rule_id not in roots}

    order, cycles = _topological_order(allowed, edges)
    if cycles:
        cyclic_ids = {rule_id for cycle in cycles for rule_id in cycle}
        for cycle in cycles:
            findings.append(Finding(
                'cyclic_dependency',
                'blocker',
                'cycle:' + ','.join(cycle),
                f'{manifest.name}: these rules can only be reviewed together: {", ".join(cycle)}',
                {'members': list(cycle)},
            ))
        allowed = {rule_id: record for rule_id, record in allowed.items() if rule_id not in cyclic_ids}
        dependency_ids -= cyclic_ids
        order, _ = _topological_order(allowed, edges)

    imports: set[str] = set()
    for record in allowed.values():
        imports.update(record.imports)
        for term in record.parsed.get('condition_terms') or ():
            if isinstance(term, str) and '.' in term:
                prefix = term.split('.', 1)[0]
                if prefix in Plyara.IMPORT_OPTIONS:
                    imports.add(prefix)

    ordered_records = [allowed[rule_id] for rule_id in order if rule_id in allowed]
    subset_text, subset_imports, verification_issues = _render_subset(
        ordered_records,
        imports,
        external_variables=manifest.external_variables,
        strict=strict,
    )

    selected_items: list[SelectedItem] = []
    for record in candidates:
        usable, rejected = root_traces.get(record.rule_id, ((), ()))
        reasons = list(initial_reasons.get(record.rule_id, []))
        selector_keys = set(manifest.selectors) | set(manifest.group_selectors.get(record.group, {}))
        role = 'enabled'
        if record.rule_id in roots:
            if record.rule_id in blocked:
                reasons.extend(
                    f'blocked_by_dependency:{dependency}'
                    for dependency in edges.get(record.rule_id, ())
                    if dependency not in allowed
                )
                if not reasons:
                    reasons.append('blocked_by_dependency')
        elif record.rule_id in dependency_ids:
            role = 'dependency'

        selected_items.append(SelectedItem(
            rule_id=record.rule_id,
            group=record.group,
            name=record.name,
            allowed=record.rule_id in allowed,
            role=role,
            selector_values=record.selector_values(selector_keys),
            source=record.source,
            approvals=usable,
            rejected_approvals=rejected,
            reasons=tuple(dict.fromkeys(reasons)),
            dependencies=edges.get(record.rule_id, ()),
        ))

    for rule_id in sorted(dependency_ids):
        record = allowed[rule_id]
        usable, rejected = allowed_traces.get(rule_id, ((), ()))
        selector_keys = set(manifest.selectors) | set(manifest.group_selectors.get(record.group, {}))
        selected_items.append(SelectedItem(
            rule_id=record.rule_id,
            group=record.group,
            name=record.name,
            allowed=True,
            role='dependency',
            selector_values=record.selector_values(selector_keys),
            source=record.source,
            approvals=usable,
            rejected_approvals=rejected,
            dependencies=edges.get(rule_id, ()),
        ))

    selected_items.sort(key=lambda item: (item.group, item.name, item.role))
    enabled_items = tuple(item for item in selected_items if item.role == 'enabled' and item.allowed)
    dependencies = tuple(item for item in selected_items if item.role == 'dependency' and item.allowed)

    return DeploymentReport(
        manifest=manifest,
        selected_items=tuple(selected_items),
        enabled_items=enabled_items,
        dependencies=dependencies,
        missing_approvals=tuple(missing),
        findings=tuple(findings),
        subset_text=subset_text,
        subset_rule_ids=tuple(record.rule_id for record in ordered_records),
        subset_imports=subset_imports,
        verification_issues=verification_issues,
    )


def review_combinations(
    manifests: Mapping[str, DeploymentManifest | Mapping[str, Any]] | Sequence[DeploymentManifest],
    groups: Mapping[str, FileGroup] | Sequence[FileGroup],
    approvals: Iterable[Approval | Review | Mapping[str, Any]] = (),
    *,
    strict_references: bool | None = None,
) -> dict[str, DeploymentReport]:
    """Resolve several deployment combinations against one installed state."""
    if isinstance(manifests, Mapping):
        items = []
        for key, manifest in manifests.items():
            if isinstance(manifest, DeploymentManifest):
                items.append((str(key), manifest))
            else:
                data = dict(manifest)
                data.setdefault('name', key)
                items.append((str(key), DeploymentManifest.from_mapping(data)))
    else:
        items = []
        for manifest in manifests:
            if isinstance(manifest, Mapping):
                manifest = DeploymentManifest.from_mapping(manifest)
            items.append((manifest.name, manifest))
    return {
        name: resolve_deployment(manifest, groups, approvals, strict_references=strict_references)
        for name, manifest in items
    }


def build_legal_subset(
    manifest: DeploymentManifest | Mapping[str, Any],
    groups: Mapping[str, FileGroup] | Sequence[FileGroup],
    approvals: Iterable[Approval | Review | Mapping[str, Any]] = (),
    *,
    strict_references: bool | None = None,
) -> str:
    """Return only the rendered legal subset for one deployment."""
    return resolve_deployment(
        manifest,
        groups,
        approvals,
        strict_references=strict_references,
    ).subset_text


resolve_manifest = resolve_deployment
review_deployment = resolve_deployment
legal_subset = build_legal_subset


__all__ = [
    'ACTIVE_STATUSES',
    'Approval',
    'ApprovalTrace',
    'DeploymentManifest',
    'DeploymentReport',
    'FileGroup',
    'Finding',
    'MissingApproval',
    'Review',
    'RuleRecord',
    'SelectedItem',
    'build_legal_subset',
    'legal_subset',
    'load_approvals',
    'load_file_group',
    'load_file_groups',
    'load_manifest',
    'manifest_from_mapping',
    'parse_file_group',
    'parse_file_groups',
    'resolve_deployment',
    'resolve_manifest',
    'review_combinations',
    'review_deployment',
    'upgrade_file_group',
]
