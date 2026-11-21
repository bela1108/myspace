"""
License policy decisions for CycloneDX components.

The model in :mod:`cyclonedx.model.license` describes what a BOM says.  This
module answers a different question: may the components in a BOM be distributed
through a particular channel and release scope, given a channel policy?

SPDX expressions are evaluated as expressions rather than as sets:

* ``A AND B`` requires ``A`` and ``B``;
* ``A OR B`` permits either branch;
* ``A WITH E`` is one license condition with an exception, not a separate
  ``AND`` condition.

All result objects keep references to the original :class:`~cyclonedx.model.bom.Bom`,
:class:`~cyclonedx.model.component.Component`, and license model instances.  This
makes a decision auditable against the source document.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, Optional, Union

from license_expression import get_spdx_licensing

from .._internal.enum import DecisionEnum as _DecisionEnum
from ..spdx import fixup_id, is_supported_id
from .license import (
    DisjunctiveLicense,
    License,
    LicenseAcknowledgement,
    LicenseExpression,
    LicenseExpressionDetails,
)

if TYPE_CHECKING:  # pragma: no cover
    from .bom import Bom
    from .component import Component, ComponentScope

__all__ = [
    'ArtifactScope',
    'ChannelPolicy',
    'ChannelLicensePolicy',
    'ComponentDecision',
    'ComponentLicenseDecision',
    'ConditionConflict',
    'ConflictGroup',
    'DecisionStatus',
    'DistributionChannelPolicy',
    'DistributionDecision',
    'DistributionPolicy',
    'DistributionScope',
    'DistributionType',
    'EvidenceSource',
    'EvidenceStatus',
    'LicenseCombination',
    'LicenseComplianceEngine',
    'LicenseConflict',
    'LicenseConflictGroup',
    'LicenseConflictReason',
    'LicenseDecision',
    'LicenseDecisionAPI',
    'LicenseDecisionEngine',
    'LicenseDecisionError',
    'LicenseDecisionOutcome',
    'LicenseDecisionResult',
    'LicenseDecisionStatus',
    'LicenseEvidenceStatus',
    'LicensePolicy',
    'LicensePolicyEngine',
    'LicenseRule',
    'LicenseSelection',
    'LicenseSource',
    'LicenseAssessment',
    'LicenseUnknownPolicy',
    'LicenseVerdict',
    'LicensingPolicy',
    'ReleaseScope',
    'SelectedLicense',
    'UnknownLicensePolicy',
    'check_license_policy',
    'check_distribution_compliance',
    'can_distribute',
    'decide_license_compliance',
    'decide_licenses',
    'decide_distribution',
    'evaluate_license_policy',
    'evaluate_license_compliance',
    'evaluate_licenses',
    'is_distributable',
]


class ReleaseScope(_DecisionEnum):
    """The artifact scope that is being distributed."""

    SOURCE = 'source'
    BINARY = 'binary'
    ALL = 'all'

    # Common spellings used by SBOM and release tooling.
    SOURCE_DISTRIBUTION = 'source'
    SOURCE_CODE = 'source'
    BINARY_DISTRIBUTION = 'binary'
    BINARY_ARTIFACT = 'binary'

    @classmethod
    def coerce(cls, value: Optional[Union['ReleaseScope', str]]) -> 'ReleaseScope':
        if value is None:
            return cls.BINARY
        if isinstance(value, cls):
            return value
        normalized = str(value).strip().lower().replace('_', '-')
        if normalized in {'source', 'src', 'source-code', 'source-distribution'}:
            return cls.SOURCE
        if normalized in {'binary', 'bin', 'binary-artifact', 'binary-distribution'}:
            return cls.BINARY
        if normalized in {'all', 'any', '*'}:
            return cls.ALL
        raise ValueError(f'unknown release scope: {value!r}')


# Descriptive aliases for callers that use artifact/channel terminology.
DistributionScope = ReleaseScope
DistributionType = ReleaseScope
ArtifactScope = ReleaseScope


class LicenseEvidenceStatus(_DecisionEnum):
    """Where a license statement sits in the licensing workflow."""

    DECLARED = 'declared'
    CONCLUDED = 'concluded'
    OBSERVED = 'observed'
    UNSPECIFIED = 'unspecified'

    UNKNOWN = 'unspecified'


EvidenceStatus = LicenseEvidenceStatus


class LicenseSource(_DecisionEnum):
    """The part of the BOM from which a license statement originated."""

    COMPONENT = 'component'
    EVIDENCE = 'evidence'


EvidenceSource = LicenseSource


class LicenseUnknownPolicy(_DecisionEnum):
    """How to handle licenses that are not known to the policy."""

    ALLOW = 'allow'
    DENY = 'deny'
    REVIEW = 'review'

    @classmethod
    def coerce(cls, value: Optional[Union['LicenseUnknownPolicy', str, bool]]) -> 'LicenseUnknownPolicy':
        if value is None:
            return cls.DENY
        if isinstance(value, cls):
            return value
        if isinstance(value, bool):
            return cls.ALLOW if value else cls.DENY
        normalized = str(value).strip().lower().replace('_', '-')
        aliases = {
            'allow': cls.ALLOW, 'allowed': cls.ALLOW, 'permit': cls.ALLOW,
            'deny': cls.DENY, 'denied': cls.DENY, 'block': cls.DENY,
            'review': cls.REVIEW, 'review-required': cls.REVIEW, 'unknown': cls.REVIEW,
        }
        if normalized not in aliases:
            raise ValueError(f'unknown unknown-license policy: {value!r}')
        return aliases[normalized]


UnknownLicensePolicy = LicenseUnknownPolicy


class LicenseDecisionStatus(_DecisionEnum):
    """Top-level outcome of a policy decision."""

    ALLOWED = 'allowed'
    DENIED = 'denied'
    REVIEW = 'review'
    ALLOW = 'allowed'
    DENY = 'denied'


DecisionStatus = LicenseDecisionStatus
LicenseVerdict = LicenseDecisionStatus


class LicenseConflictReason(_DecisionEnum):
    """Machine-readable reason attached to a rejected license condition."""

    DENIED_LICENSE = 'denied-license'
    LICENSE_NOT_ALLOWED = 'license-not-allowed'
    UNKNOWN_LICENSE = 'unknown-license'
    UNKNOWN_EXCEPTION = 'unknown-exception'
    DENIED_EXCEPTION = 'denied-exception'
    EXCEPTION_NOT_ALLOWED = 'exception-not-allowed'
    MISSING_LICENSE = 'missing-license'
    INVALID_EXPRESSION = 'invalid-expression'
    INCOMPATIBLE_LICENSES = 'incompatible-licenses'
    EVIDENCE_NOT_ACCEPTED = 'evidence-not-accepted'
    REVIEW_REQUIRED = 'review-required'
    NOT_ALLOWED = 'license-not-allowed'
    UNKNOWN = 'unknown-license'
    INCOMPATIBLE = 'incompatible-licenses'


class LicenseDecisionError(ValueError):
    """Raised for an invalid decision request."""


_LICENSING = get_spdx_licensing()
_KNOWN_SYMBOLS = frozenset(_LICENSING.known_symbols)


def _norm(value: str) -> str:
    """Return a stable, case-insensitive policy key."""
    return re.sub(r'\s+', ' ', str(value).strip()).lower()


def _norm_atom(value: str) -> str:
    canonical = fixup_id(value) or value
    return _norm(canonical)


def _split_with(value: str) -> tuple[str, Optional[str]]:
    parts = re.split(r'\s+WITH\s+', value.strip(), maxsplit=1, flags=re.IGNORECASE)
    if len(parts) == 2 and parts[0].strip() and parts[1].strip():
        return parts[0].strip(), parts[1].strip()
    return value.strip(), None


def _norm_rule_key(value: str) -> str:
    base, exception = _split_with(value)
    if exception is None:
        return _norm_atom(base)
    return f'{_norm_atom(base)} with {_norm_atom(exception)}'


def _canonical_license(value: str) -> str:
    base, exception = _split_with(value)
    base = fixup_id(base) or base
    if exception is None:
        return base
    return f'{base} WITH {fixup_id(exception) or exception}'


def _coerce_strings(values: Optional[Iterable[str]]) -> Optional[frozenset[str]]:
    if values is None:
        return None
    if isinstance(values, str):
        values = (values,)
    return frozenset(_norm_rule_key(v) for v in values)


@dataclass(frozen=True)
class LicenseRule:
    """An explicit, optionally-scoped policy rule for one license condition.

    A rule for ``GPL-2.0-only WITH Classpath-exception-2.0`` is matched as a
    whole.  Separate base-license and exception rules can still be expressed via
    a rule with ``license='GPL-2.0-only'`` and ``exception='Classpath-exception-2.0'``.
    """

    license: str
    allowed: bool = True
    exception: Optional[str] = None
    channel: Optional[str] = None
    release_scope: Optional[Union[ReleaseScope, str]] = None
    scope: Optional[Union[ReleaseScope, str]] = None
    component_scope: Optional[ComponentScope] = None
    reason: Optional[str] = None

    @property
    def key(self) -> str:
        if self.exception:
            return _norm_rule_key(f'{self.license} WITH {self.exception}')
        return _norm_rule_key(self.license)

    @property
    def base_key(self) -> str:
        return _norm_atom(self.license)

    @property
    def exception_key(self) -> Optional[str]:
        return _norm_atom(self.exception) if self.exception else None


@dataclass(frozen=True)
class _ScopePolicy:
    allowed: Optional[frozenset[str]] = None
    denied: frozenset[str] = frozenset()
    preferred: Optional[tuple[str, ...]] = None
    component_scopes: Optional[frozenset[ComponentScope]] = None
    include_external: Optional[bool] = None


class LicensePolicy:
    """A policy for one distribution channel.

    ``allowed`` is an allow-list.  If it is supplied, a license that is not in
    the list is denied.  ``denied`` always denies an explicitly named license.
    An explicit deny wins over an allow.

    Unknown SPDX licenses are denied by default.  Custom ``LicenseRef-*``
    licenses are treated as unknown unless the policy names them explicitly or
    ``unknown_license_policy`` is set to allow them.

    Source and binary releases often have different policies.  They can be
    expressed with ``source_allowed``/``binary_allowed`` (and the corresponding
    denied variants), or with ``by_release_scope``.
    """

    def __init__(
        self,
        channel: Optional[str] = None,
        *,
        allowed: Optional[Iterable[str]] = None,
        denied: Optional[Iterable[str]] = None,
        allowed_licenses: Optional[Iterable[str]] = None,
        denied_licenses: Optional[Iterable[str]] = None,
        allowed_exceptions: Optional[Iterable[str]] = None,
        denied_exceptions: Optional[Iterable[str]] = None,
        unknown_license_policy: Optional[Union[LicenseUnknownPolicy, str, bool]] = None,
        unknown_policy: Optional[Union[LicenseUnknownPolicy, str, bool]] = None,
        allow_unknown: Optional[bool] = None,
        allow_unknown_licenses: Optional[bool] = None,
        allow_unknown_exceptions: bool = False,
        exception_grants: Union[bool, Iterable[str]] = False,
        preferred_licenses: Optional[Iterable[str]] = None,
        preferred: Optional[Iterable[str]] = None,
        incompatible_licenses: Optional[Iterable[Union[tuple[str, str], Sequence[str]]]] = None,
        forbidden_combinations: Optional[Iterable[Iterable[str]]] = None,
        rules: Optional[Iterable[LicenseRule]] = None,
        source_allowed: Optional[Iterable[str]] = None,
        source_denied: Optional[Iterable[str]] = None,
        binary_allowed: Optional[Iterable[str]] = None,
        binary_denied: Optional[Iterable[str]] = None,
        source_allowed_licenses: Optional[Iterable[str]] = None,
        source_denied_licenses: Optional[Iterable[str]] = None,
        binary_allowed_licenses: Optional[Iterable[str]] = None,
        binary_denied_licenses: Optional[Iterable[str]] = None,
        source_component_scopes: Optional[Iterable[ComponentScope]] = None,
        binary_component_scopes: Optional[Iterable[ComponentScope]] = None,
        by_release_scope: Optional[Mapping[Union[ReleaseScope, str], Any]] = None,
        evidence_statuses: Optional[Iterable[Union[LicenseEvidenceStatus, str]]] = None,
        accepted_evidence: Optional[Iterable[Union[LicenseEvidenceStatus, str]]] = None,
        evidence_policy: Optional[Union[LicenseEvidenceStatus, str]] = None,
        include_component: Optional[Callable[[Component, ReleaseScope], bool]] = None,
        include_external: Optional[bool] = None,
        description: Optional[str] = None,
        reason: Optional[str] = None,
        **extra: Any,
    ) -> None:
        self.channel = channel or extra.pop('channel_id', None) or 'default'
        self.description = description or reason
        default_scope = extra.get('release_scope', extra.get('distribution_scope'))
        self.default_release_scope: Optional[ReleaseScope] = (
            ReleaseScope.coerce(default_scope) if default_scope is not None else None
        )

        if allowed is None:
            allowed = allowed_licenses
        elif allowed_licenses is not None:
            raise TypeError('use either `allowed` or `allowed_licenses`, not both')
        if denied is None:
            denied = denied_licenses
        elif denied_licenses is not None:
            raise TypeError('use either `denied` or `denied_licenses`, not both')

        self._allowed = _coerce_strings(allowed)
        self._denied = _coerce_strings(denied) or frozenset()
        self.allowed_exceptions = _coerce_strings(allowed_exceptions)
        self.denied_exceptions = _coerce_strings(denied_exceptions) or frozenset()
        self.unknown_license_policy = LicenseUnknownPolicy.coerce(
            unknown_license_policy if unknown_license_policy is not None
            else unknown_policy if unknown_policy is not None
            else allow_unknown if allow_unknown is not None
            else allow_unknown_licenses
        )
        self.allow_unknown_exceptions = allow_unknown_exceptions
        if exception_grants is True:
            self.exception_grants: Union[bool, frozenset[str]] = True
        elif exception_grants is False:
            self.exception_grants = False
        else:
            self.exception_grants = frozenset(
                _norm_atom(v)
                for v in ((exception_grants,) if isinstance(exception_grants, str) else exception_grants)
            )

        preferred_values = preferred_licenses if preferred_licenses is not None else preferred
        if isinstance(preferred_values, str):
            preferred_values = (preferred_values,)
        self.preferred_licenses = tuple(_canonical_license(v) for v in preferred_values or ())
        self._preferred_order = tuple(_norm_rule_key(v) for v in self.preferred_licenses)

        self.rules = (rules,) if isinstance(rules, LicenseRule) else tuple(rules or ())

        incompatible: list[tuple[str, str]] = []
        if isinstance(incompatible_licenses, tuple) and len(incompatible_licenses) == 2 and all(
            isinstance(value, str) for value in incompatible_licenses
        ):
            incompatible_licenses = (incompatible_licenses,)
        for pair in incompatible_licenses or ():
            values = tuple(pair)
            if len(values) != 2:
                raise ValueError(f'incompatible license declaration must have two values: {pair!r}')
            incompatible.append((_norm_rule_key(values[0]), _norm_rule_key(values[1])))
        for combination in forbidden_combinations or ():
            values = tuple(combination)
            for index, first in enumerate(values):
                for second in values[index + 1:]:
                    incompatible.append((_norm_atom(first), _norm_atom(second)))
        self.incompatible_licenses = tuple(sorted(set(incompatible)))

        statuses = evidence_statuses if evidence_statuses is not None else accepted_evidence
        if statuses is None and evidence_policy is not None:
            statuses = (evidence_policy,)
        if statuses is None:
            statuses = extra.get('evidence_status', extra.get('accepted_evidence_statuses'))
        self.evidence_statuses = self._coerce_evidence_statuses(statuses)

        self.include_component = include_component
        self.include_external = include_external

        scope_policies: dict[ReleaseScope, _ScopePolicy] = {}

        def add_scope_policy(
            scope: ReleaseScope,
            *,
            scope_allowed: Optional[Iterable[str]] = None,
            scope_denied: Optional[Iterable[str]] = None,
            scope_component_scopes: Optional[Iterable[ComponentScope]] = None,
            scope_preferred: Optional[Iterable[str]] = None,
            scope_include_external: Optional[bool] = None,
        ) -> None:
            existing = scope_policies.get(scope, _ScopePolicy())
            scope_policies[scope] = _ScopePolicy(
                allowed=_coerce_strings(scope_allowed) if scope_allowed is not None else existing.allowed,
                denied=(existing.denied | (_coerce_strings(scope_denied) or frozenset())),
                preferred=(
                    tuple(_norm_rule_key(v) for v in scope_preferred)
                    if scope_preferred is not None
                    else existing.preferred
                ),
                component_scopes=(
                    _coerce_component_scopes(scope_component_scopes)
                    if scope_component_scopes is not None
                    else existing.component_scopes
                ),
                include_external=(
                    scope_include_external
                    if scope_include_external is not None
                    else existing.include_external
                ),
            )

        add_scope_policy(
            ReleaseScope.SOURCE,
            scope_allowed=source_allowed if source_allowed is not None else source_allowed_licenses,
            scope_denied=source_denied if source_denied is not None else source_denied_licenses,
            scope_component_scopes=source_component_scopes,
        )
        add_scope_policy(
            ReleaseScope.BINARY,
            scope_allowed=binary_allowed if binary_allowed is not None else binary_allowed_licenses,
            scope_denied=binary_denied if binary_denied is not None else binary_denied_licenses,
            scope_component_scopes=binary_component_scopes,
        )

        for scope_key, scope_value in (by_release_scope or {}).items():
            scope = ReleaseScope.coerce(scope_key)
            if isinstance(scope_value, LicensePolicy):
                scope_allowed = scope_value.allowed
                scope_denied = scope_value.denied
                scope_preferred = scope_value.preferred_licenses
                scope_component_scopes = None
                scope_include_external = scope_value.include_external
            elif isinstance(scope_value, Mapping):
                scope_allowed = (
                    scope_value.get('allowed')
                    or scope_value.get('allowed_licenses')
                    or scope_value.get('licenses')
                )
                scope_denied = (
                    scope_value.get('denied')
                    or scope_value.get('denied_licenses')
                )
                scope_preferred = scope_value.get('preferred') or scope_value.get('preferred_licenses')
                scope_component_scopes = (
                    scope_value.get('component_scopes')
                    or scope_value.get('components')
                )
                scope_include_external = scope_value.get('include_external')
            else:
                scope_allowed = tuple(scope_value)
                scope_denied = None
                scope_preferred = None
                scope_component_scopes = None
                scope_include_external = None
            add_scope_policy(
                scope,
                scope_allowed=scope_allowed,
                scope_denied=scope_denied,
                scope_component_scopes=scope_component_scopes,
                scope_preferred=scope_preferred,
                scope_include_external=scope_include_external,
            )

        self._scope_policies = scope_policies

        # Aliases accepted for callers coming from different policy engines.
        if 'whitelist' in extra and self._allowed is None:
            self._allowed = _coerce_strings(extra['whitelist'])
        if 'blacklist' in extra:
            self._denied = self._denied | (_coerce_strings(extra['blacklist']) or frozenset())
        for unknown_alias in ('unknown', 'on_unknown', 'unknown_licenses'):
            if unknown_alias in extra:
                self.unknown_license_policy = LicenseUnknownPolicy.coerce(extra[unknown_alias])
                break
        if self._allowed is None:
            for alias in (
                'allow', 'permit', 'permitted', 'permitted_licenses',
                'approved', 'approved_licenses', 'licenses',
            ):
                if alias in extra and not isinstance(extra[alias], Mapping):
                    self._allowed = _coerce_strings(extra[alias])
                    break
        for alias in (
            'deny', 'prohibit', 'prohibited', 'prohibited_licenses',
            'forbidden', 'forbidden_licenses',
        ):
            if alias in extra:
                self._denied = self._denied | (_coerce_strings(extra[alias]) or frozenset())
        license_map = extra.get('license_map') or extra.get('licenses_by_id')
        if not license_map and isinstance(extra.get('licenses'), Mapping):
            license_map = extra['licenses']
        if isinstance(license_map, Mapping):
            mapped_allowed = [key for key, value in license_map.items() if bool(value)]
            mapped_denied = [key for key, value in license_map.items() if not bool(value)]
            if self._allowed is None:
                self._allowed = _coerce_strings(mapped_allowed)
            self._denied = self._denied | (_coerce_strings(mapped_denied) or frozenset())

    @staticmethod
    def _coerce_evidence_statuses(
        values: Optional[Iterable[Union[LicenseEvidenceStatus, str]]]
    ) -> Optional[frozenset[LicenseEvidenceStatus]]:
        if values is None:
            return None
        if isinstance(values, (str, LicenseEvidenceStatus)):
            values = (values,)
        result = set()
        for value in values:
            if isinstance(value, LicenseEvidenceStatus):
                result.add(value)
                continue
            normalized = str(value).strip().lower()
            aliases = {
                'declared': LicenseEvidenceStatus.DECLARED,
                'concluded': LicenseEvidenceStatus.CONCLUDED,
                'observed': LicenseEvidenceStatus.OBSERVED,
                'evidence': LicenseEvidenceStatus.OBSERVED,
                'unspecified': LicenseEvidenceStatus.UNSPECIFIED,
                'unknown': LicenseEvidenceStatus.UNSPECIFIED,
            }
            if normalized not in aliases:
                raise ValueError(f'unknown evidence status: {value!r}')
            result.add(aliases[normalized])
        return frozenset(result)

    @property
    def allowed(self) -> Optional[frozenset[str]]:
        return self._allowed

    @property
    def channel_id(self) -> str:
        return self.channel

    @property
    def name(self) -> str:
        return self.channel

    @property
    def denied(self) -> frozenset[str]:
        return self._denied

    @property
    def allowed_licenses(self) -> Optional[frozenset[str]]:
        return self._allowed

    @property
    def denied_licenses(self) -> frozenset[str]:
        return self._denied

    def for_release_scope(self, release_scope: ReleaseScope) -> '_EffectivePolicy':
        release_scope = ReleaseScope.coerce(release_scope)
        scope_policy = self._scope_policies.get(release_scope, _ScopePolicy())
        allowed = scope_policy.allowed if scope_policy.allowed is not None else self._allowed
        denied = self._denied | scope_policy.denied
        preferred = scope_policy.preferred if scope_policy.preferred is not None else self._preferred_order
        return _EffectivePolicy(
            policy=self,
            release_scope=release_scope,
            allowed=allowed,
            denied=denied,
            preferred=preferred,
            component_scopes=(
                scope_policy.component_scopes
                if scope_policy.component_scopes is not None
                else _default_component_scopes(release_scope)
            ),
            include_external=(
                scope_policy.include_external
                if scope_policy.include_external is not None
                else self.include_external
            ),
        )

    def evaluate(
        self,
        bom: Bom,
        *,
        release_scope: Optional[Union[ReleaseScope, str]] = None,
        component_scope: Optional[Any] = None,
        components: Optional[Iterable[Component]] = None,
        include_metadata_component: bool = False,
        scope: Optional[Union[ReleaseScope, str]] = None,
        distribution_scope: Optional[Union[ReleaseScope, str]] = None,
    ) -> 'LicenseDecision':
        """Evaluate this policy against a BOM."""
        return decide_license_compliance(
            bom, self,
            release_scope=release_scope if release_scope is not None else (scope or distribution_scope),
            component_scope=component_scope,
            components=components,
            include_metadata_component=include_metadata_component,
        )

    decide = evaluate
    check = evaluate
    assess = evaluate

    def __repr__(self) -> str:
        return (
            f'<LicensePolicy channel={self.channel!r}, allowed={self._allowed!r}, '
            f'denied={self._denied!r}>'
        )


ChannelPolicy = LicensePolicy
DistributionPolicy = LicensePolicy
LicensingPolicy = LicensePolicy
ChannelLicensePolicy = LicensePolicy
DistributionChannelPolicy = LicensePolicy


def _default_component_scopes(release_scope: ReleaseScope) -> Optional[frozenset[ComponentScope]]:
    from .component import ComponentScope

    if release_scope is ReleaseScope.SOURCE:
        return frozenset({ComponentScope.REQUIRED, ComponentScope.OPTIONAL})
    if release_scope is ReleaseScope.BINARY:
        return frozenset({ComponentScope.REQUIRED})
    return None


@dataclass(frozen=True)
class _EffectivePolicy:
    policy: LicensePolicy
    release_scope: ReleaseScope
    allowed: Optional[frozenset[str]]
    denied: frozenset[str]
    preferred: tuple[str, ...]
    component_scopes: Optional[frozenset[ComponentScope]]
    include_external: Optional[bool]


@dataclass(frozen=True)
class _Atom:
    base: str
    exception: Optional[str] = None
    known: bool = False
    custom: bool = False

    @property
    def key(self) -> str:
        if self.exception:
            return f'{self.base} WITH {self.exception}'
        return self.base

    @property
    def normalized_key(self) -> str:
        return _norm_rule_key(self.key)

    @property
    def is_unknown(self) -> bool:
        return not self.known


@dataclass(frozen=True)
class _Binding:
    license: License
    status: LicenseEvidenceStatus
    source: LicenseSource


@dataclass(frozen=True)
class _AtomVerdict:
    allowed: bool
    reason: Optional[LicenseConflictReason] = None
    detail: Optional[str] = None
    rule: Optional[LicenseRule] = None
    exception_known: Optional[bool] = None


@dataclass
class _Alternative:
    atoms: tuple[_Atom, ...]
    order: int
    expression: str
    binding: _Binding
    bindings: tuple[_Binding, ...] = ()

    @property
    def key(self) -> tuple[str, ...]:
        return tuple(atom.normalized_key for atom in self.atoms)

    def binding_for(self, index: int) -> _Binding:
        if self.bindings:
            return self.bindings[index]
        return self.binding


@dataclass(frozen=True)
class LicenseSelection:
    """One license condition selected for a component."""

    component: Component
    license: License
    expression: str
    atom: str
    license_id: Optional[str]
    exception: Optional[str]
    evidence_status: LicenseEvidenceStatus
    acknowledgement: Optional[LicenseAcknowledgement]
    source: LicenseSource
    is_unknown: bool
    is_custom: bool
    expression_details: Optional[LicenseExpressionDetails] = None
    component_bom_ref: Optional[str] = None
    license_bom_ref: Optional[str] = None

    @property
    def evidence(self) -> LicenseEvidenceStatus:
        return self.evidence_status

    @property
    def bom_ref(self) -> Optional[str]:
        return self.license_bom_ref or self.component_bom_ref

    @property
    def unknown(self) -> bool:
        return self.is_unknown

    @property
    def selected_license(self) -> str:
        return self.atom

    @property
    def license_expression(self) -> str:
        return self.atom

    @property
    def condition(self) -> str:
        return self.atom

    @property
    def source_license(self) -> License:
        return self.license

    @property
    def source_component(self) -> Component:
        return self.component

    def __str__(self) -> str:
        return self.atom


SelectedLicense = LicenseSelection


@dataclass(frozen=True)
class LicenseConflict:
    """A single condition that prevents a component's license choice."""

    reason: LicenseConflictReason
    detail: str
    component: Optional[Component] = None
    license: Optional[License] = None
    expression: Optional[str] = None
    atom: Optional[str] = None
    license_id: Optional[str] = None
    exception: Optional[str] = None
    evidence_status: Optional[LicenseEvidenceStatus] = None
    source: Optional[LicenseSource] = None
    is_unknown: bool = False
    condition: Optional[str] = None
    related_component: Optional[Component] = None
    related_license: Optional[str] = None
    rule: Optional[LicenseRule] = None

    @property
    def component_name(self) -> Optional[str]:
        return self.component.name if self.component is not None else None

    @property
    def component_bom_ref(self) -> Optional[str]:
        return self.component.bom_ref.value if self.component is not None else None

    @property
    def conditions(self) -> tuple[str, ...]:
        values = []
        if self.condition:
            values.append(self.condition)
        if self.related_license:
            values.append(self.related_license)
        if not values and self.atom:
            values.append(self.atom)
        if not values:
            values.append(self.detail)
        return tuple(values)

    @property
    def rejection_reason(self) -> str:
        return self.detail

    @property
    def explanation(self) -> str:
        return self.detail

    @property
    def unknown(self) -> bool:
        return self.is_unknown

    def __str__(self) -> str:
        component = f'component {self.component.name!r}: ' if self.component is not None else ''
        return f'{component}{self.detail}'


ConditionConflict = LicenseConflict


@dataclass(frozen=True)
class LicenseConflictGroup:
    """All conditions that make one concrete license branch impossible."""

    expression: str
    conditions: tuple[LicenseConflict, ...]
    component: Optional[Component] = None
    reason: Optional[LicenseConflictReason] = None

    @property
    def conflicts(self) -> tuple[LicenseConflict, ...]:
        return self.conditions

    @property
    def rejection_reasons(self) -> tuple[str, ...]:
        return tuple(conflict.detail for conflict in self.conditions)

    def __str__(self) -> str:
        return ', '.join(str(conflict) for conflict in self.conditions)


ConflictGroup = LicenseConflictGroup


@dataclass(frozen=True)
class LicenseCombination:
    """One satisfiable or rejected combination of license conditions."""

    expression: str
    licenses: tuple[LicenseSelection, ...]
    allowed: bool
    conflicts: tuple[LicenseConflict, ...] = ()
    component: Optional[Component] = None
    order: int = 0

    @property
    def atoms(self) -> tuple[str, ...]:
        return tuple(selection.atom for selection in self.licenses)

    @property
    def license_ids(self) -> tuple[str, ...]:
        return tuple(
            selection.license_id or selection.atom
            for selection in self.licenses
        )

    @property
    def selections(self) -> tuple[LicenseSelection, ...]:
        return self.licenses

    def __iter__(self):
        return iter(self.licenses)

    def __len__(self) -> int:
        return len(self.licenses)

    def __str__(self) -> str:
        return self.expression


@dataclass(frozen=True)
class ComponentLicenseDecision:
    """License decision for one component in the evaluated scope."""

    component: Component
    allowed: bool
    expression: Optional[str]
    alternatives: tuple[LicenseCombination, ...]
    selected: Optional[LicenseCombination]
    conflicts: tuple[LicenseConflict, ...]
    conflict_groups: tuple[LicenseConflictGroup, ...]
    evidence_status: LicenseEvidenceStatus
    reason: Optional[str] = None

    @property
    def selected_licenses(self) -> tuple[LicenseSelection, ...]:
        return self.selected.licenses if self.selected is not None else ()

    @property
    def selected_expression(self) -> Optional[str]:
        return self.selected.expression if self.selected is not None else None

    @property
    def license_combination(self) -> Optional[LicenseCombination]:
        return self.selected

    @property
    def rejection_reasons(self) -> tuple[str, ...]:
        return tuple(conflict.detail for conflict in self.conflicts)

    @property
    def selected_atoms(self) -> tuple[str, ...]:
        return tuple(selection.atom for selection in self.selected_licenses)

    @property
    def explanation(self) -> Optional[str]:
        return self.reason

    @property
    def component_bom_ref(self) -> Optional[str]:
        return self.component.bom_ref.value

    @property
    def observed_licenses(self) -> tuple[License, ...]:
        evidence = self.component.evidence
        return tuple(evidence.licenses) if evidence is not None else ()

    @property
    def declared_licenses(self) -> tuple[License, ...]:
        return tuple(
            license for license in self.component.licenses
            if _status_for_license(license) is LicenseEvidenceStatus.DECLARED
        )

    @property
    def concluded_licenses(self) -> tuple[License, ...]:
        return tuple(
            license for license in self.component.licenses
            if _status_for_license(license) is LicenseEvidenceStatus.CONCLUDED
        )

    @property
    def denied(self) -> bool:
        return not self.allowed

    def __str__(self) -> str:
        result = 'allowed' if self.allowed else 'denied'
        return f'<ComponentLicenseDecision {self.component.name!r}: {result}>'


@dataclass(frozen=True)
class LicenseDecision:
    """Result of evaluating a BOM against a channel policy."""

    bom: Bom
    policy: LicensePolicy
    channel: str
    release_scope: ReleaseScope
    status: LicenseDecisionStatus
    components: tuple[ComponentLicenseDecision, ...]
    combination: tuple[LicenseCombination, ...]
    conflicts: tuple[LicenseConflict, ...]
    conflict_groups: tuple[LicenseConflictGroup, ...]
    excluded_components: tuple[Component, ...] = ()
    reason: Optional[str] = None

    @property
    def allowed(self) -> bool:
        return self.status is LicenseDecisionStatus.ALLOWED

    @property
    def is_allowed(self) -> bool:
        return self.allowed

    @property
    def denied(self) -> bool:
        return not self.allowed

    @property
    def accepted(self) -> bool:
        return self.allowed

    @classmethod
    def evaluate(
        cls,
        bom: Bom,
        policy: Union[LicensePolicy, Mapping[str, Any]],
        **kwargs: Any,
    ) -> 'LicenseDecision':
        """Evaluate a BOM and policy, returning a decision result."""
        return decide_license_compliance(bom, policy, **kwargs)

    @property
    def outcome(self) -> LicenseDecisionStatus:
        return self.status

    @property
    def source_bom(self) -> Bom:
        return self.bom

    @property
    def component_decisions(self) -> tuple[ComponentLicenseDecision, ...]:
        return self.components

    @property
    def license_combination(self) -> tuple[LicenseCombination, ...]:
        return self.combination

    @property
    def selected_combination(self) -> tuple[LicenseCombination, ...]:
        return self.combination

    @property
    def selected_by_component(self) -> dict[str, LicenseCombination]:
        return {
            decision.component.bom_ref.value or decision.component.name: combination
            for decision in self.components
            for combination in ((decision.selected,) if decision.selected is not None else ())
        }

    @property
    def selected(self) -> tuple[LicenseSelection, ...]:
        return tuple(
            selection
            for combination in self.combination
            for selection in combination.licenses
        )

    @property
    def selected_licenses(self) -> tuple[LicenseSelection, ...]:
        return self.selected

    @property
    def selected_expression(self) -> Optional[str]:
        if not self.combination:
            return None
        return ' AND '.join(
            f'({combination.expression})'
            if len(combination.licenses) > 1 and ' OR ' in combination.expression.upper()
            else combination.expression
            for combination in self.combination
        )

    @property
    def denied_components(self) -> tuple[ComponentLicenseDecision, ...]:
        return tuple(component for component in self.components if not component.allowed)

    @property
    def conditions(self) -> tuple[str, ...]:
        return tuple(condition for conflict in self.conflicts for condition in conflict.conditions)

    @property
    def rejection_reasons(self) -> tuple[str, ...]:
        return tuple(conflict.detail for conflict in self.conflicts)

    @property
    def reasons(self) -> tuple[str, ...]:
        return self.rejection_reasons

    @property
    def explanation(self) -> Optional[str]:
        return self.reason

    @property
    def unknown_license_conflicts(self) -> tuple[LicenseConflict, ...]:
        return tuple(conflict for conflict in self.conflicts if conflict.is_unknown)

    def __bool__(self) -> bool:
        return self.allowed

    def __str__(self) -> str:
        return (
            f'<LicenseDecision channel={self.channel!r} scope={self.release_scope.value!r} '
            f'status={self.status.value!r}>'
        )


LicenseDecisionResult = LicenseDecision


def _atom_for_disjunctive(license: DisjunctiveLicense) -> _Atom:
    value = license.id or license.name or ''
    known = bool(license.id and (is_supported_id(license.id) or fixup_id(license.id)))
    custom = value.lower().startswith(('licenseref-', 'documentref-'))
    return _Atom(base=_canonical_license(value), known=known, custom=custom)


def _atom_from_expression(node: Any) -> _Atom:
    license_symbol = getattr(node, 'license_symbol', None)
    exception_symbol = getattr(node, 'exception_symbol', None)
    if license_symbol is not None and exception_symbol is not None:
        base = str(getattr(license_symbol, 'key', license_symbol))
        exception = str(getattr(exception_symbol, 'key', exception_symbol))
        return _Atom(
            base=_canonical_license(base),
            exception=_canonical_license(exception),
            known=bool(is_supported_id(base) or fixup_id(base)),
            custom=base.lower().startswith(('licenseref-', 'documentref-')),
        )
    key = getattr(node, 'key', None)
    if key is None:
        key = getattr(node, 'symbol', None)
    if key is None:
        key = str(node)
    return _Atom(
        base=_canonical_license(str(key)),
        known=bool(is_supported_id(str(key)) or fixup_id(str(key))),
        custom=str(key).lower().startswith(('licenseref-', 'documentref-')),
    )


def _parse_license(license: License) -> list[_Alternative]:
    if isinstance(license, DisjunctiveLicense):
        atom = _atom_for_disjunctive(license)
        return [_Alternative((atom,), 0, atom.key, _Binding(
            license, _status_for_license(license), LicenseSource.COMPONENT,
        ))]

    expression = license.value
    try:
        node = _LICENSING.parse(expression)
    except Exception as exc:
        raise LicenseDecisionError(f'invalid SPDX expression {expression!r}: {exc}') from exc

    binding = _Binding(license, _status_for_license(license), LicenseSource.COMPONENT)
    return _alternatives_from_node(node, binding, expression)


def _alternatives_from_node(node: Any, binding: _Binding, source_expression: str) -> list[_Alternative]:
    operator = getattr(node, 'operator', None)
    args = getattr(node, 'args', None)
    license_symbol = getattr(node, 'license_symbol', None)
    exception_symbol = getattr(node, 'exception_symbol', None)

    if license_symbol is not None and exception_symbol is not None:
        atom = _atom_from_expression(node)
        return [_Alternative((atom,), 0, atom.key, binding, (binding,))]

    if operator is not None and args is not None:
        operator_name = str(operator).strip().upper()
        child_alternatives = [
            _alternatives_from_node(child, binding, source_expression)
            for child in args
        ]
        if operator_name == 'OR':
            result: list[_Alternative] = []
            seen: set[tuple[str, ...]] = set()
            order = 0
            for child in child_alternatives:
                for alternative in child:
                    if alternative.key in seen:
                        continue
                    seen.add(alternative.key)
                    result.append(_Alternative(
                        alternative.atoms, order, alternative.expression, binding,
                        alternative.bindings,
                    ))
                    order += 1
            return result
        if operator_name == 'AND':
            result = [_Alternative((), 0, '', binding, ())]
            order = 0
            for child in child_alternatives:
                combined = []
                for prefix in result:
                    for alternative in child:
                        atoms = prefix.atoms + alternative.atoms
                        expression = ' AND '.join(
                            atom.key for atom in atoms
                        )
                        combined.append(_Alternative(
                            atoms, order, expression, binding,
                            prefix.bindings + alternative.bindings,
                        ))
                        order += 1
                result = combined
            return result

    atom = _atom_from_expression(node)
    return [_Alternative((atom,), 0, atom.key, binding, (binding,))]


def _status_for_license(license: License) -> LicenseEvidenceStatus:
    if isinstance(license, (LicenseExpression, DisjunctiveLicense)):
        acknowledgement = license.acknowledgement
        if acknowledgement is LicenseAcknowledgement.CONCLUDED:
            return LicenseEvidenceStatus.CONCLUDED
        if acknowledgement is LicenseAcknowledgement.DECLARED:
            return LicenseEvidenceStatus.DECLARED
    return LicenseEvidenceStatus.UNSPECIFIED


def _bindings_for(
    component: Component,
    policy: LicensePolicy,
) -> tuple[tuple[_Binding, ...], Optional[LicenseConflict]]:
    primary = [
        _Binding(license, _status_for_license(license), LicenseSource.COMPONENT)
        for license in component.licenses
    ]
    observed: list[_Binding] = []
    if component.evidence is not None:
        observed = [
            _Binding(license, LicenseEvidenceStatus.OBSERVED, LicenseSource.EVIDENCE)
            for license in component.evidence.licenses
        ]

    all_bindings = primary + observed
    if policy.evidence_statuses is not None:
        accepted = tuple(
            binding for binding in all_bindings
            if binding.status in policy.evidence_statuses
        )
        if not accepted:
            return (), _conflict(
                LicenseConflictReason.EVIDENCE_NOT_ACCEPTED,
                f'component {component.name!r} has no license with an accepted evidence status',
                component=component,
            )
        return accepted, None

    concluded = tuple(binding for binding in primary if binding.status is LicenseEvidenceStatus.CONCLUDED)
    if concluded:
        return concluded, None
    if primary:
        return tuple(primary), None
    if observed:
        return tuple(observed), None
    return (), _conflict(
        LicenseConflictReason.MISSING_LICENSE,
        f'component {component.name!r} has no declared, concluded, or observed license',
        component=component,
    )


def _conflict(
    reason: LicenseConflictReason,
    detail: str,
    *,
    component: Optional[Component] = None,
    license: Optional[License] = None,
    expression: Optional[str] = None,
    atom: Optional[_Atom] = None,
    evidence_status: Optional[LicenseEvidenceStatus] = None,
    source: Optional[LicenseSource] = None,
    condition: Optional[str] = None,
    related_component: Optional[Component] = None,
    related_license: Optional[str] = None,
    rule: Optional[LicenseRule] = None,
) -> LicenseConflict:
    return LicenseConflict(
        reason=reason,
        detail=detail,
        component=component,
        license=license,
        expression=expression,
        atom=atom.key if atom is not None else None,
        license_id=atom.base if atom is not None else None,
        exception=atom.exception if atom is not None else None,
        evidence_status=evidence_status,
        source=source,
        is_unknown=atom.is_unknown if atom is not None else False,
        condition=condition,
        related_component=related_component,
        related_license=related_license,
        rule=rule,
    )


def _rule_matches(
    rule: LicenseRule,
    atom: _Atom,
    effective: _EffectivePolicy,
    component: Component,
) -> bool:
    from .component import ComponentScope

    if rule.channel and _norm(rule.channel) != _norm(effective.policy.channel):
        return False
    rule_scope = rule.release_scope if rule.release_scope is not None else rule.scope
    if rule_scope is not None and ReleaseScope.coerce(rule_scope) not in {
        effective.release_scope, ReleaseScope.ALL,
    }:
        return False
    actual_scope = component.scope or ComponentScope.REQUIRED
    if rule.component_scope is not None:
        rule_component_scope = (
            rule.component_scope
            if isinstance(rule.component_scope, ComponentScope)
            else ComponentScope(str(rule.component_scope))
        )
        if rule_component_scope is not actual_scope:
            return False
    if rule.base_key != _norm_atom(atom.base):
        return False
    if rule.exception_key is not None and rule.exception_key != (
        _norm_atom(atom.exception) if atom.exception else None
    ):
        return False
    return True


def _find_rule(atom: _Atom, effective: _EffectivePolicy, component: Component) -> Optional[LicenseRule]:
    matches = [
        rule for rule in effective.policy.rules
        if _rule_matches(rule, atom, effective, component)
    ]
    if not matches:
        return None

    def specificity(rule: LicenseRule) -> tuple[int, int, int]:
        return (
            1 if rule.exception_key is not None else 0,
            1 if rule.release_scope is not None or rule.scope is not None else 0,
            1 if rule.component_scope is not None else 0,
        )

    return max(matches, key=specificity)


def _exception_known(exception: str) -> bool:
    return exception in _KNOWN_SYMBOLS or exception.lower() in _LICENSING.known_symbols_lowercase


def _evaluate_atom(
    atom: _Atom,
    effective: _EffectivePolicy,
    component: Component,
) -> _AtomVerdict:
    key = atom.normalized_key
    base_key = _norm_atom(atom.base)

    rule = _find_rule(atom, effective, component)
    if rule is not None:
        return _AtomVerdict(
            rule.allowed,
            None if rule.allowed else (
                LicenseConflictReason.LICENSE_NOT_ALLOWED
                if not atom.is_unknown
                else LicenseConflictReason.UNKNOWN_LICENSE
            ),
            rule.reason or (
                f'policy rule allows {atom.key}' if rule.allowed
                else f'policy rule denies {atom.key}'
            ),
            rule=rule,
        )

    if key in effective.denied:
        return _AtomVerdict(
            False, LicenseConflictReason.DENIED_LICENSE,
            f'{atom.key} is explicitly denied for channel {effective.policy.channel!r}',
        )
    if key in (effective.allowed or frozenset()):
        if atom.exception and _norm_atom(atom.exception) in effective.policy.denied_exceptions:
            return _AtomVerdict(
                False, LicenseConflictReason.DENIED_EXCEPTION,
                f'exception {atom.exception} is explicitly denied',
            )
        return _AtomVerdict(True)

    if atom.exception is not None:
        exception_key = _norm_atom(atom.exception)
        if exception_key in effective.policy.denied_exceptions:
            return _AtomVerdict(
                False, LicenseConflictReason.DENIED_EXCEPTION,
                f'exception {atom.exception} is explicitly denied',
            )
        if (
            effective.policy.allowed_exceptions is not None
            and exception_key not in effective.policy.allowed_exceptions
        ):
            return _AtomVerdict(
                False, LicenseConflictReason.EXCEPTION_NOT_ALLOWED,
                f'exception {atom.exception} is not in the allowed exception list',
            )

        base_verdict = _evaluate_atom(_Atom(base=atom.base, known=atom.known, custom=atom.custom), effective, component)
        exception_known = _exception_known(atom.exception)
        exception_allowed = (
            effective.policy.allowed_exceptions is not None
            and exception_key in effective.policy.allowed_exceptions
        )
        if not exception_known and not exception_allowed and not effective.policy.allow_unknown_exceptions:
            return _AtomVerdict(
                False, LicenseConflictReason.UNKNOWN_EXCEPTION,
                f'exception {atom.exception!r} is not known to SPDX or the policy',
                exception_known=False,
            )
        if base_verdict.allowed:
            return _AtomVerdict(True, exception_known=exception_known)

        grants = effective.policy.exception_grants
        if grants is True or (
            isinstance(grants, frozenset) and base_key in grants
        ):
            if exception_key not in effective.policy.denied_exceptions:
                return _AtomVerdict(True, exception_known=exception_known)
        return _AtomVerdict(
            allowed=False,
            reason=base_verdict.reason or LicenseConflictReason.LICENSE_NOT_ALLOWED,
            detail=base_verdict.detail or f'base license {atom.base} is not allowed',
            exception_known=exception_known,
        )

    # A deny-list-only policy permits everything that is not denied, except
    # unknown licenses, which are handled separately.
    if effective.allowed is not None:
        if atom.is_unknown:
            handling = effective.policy.unknown_license_policy
            if handling is LicenseUnknownPolicy.ALLOW:
                return _AtomVerdict(True)
            if handling is LicenseUnknownPolicy.REVIEW:
                return _AtomVerdict(
                    False, LicenseConflictReason.REVIEW_REQUIRED,
                    f'{atom.key} is unknown and requires compliance review',
                )
        return _AtomVerdict(
            False,
            LicenseConflictReason.UNKNOWN_LICENSE if atom.is_unknown else LicenseConflictReason.LICENSE_NOT_ALLOWED,
            (
                f'{atom.key} is unknown and not in the allow-list for channel '
                f'{effective.policy.channel!r}'
                if atom.is_unknown else
                f'{atom.key} is not in the allow-list for channel {effective.policy.channel!r}'
            ),
        )

    if atom.is_unknown:
        handling = effective.policy.unknown_license_policy
        if handling is LicenseUnknownPolicy.ALLOW:
            return _AtomVerdict(True)
        if handling is LicenseUnknownPolicy.REVIEW:
            return _AtomVerdict(
                False, LicenseConflictReason.REVIEW_REQUIRED,
                f'{atom.key} is unknown and requires compliance review',
            )
        return _AtomVerdict(
            False, LicenseConflictReason.UNKNOWN_LICENSE,
            f'{atom.key} is unknown to SPDX and the policy',
        )

    return _AtomVerdict(True)


def _details_for(license: License, atom: _Atom) -> Optional[LicenseExpressionDetails]:
    if not isinstance(license, LicenseExpression):
        return None
    candidates = {
        _norm_rule_key(atom.key),
        _norm_atom(atom.base),
    }
    for detail in license.details:
        if _norm_rule_key(detail.license_identifier) in candidates:
            return detail
    return None


def _selection_for(
    component: Component,
    binding: _Binding,
    atom: _Atom,
    effective: _EffectivePolicy,
) -> LicenseSelection:
    details = _details_for(binding.license, atom)
    license_bom_ref = None
    if details is not None and details.bom_ref.value:
        license_bom_ref = details.bom_ref.value
    elif binding.license.bom_ref.value:
        license_bom_ref = binding.license.bom_ref.value
    return LicenseSelection(
        component=component,
        license=binding.license,
        expression=(
            binding.license.value
            if isinstance(binding.license, LicenseExpression)
            else atom.key
        ),
        atom=atom.key,
        license_id=atom.base,
        exception=atom.exception,
        evidence_status=binding.status,
        acknowledgement=binding.license.acknowledgement,
        source=binding.source,
        is_unknown=atom.is_unknown,
        is_custom=atom.custom,
        expression_details=details,
        component_bom_ref=component.bom_ref.value,
        license_bom_ref=license_bom_ref,
    )


def _combine_binding_alternatives(
    bindings: tuple[_Binding, ...],
    component: Component,
    effective: _EffectivePolicy,
) -> list[_Alternative]:
    alternatives: list[_Alternative] = [
        _Alternative((), 0, '', _Binding(bindings[0].license, bindings[0].status, bindings[0].source))
    ]
    order = 0
    for binding in bindings:
        try:
            parsed = _parse_license(binding.license)
        except LicenseDecisionError:
            raise
        for alternative in parsed:
            alternative.binding = binding
            alternative.bindings = (binding,) * len(alternative.atoms)
        combined: list[_Alternative] = []
        for prefix in alternatives:
            for alternative in parsed:
                atoms = prefix.atoms + alternative.atoms
                expression = ' AND '.join(atom.key for atom in atoms)
                combined.append(_Alternative(
                    atoms, order, expression, binding,
                    prefix.bindings + alternative.bindings,
                ))
                order += 1
        alternatives = combined
    return alternatives


def _alternative_rank(
    alternative: _Alternative,
    preferred: tuple[str, ...],
) -> tuple[int, int, int, int]:
    ranks = [
        preferred.index(atom.normalized_key)
        if atom.normalized_key in preferred else len(preferred) + 1
        for atom in alternative.atoms
    ]
    return (
        max(ranks) if ranks else 0,
        sum(ranks),
        len(alternative.atoms),
        alternative.order,
    )


def _evaluate_component(
    component: Component,
    effective: _EffectivePolicy,
) -> ComponentLicenseDecision:
    bindings, missing_conflict = _bindings_for(component, effective.policy)
    if missing_conflict is not None:
        return ComponentLicenseDecision(
            component=component,
            allowed=False,
            expression=None,
            alternatives=(),
            selected=None,
            conflicts=(missing_conflict,),
            conflict_groups=(LicenseConflictGroup(
                expression='',
                conditions=(missing_conflict,),
                component=component,
                reason=missing_conflict.reason,
            ),),
            evidence_status=LicenseEvidenceStatus.UNSPECIFIED,
            reason=missing_conflict.detail,
        )

    try:
        alternatives = _combine_binding_alternatives(bindings, component, effective)
    except LicenseDecisionError as exc:
        conflicts = tuple(
            _conflict(
                LicenseConflictReason.INVALID_EXPRESSION,
                str(exc),
                component=component,
                license=binding.license,
                expression=(
                    binding.license.value
                    if isinstance(binding.license, LicenseExpression)
                    else _atom_for_disjunctive(binding.license).key
                ),
                evidence_status=binding.status,
                source=binding.source,
            )
            for binding in bindings
        )
        return ComponentLicenseDecision(
            component=component,
            allowed=False,
            expression=' AND '.join(
                binding.license.value
                for binding in bindings
                if isinstance(binding.license, LicenseExpression)
            ) or None,
            alternatives=(),
            selected=None,
            conflicts=conflicts,
            conflict_groups=(LicenseConflictGroup(
                expression='',
                conditions=conflicts,
                component=component,
                reason=LicenseConflictReason.INVALID_EXPRESSION,
            ),),
            evidence_status=bindings[0].status,
            reason=str(exc),
        )

    combinations: list[LicenseCombination] = []
    all_conflicts: list[LicenseConflict] = []
    groups: list[LicenseConflictGroup] = []
    for alternative in alternatives:
        selections: list[LicenseSelection] = []
        conflicts: list[LicenseConflict] = []
        for index, atom in enumerate(alternative.atoms):
            binding = alternative.binding_for(index)
            verdict = _evaluate_atom(atom, effective, component)
            selection = _selection_for(component, binding, atom, effective)
            if verdict.allowed:
                selections.append(selection)
            else:
                conflict = _conflict(
                    verdict.reason or LicenseConflictReason.LICENSE_NOT_ALLOWED,
                    verdict.detail or f'{atom.key} is not allowed',
                    component=component,
                    license=binding.license,
                    expression=alternative.expression,
                    atom=atom,
                    evidence_status=binding.status,
                    source=binding.source,
                    condition=f'{component.name}: {atom.key}',
                    rule=verdict.rule,
                )
                conflicts.append(conflict)
                all_conflicts.append(conflict)
        combination = LicenseCombination(
            expression=alternative.expression,
            licenses=tuple(selections),
            allowed=not conflicts,
            conflicts=tuple(conflicts),
            component=component,
            order=alternative.order,
        )
        combinations.append(combination)
        if conflicts:
            groups.append(LicenseConflictGroup(
                expression=alternative.expression,
                conditions=tuple(conflicts),
                component=component,
                reason=conflicts[0].reason,
            ))

    combinations.sort(key=lambda combo: _alternative_rank(
        next(alt for alt in alternatives if alt.order == combo.order),
        effective.preferred,
    ))
    selected = next((combo for combo in combinations if combo.allowed), None)
    allowed = selected is not None
    evidence_status = (
        selected.licenses[0].evidence_status if selected is not None and selected.licenses
        else bindings[0].status if len(bindings) == 1
        else LicenseEvidenceStatus.UNSPECIFIED
    )

    if allowed:
        reason = f'feasible license combination: {selected.expression}'
    else:
        reason = '; '.join(str(conflict) for conflict in _unique_conflicts(all_conflicts))

    return ComponentLicenseDecision(
        component=component,
        allowed=allowed,
        expression=' AND '.join(
            binding.license.value
            if isinstance(binding.license, LicenseExpression)
            else _atom_for_disjunctive(binding.license).key
            for binding in bindings
        ),
        alternatives=tuple(combinations),
        selected=selected,
        conflicts=tuple(_unique_conflicts(all_conflicts)) if not allowed else (),
        conflict_groups=tuple(groups) if not allowed else (),
        evidence_status=evidence_status,
        reason=reason,
    )


def _unique_conflicts(conflicts: Iterable[LicenseConflict]) -> list[LicenseConflict]:
    result: list[LicenseConflict] = []
    seen: set[tuple[Optional[int], Optional[str], Optional[str], str]] = set()
    for conflict in conflicts:
        key = (
            id(conflict.component) if conflict.component is not None else None,
            conflict.atom,
            conflict.evidence_status.value if conflict.evidence_status is not None else None,
            conflict.reason.value,
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(conflict)
    return result


def _component_scope_values(component: Component) -> ComponentScope:
    from .component import ComponentScope

    return component.scope or ComponentScope.REQUIRED


def _coerce_component_scopes(value: Any) -> Optional[frozenset[ComponentScope]]:
    from .component import ComponentScope

    if value is None:
        return None
    if isinstance(value, (ComponentScope, str)):
        values: Iterable[Any] = (value,)
    else:
        values = value
    result = set()
    for item in values:
        if isinstance(item, ComponentScope):
            result.add(item)
            continue
        normalized = str(item).strip().lower()
        try:
            result.add(ComponentScope(normalized))
        except ValueError as exc:
            raise LicenseDecisionError(f'unknown component scope: {item!r}') from exc
    return frozenset(result)


def _iter_components(component: Component, seen: Optional[set[int]] = None) -> Iterable[Component]:
    seen = seen if seen is not None else set()
    if id(component) in seen:
        return
    seen.add(id(component))
    yield component
    for child in component.components:
        yield from _iter_components(child, seen)


def _select_components(
    bom: Bom,
    effective: _EffectivePolicy,
    *,
    component_scope: Optional[Any],
    components: Optional[Iterable[Component]],
    include_metadata_component: bool,
) -> tuple[tuple[Component, ...], tuple[Component, ...]]:
    explicit_scopes = _coerce_component_scopes(component_scope)
    use_default_scopes = components is None
    selected: list[Component] = []
    excluded: list[Component] = []
    seen: set[int] = set()

    if components is not None:
        try:
            candidates = tuple(components)
        except TypeError:
            candidates = (components,)
    else:
        candidates = tuple(bom.components)
        if include_metadata_component and bom.metadata.component is not None:
            candidates = (bom.metadata.component,) + candidates

    for root in candidates:
        for component in _iter_components(root, seen):
            scope_value = _component_scope_values(component)
            if explicit_scopes is not None:
                include = scope_value in explicit_scopes
            elif use_default_scopes:
                include = (
                    effective.component_scopes is None
                    or scope_value in effective.component_scopes
                )
            else:
                include = True
            if include and effective.include_external is False and component.is_external is True:
                include = False
            if include and effective.policy.include_component is not None:
                include = effective.policy.include_component(component, effective.release_scope)
            if include:
                selected.append(component)
            else:
                excluded.append(component)
    return tuple(selected), tuple(excluded)


def _global_conflicts(
    chosen: Sequence[LicenseCombination],
    effective: _EffectivePolicy,
) -> list[LicenseConflict]:
    present: dict[str, tuple[Component, LicenseSelection]] = {}
    for combination in chosen:
        for selection in combination.licenses:
            atom = _Atom(
                base=selection.license_id or selection.atom,
                exception=selection.exception,
                known=not selection.is_unknown,
                custom=selection.is_custom,
            )
            for key in {atom.normalized_key, _norm_atom(atom.base)}:
                present.setdefault(key, (selection.component, selection))

    conflicts: list[LicenseConflict] = []
    for first, second in effective.policy.incompatible_licenses:
        if first not in present or second not in present:
            continue
        first_component, first_selection = present[first]
        second_component, second_selection = present[second]
        conflicts.append(LicenseConflict(
            reason=LicenseConflictReason.INCOMPATIBLE_LICENSES,
            detail=(
                f'{first_selection.atom} in component {first_component.name!r} cannot be '
                f'combined with {second_selection.atom} in component {second_component.name!r}'
            ),
            component=first_component,
            license=first_selection.license,
            expression=first_selection.expression,
            atom=first_selection.atom,
            license_id=first_selection.license_id,
            exception=first_selection.exception,
            evidence_status=first_selection.evidence_status,
            source=first_selection.source,
            condition=f'{first_component.name}: {first_selection.atom}',
            related_component=second_component,
            related_license=f'{second_component.name}: {second_selection.atom}',
        ))
    return conflicts


def _find_global_combination(
    component_decisions: Sequence[ComponentLicenseDecision],
    effective: _EffectivePolicy,
) -> tuple[tuple[LicenseCombination, ...], tuple[LicenseConflict, ...]]:
    if not effective.policy.incompatible_licenses:
        return tuple(
            decision.selected
            for decision in component_decisions
            if decision.selected is not None
        ), ()

    selected_alternatives = [
        tuple(combo for combo in decision.alternatives if combo.allowed)
        for decision in component_decisions
    ]
    conflict_evidence: list[LicenseConflict] = []

    def search(index: int, chosen: list[LicenseCombination]) -> Optional[list[LicenseCombination]]:
        if index == len(selected_alternatives):
            return list(chosen)
        for alternative in selected_alternatives[index]:
            conflicts = _global_conflicts(chosen + [alternative], effective)
            if conflicts:
                conflict_evidence.extend(conflicts)
                continue
            result = search(index + 1, chosen + [alternative])
            if result is not None:
                return result
        return None

    combination = search(0, [])
    if combination is None:
        unique: list[LicenseConflict] = []
        seen: set[tuple[str, Optional[str], Optional[str]]] = set()
        for conflict in conflict_evidence:
            key = (
                conflict.atom or '',
                conflict.related_license,
                conflict.component.name if conflict.component is not None else None,
            )
            if key in seen:
                continue
            seen.add(key)
            unique.append(conflict)
        return (), tuple(unique)
    return tuple(combination), ()


def decide_license_compliance(
    bom: Bom,
    policy: Union[LicensePolicy, Mapping[str, Any]],
    *,
    release_scope: Optional[Union[ReleaseScope, str]] = None,
    component_scope: Optional[Any] = None,
    components: Optional[Iterable[Component]] = None,
    include_metadata_component: bool = False,
    scope: Optional[Union[ReleaseScope, str]] = None,
    distribution_scope: Optional[Union[ReleaseScope, str]] = None,
) -> LicenseDecision:
    """Decide whether components in ``bom`` may use ``policy``.

    ``release_scope`` selects the source or binary component set.  By default a
    source release includes required and optional components, while a binary
    release includes required components.  ``component_scope`` can be used to
    select a CycloneDX scope explicitly.
    """
    from .bom import Bom as BomType

    if isinstance(bom, LicensePolicy) and isinstance(policy, BomType):
        bom, policy = policy, bom
    if not isinstance(bom, BomType):
        raise LicenseDecisionError('`bom` must be a cyclonedx.model.bom.Bom')
    if isinstance(policy, Mapping):
        policy = LicensePolicy(**policy)
    if not isinstance(policy, LicensePolicy):
        raise LicenseDecisionError('`policy` must be a LicensePolicy')

    if (
        release_scope is None and distribution_scope is None and scope is None
        and policy.default_release_scope is not None
    ):
        release_scope = policy.default_release_scope

    if release_scope is None and distribution_scope is not None:
        release_scope = distribution_scope

    if release_scope is None and scope is not None:
        from .component import ComponentScope

        if isinstance(scope, (list, tuple, set, frozenset)):
            component_scope = scope
        elif isinstance(scope, ComponentScope) or (
            isinstance(scope, str) and scope.strip().lower() in {
                ComponentScope.REQUIRED.value,
                ComponentScope.OPTIONAL.value,
                ComponentScope.EXCLUDED.value,
            }
        ):
            component_scope = scope
        else:
            release_scope = scope
    if release_scope is None and isinstance(component_scope, ReleaseScope):
        release_scope = component_scope
        component_scope = None
    elif release_scope is None and isinstance(component_scope, str):
        normalized = component_scope.strip().lower()
        if normalized in {
            'source', 'src', 'source-code', 'source-distribution',
            'binary', 'bin', 'binary-artifact', 'binary-distribution', 'all',
        }:
            release_scope = component_scope
            component_scope = None

    effective_scope = ReleaseScope.coerce(release_scope)
    effective = policy.for_release_scope(effective_scope)
    selected_components, excluded_components = _select_components(
        bom, effective,
        component_scope=component_scope,
        components=components,
        include_metadata_component=include_metadata_component,
    )
    component_decisions = tuple(
        _evaluate_component(component, effective)
        for component in selected_components
    )

    component_conflicts = tuple(
        conflict
        for decision in component_decisions
        for conflict in decision.conflicts
    )
    conflict_groups = tuple(
        group
        for decision in component_decisions
        for group in decision.conflict_groups
    )

    if component_conflicts:
        status = (
            LicenseDecisionStatus.REVIEW
            if all(c.reason is LicenseConflictReason.REVIEW_REQUIRED for c in component_conflicts)
            else LicenseDecisionStatus.DENIED
        )
        combination: tuple[LicenseCombination, ...] = ()
        conflicts = component_conflicts
        reason = '; '.join(str(conflict) for conflict in component_conflicts)
    else:
        combination, global_conflicts = _find_global_combination(component_decisions, effective)
        if global_conflicts:
            status = LicenseDecisionStatus.DENIED
            combination = ()
            conflicts = global_conflicts
            reason = '; '.join(str(conflict) for conflict in global_conflicts)
            conflict_groups = conflict_groups + (LicenseConflictGroup(
                expression=' AND '.join(
                    decision.selected_expression or ''
                    for decision in component_decisions
                    if decision.selected is not None
                ),
                conditions=global_conflicts,
                reason=LicenseConflictReason.INCOMPATIBLE_LICENSES,
            ),)
        else:
            status = LicenseDecisionStatus.ALLOWED
            conflicts = ()
            chosen_by_component = {
                id(combo.component): combo
                for combo in combination
                if combo.component is not None
            }
            if chosen_by_component:
                component_decisions = tuple(
                    replace(decision, selected=chosen_by_component[id(decision.component)])
                    if id(decision.component) in chosen_by_component
                    else decision
                    for decision in component_decisions
                )
            reason = 'feasible license combination: ' + (
                ' AND '.join(combo.expression for combo in combination)
                if combination else 'no licensed components in scope'
            )

    return LicenseDecision(
        bom=bom,
        policy=policy,
        channel=policy.channel,
        release_scope=effective_scope,
        status=status,
        components=component_decisions,
        combination=combination,
        conflicts=conflicts,
        conflict_groups=conflict_groups,
        excluded_components=excluded_components,
        reason=reason,
    )


def evaluate_license_policy(
    bom: Bom,
    policy: Union[LicensePolicy, Mapping[str, Any]],
    **kwargs: Any,
) -> LicenseDecision:
    """Alias for :func:`decide_license_compliance`."""
    if isinstance(bom, LicensePolicy) and isinstance(policy, Bom):
        bom, policy = policy, bom
    return decide_license_compliance(bom, policy, **kwargs)


def evaluate_licenses(*args: Any, **kwargs: Any) -> LicenseDecision:
    """Alias for :func:`evaluate_license_policy`."""
    return evaluate_license_policy(*args, **kwargs)


def decide_licenses(*args: Any, **kwargs: Any) -> LicenseDecision:
    """Alias for :func:`evaluate_license_policy`."""
    return evaluate_license_policy(*args, **kwargs)


def check_license_policy(*args: Any, **kwargs: Any) -> LicenseDecision:
    """Alias for :func:`evaluate_license_policy`."""
    return evaluate_license_policy(*args, **kwargs)


def evaluate_license_compliance(*args: Any, **kwargs: Any) -> LicenseDecision:
    """Alias for :func:`evaluate_license_policy`."""
    return evaluate_license_policy(*args, **kwargs)


def check_distribution_compliance(*args: Any, **kwargs: Any) -> LicenseDecision:
    """Alias for :func:`evaluate_license_policy`."""
    return evaluate_license_policy(*args, **kwargs)


def decide_distribution(*args: Any, **kwargs: Any) -> LicenseDecision:
    """Alias for :func:`evaluate_license_policy`."""
    return evaluate_license_policy(*args, **kwargs)


def can_distribute(*args: Any, **kwargs: Any) -> bool:
    """Return whether the requested distribution is allowed."""
    return evaluate_license_policy(*args, **kwargs).allowed


is_distributable = can_distribute


class LicenseDecisionEngine:
    """Convenience wrapper binding a policy to an evaluation API."""

    def __init__(
        self,
        policy: Optional[Union[LicensePolicy, Mapping[str, Any]]] = None,
        **policy_kwargs: Any,
    ) -> None:
        if policy is None:
            policy = LicensePolicy(**policy_kwargs)
        elif isinstance(policy, Mapping):
            policy = LicensePolicy(**policy)
        elif policy_kwargs:
            raise LicenseDecisionError('policy arguments cannot accompany a LicensePolicy object')
        if not isinstance(policy, LicensePolicy):
            raise LicenseDecisionError('`policy` must be a LicensePolicy or mapping')
        self.policy = policy

    def evaluate(self, bom: Bom, **kwargs: Any) -> LicenseDecision:
        return self.policy.evaluate(bom, **kwargs)

    decide = evaluate
    check = evaluate

    def can_distribute(self, bom: Bom, **kwargs: Any) -> bool:
        return self.evaluate(bom, **kwargs).allowed


LicensePolicyEngine = LicenseDecisionEngine
LicenseComplianceEngine = LicenseDecisionEngine
LicenseDecisionAPI = LicenseDecisionEngine
LicenseDecisionOutcome = LicenseDecision
LicenseAssessment = LicenseDecision
DistributionDecision = LicenseDecision
ComponentDecision = ComponentLicenseDecision
