"""Publish precheck for multi-agency testimony custody directives.

Two agencies may investigate the same STIX object, but only one agency
may hold the original of a given testimony class at a time.  This module
evaluates investigation/custody directives against a *fictional* STIX
bundle, using statement markings (testimony class), object versions, and
a handover registry.  It separates directives that can hold together
from mutually exclusive requirements, and when a late retention slip
makes two directives conflict it reports the concrete testimony object
and the minimal conflicting permission set.
"""

import itertools
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .markings import is_marked
from .parsing import parse
from .utils import parse_into_datetime

FICTIONAL_STATEMENT = "FICTIONAL-SYNTHETIC"
TESTIMONY_ORIGINAL_STATEMENT = "TESTIMONY-ORIGINAL"

ACTION_INVESTIGATE = "investigate"
ACTION_HOLD_ORIGINAL = "hold-original"

REASON_LATE_RETENTION_SLIP = "late-retention-slip"
REASON_MISSING_HANDOVER = "missing-handover"
REASON_INCOMPLETE_HANDOVER = "incomplete-handover"

INVALID_UNKNOWN_OBJECT = "unknown-object"
INVALID_UNKNOWN_VERSION = "unknown-version"
INVALID_NOT_TESTIMONY = "not-testimony-in-version"


class PrecheckError(Exception):
    """Base error for publish precheck failures."""


class NonFictionalBundleError(PrecheckError):
    """Raised when a bundle is not marked as fictional/synthetic data."""


def _as_utc(value):
    if isinstance(value, str):
        value = parse_into_datetime(value)
    if isinstance(value, datetime) and value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value


@dataclass(frozen=True)
class Directive:
    """A single agency instruction evaluated by the precheck.

    ``action`` is either ``ACTION_INVESTIGATE`` (always compatible with
    other directives on the same object) or ``ACTION_HOLD_ORIGINAL``
    (exclusive per testimony class).  ``object_version`` optionally pins
    the directive to one version of the target object; when omitted the
    latest version present in the bundle is used.
    """

    directive_id: str
    agency: str
    action: str
    object_id: str
    effective_at: datetime
    object_version: datetime | None = None


@dataclass(frozen=True)
class HandoverEntry:
    """One handover-registry record for a custody role switch.

    ``releases_retention`` must be True: a role handover has to state
    explicitly that the previous holder's retention obligation ends.
    ``recorded_at`` is when the slip entered the registry; a slip
    recorded only after the follow-up directive's effective time is a
    late retention slip and cannot resolve the conflict.
    """

    entry_id: str
    object_id: str
    from_agency: str
    to_agency: str
    effective_at: datetime
    recorded_at: datetime
    releases_retention: bool


@dataclass(frozen=True)
class Conflict:
    """A mutually exclusive pair of custody directives.

    ``directive_ids`` is the minimal conflicting permission set: each
    directive is satisfiable on its own, together they are not.
    """

    object_id: str
    testimony_class: str
    directive_ids: tuple
    object_versions: tuple
    reason: str
    handover_entry_id: str | None = None


@dataclass
class PrecheckReport:
    """Outcome of a publish precheck run."""

    fictional_marking_refs: tuple = ()
    resolved_directives: dict = field(default_factory=dict)
    invalid_directives: dict = field(default_factory=dict)
    compatible_pairs: list = field(default_factory=list)
    mutually_exclusive_pairs: list = field(default_factory=list)
    conflicts: list = field(default_factory=list)
    incomplete_handovers: list = field(default_factory=list)

    @property
    def ok(self):
        return not (
            self.conflicts
            or self.invalid_directives
            or self.incomplete_handovers
        )


def _as_directive(value):
    if isinstance(value, Directive):
        directive = value
    else:
        directive = Directive(**value)
    return Directive(
        directive_id=directive.directive_id,
        agency=directive.agency,
        action=directive.action,
        object_id=directive.object_id,
        effective_at=_as_utc(directive.effective_at),
        object_version=(
            _as_utc(directive.object_version)
            if directive.object_version is not None
            else None
        ),
    )


def _as_handover(value):
    if isinstance(value, HandoverEntry):
        entry = value
    else:
        entry = HandoverEntry(**value)
    return HandoverEntry(
        entry_id=entry.entry_id,
        object_id=entry.object_id,
        from_agency=entry.from_agency,
        to_agency=entry.to_agency,
        effective_at=_as_utc(entry.effective_at),
        recorded_at=_as_utc(entry.recorded_at),
        releases_retention=bool(entry.releases_retention),
    )


def _as_bundle(bundle):
    if hasattr(bundle, "objects"):
        return bundle
    return parse(bundle, allow_custom=True)


def _statement_markings(bundle):
    markings = {}
    for obj in bundle.objects:
        if obj.get("type") == "marking-definition":
            markings[obj["id"]] = obj.get("definition", {}).get("statement", "")
    return markings


def _fictional_marking_refs(bundle):
    return tuple(
        marking_id
        for marking_id, statement in _statement_markings(bundle).items()
        if FICTIONAL_STATEMENT in statement
    )


def _testimony_classes(obj, statement_markings):
    classes = set()
    for marking_ref in obj.get("object_marking_refs", []):
        statement = statement_markings.get(marking_ref, "")
        if statement.startswith(TESTIMONY_ORIGINAL_STATEMENT):
            _, _, suffix = statement.partition(":")
            classes.add(suffix or "default")
    return classes


def _index_versions(bundle):
    versions = {}
    for obj in bundle.objects:
        if obj.get("type") == "marking-definition":
            continue
        timestamp = obj.get("modified") or obj.get("created")
        versions.setdefault(obj["id"], []).append((timestamp, obj))
    for history in versions.values():
        history.sort(key=lambda item: item[0])
    return versions


def _resolve_version(versions, directive):
    history = versions.get(directive.object_id)
    if not history:
        return None, INVALID_UNKNOWN_OBJECT
    if directive.object_version is None:
        return history[-1][1], None
    for timestamp, obj in history:
        if timestamp == directive.object_version:
            return obj, None
    return None, INVALID_UNKNOWN_VERSION


def _find_handover(registry, object_id, from_agency, to_agency, deadline):
    candidates = [
        entry
        for entry in registry
        if entry.object_id == object_id
        and entry.from_agency == from_agency
        and entry.to_agency == to_agency
        and entry.effective_at <= deadline
    ]
    complete = [entry for entry in candidates if entry.releases_retention]
    timely = [entry for entry in complete if entry.recorded_at <= deadline]
    if timely:
        return timely[0], None
    if complete:
        return complete[0], REASON_LATE_RETENTION_SLIP
    if candidates:
        return candidates[0], REASON_INCOMPLETE_HANDOVER
    return None, REASON_MISSING_HANDOVER


def run_precheck(bundle, directives, handover_registry=()):
    """Run the publish precheck over a fictional STIX bundle.

    Args:
        bundle: A STIX bundle (object, dict, or JSON string) that must
            carry a fictional/synthetic statement marking.
        directives: Iterable of Directive instances (or equivalent
            mappings) to evaluate.
        handover_registry: Iterable of HandoverEntry instances (or
            equivalent mappings) recording custody role switches.

    Returns:
        A PrecheckReport separating directives that can hold together
        from mutually exclusive requirements.  Each conflict names the
        concrete testimony object and the minimal conflicting permission
        set.

    Raises:
        NonFictionalBundleError: If the bundle, or any object referenced
            by a directive, is not marked as fictional/synthetic.
    """
    bundle = _as_bundle(bundle)
    fictional_refs = _fictional_marking_refs(bundle)
    if not fictional_refs:
        raise NonFictionalBundleError(
            "bundle carries no %r statement marking; "
            "only fictional bundles are processed" % FICTIONAL_STATEMENT,
        )

    statement_markings = _statement_markings(bundle)
    versions = _index_versions(bundle)
    registry = [_as_handover(entry) for entry in handover_registry]
    report = PrecheckReport(fictional_marking_refs=fictional_refs)

    for entry in registry:
        if not entry.releases_retention:
            report.incomplete_handovers.append(entry.entry_id)

    resolved = {}
    for raw in directives:
        directive = _as_directive(raw)
        obj, error = _resolve_version(versions, directive)
        if error:
            report.invalid_directives[directive.directive_id] = error
            continue
        if not is_marked(obj, list(fictional_refs)):
            raise NonFictionalBundleError(
                "object %r is not marked %r; only fictional bundles are "
                "processed" % (directive.object_id, FICTIONAL_STATEMENT),
            )
        classes = _testimony_classes(obj, statement_markings)
        if directive.action == ACTION_HOLD_ORIGINAL and not classes:
            report.invalid_directives[directive.directive_id] = (
                INVALID_NOT_TESTIMONY
            )
            continue
        version = obj.get("modified") or obj.get("created")
        report.resolved_directives[directive.directive_id] = version
        resolved[directive.directive_id] = (directive, obj, version, classes)

    by_object = {}
    for directive, obj, version, classes in resolved.values():
        by_object.setdefault(directive.object_id, []).append(
            (directive, version, classes),
        )

    for object_id, group in sorted(by_object.items()):
        for left, right in itertools.combinations(group, 2):
            left_directive, left_version, left_classes = left
            right_directive, right_version, right_classes = right
            pair = tuple(sorted(
                (left_directive.directive_id, right_directive.directive_id),
            ))
            shared_classes = sorted(left_classes & right_classes)
            holds = (
                left_directive.action == ACTION_HOLD_ORIGINAL
                and right_directive.action == ACTION_HOLD_ORIGINAL
            )
            if (
                not holds
                or not shared_classes
                or left_directive.agency == right_directive.agency
            ):
                report.compatible_pairs.append(pair)
                continue
            earlier, later = sorted(
                (left, right),
                key=lambda item: (
                    item[0].effective_at, item[0].directive_id,
                ),
            )
            for testimony_class in shared_classes:
                entry, reason = _find_handover(
                    registry,
                    object_id,
                    earlier[0].agency,
                    later[0].agency,
                    later[0].effective_at,
                )
                if reason is None:
                    report.compatible_pairs.append(pair)
                    continue
                report.mutually_exclusive_pairs.append(pair)
                report.conflicts.append(Conflict(
                    object_id=object_id,
                    testimony_class=testimony_class,
                    directive_ids=pair,
                    object_versions=(earlier[1], later[1]),
                    reason=reason,
                    handover_entry_id=(
                        entry.entry_id if entry is not None else None
                    ),
                ))

    return report
