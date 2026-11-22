"""Embargo-aware STIX delivery previews.

This module implements a small policy layer on top of the STIX object model.
It is intended to be called by a publishing backend before a bundle is sent to
a receiving community.

The preview answers one question: *at a given time and for a given set of
receiving categories, which objects and relationships may be published
together?*  Objects and relationships may carry embargo/declassification
metadata (custom STIX properties such as ``x_embargo_until``), and
relationships to restricted cases may have their own embargo period.

The implementation deliberately keeps the release decision and the STIX
payload separate.  A ``DeliveryPreview`` contains:

* one ``DeliveryItem`` per selected object/relationship;
* one ``ReleasePermit`` per item (granted or denied);
* the version of each referenced object which was used;
* deterministic cycle information for relationship graphs;
* a revision log used by :meth:`DeliveryPreview.extend_embargo`.

Embargo metadata
----------------

The following custom properties are understood (the first name in each group
is the canonical form):

* release time: ``x_embargo_until``, ``x_declassify_at``,
  ``x_declassified_at``, ``x_release_at``, ``x_public_at``,
  ``x_publication_date`` (and a few common aliases);
* receiving categories: ``x_release_categories``,
  ``x_receiving_categories``, ``x_allowed_categories``, ``x_audience``,
  ``x_audiences``, ``x_release_to``;
* restricted cases: ``x_restricted_cases``,
  ``x_restricted_case_refs``, ``x_case_refs``;
* explicit source/target version pins on relationships:
  ``x_source_version`` and ``x_target_version``.

All timestamps are evaluated as UTC.  A release time is inclusive: an item is
released when ``delivery_at >= release_at``.

Example
-------

.. code-block:: python

    from stix2.delivery import preview_delivery

    preview = preview_delivery(
        objects=[identity, indicator, relationship],
        receiving_categories=["partner"],
        at="2026-12-01T00:00:00Z",
    )

    print(preview.released_ids)
    print(preview.to_bundle().serialize(pretty=True))

Use :func:`preview_transition` to keep a before/after pair around an embargo
lifting event.
"""

from __future__ import annotations

import argparse
from collections import defaultdict
from collections.abc import Iterable, Mapping
import copy
from dataclasses import dataclass, field
import datetime as dt
import json
import os
from pathlib import Path
import sys
from typing import Any, Optional

from .utils import format_datetime, get_timestamp
from .v21.bundle import Bundle

__all__ = [
    "CASE_PROPERTIES",
    "CATEGORY_PROPERTIES",
    "EMBARGO_PROPERTIES",
    "SOURCE_VERSION_PROPERTIES",
    "TARGET_VERSION_PROPERTIES",
    "DeliveryItem",
    "DeliveryPolicy",
    "DeliveryPreview",
    "DeliveryPreviewError",
    "EmbargoTransition",
    "PublicationPermit",
    "ReleasePermit",
    "DeclassificationPolicy",
    "DeliveryPermit",
    "DeliveryPlanner",
    "DeliveryPreviewBuilder",
    "EmbargoPermit",
    "EmbargoPolicy",
    "EmbargoPreview",
    "Permission",
    "PublicationPreview",
    "ReleaseDecision",
    "ReleasePreview",
    "build_delivery_preview",
    "build_release_preview",
    "compute_delivery_preview",
    "compute_delivery_set",
    "compute_release_set",
    "delivery_preview",
    "delivery_transition",
    "embargo_transition",
    "preview_around_embargo",
    "preview_delivery",
    "preview_release",
    "preview_release_set",
    "preview_transition",
    "release_preview",
    "main",
]


class DeliveryPreviewError(ValueError):
    """Raised for an invalid delivery-preview request."""


#: Custom properties which may carry a release/declassification timestamp.
EMBARGO_PROPERTIES = (
    "x_embargo_until",
    "x_embargo_end",
    "x_embargo_expires",
    "x_embargo",
    "x_release_policy",
    "x_declassify_at",
    "x_declassification_at",
    "x_declassified_at",
    "x_declassification_date",
    "x_release_at",
    "x_release_after",
    "x_public_at",
    "x_publication_date",
    "x_public_release_at",
    "x_release_date",
    "x_release_time",
    "x_releasable_at",
    "x_available_at",
    "x_embargo_lifted_at",
    "x_declassification_time",
    "x_unclassify_at",
    "x_case_embargo_until",
    "x_case_release_at",
    "x_case_public_at",
    "embargo_until",
    "declassify_at",
    "declassified_at",
    "declassification_date",
    "public_at",
    "release_at",
)

#: Custom properties which may carry receiving-category names.
CATEGORY_PROPERTIES = (
    "x_release_categories",
    "x_receiving_categories",
    "x_receiving_category",
    "x_allowed_categories",
    "x_release_to",
    "x_release_scope",
    "x_audience",
    "x_audiences",
    "x_categories",
    "x_authorized_categories",
    "x_authorised_categories",
    "x_sharing_categories",
    "x_receiver_categories",
    "x_release_groups",
    "x_distribution",
    "x_need_to_know",
    "x_recipients",
    "release_categories",
    "receiving_categories",
    "allowed_categories",
    "release_to",
    "audience",
    "audiences",
    "categories",
)

#: Custom properties which may reference a restricted case.
CASE_PROPERTIES = (
    "x_restricted_cases",
    "x_restricted_case_refs",
    "x_restricted_case",
    "x_case_refs",
    "x_case_ref",
    "x_cases",
    "x_case_ids",
    "x_restricted_case_ids",
    "x_related_cases",
    "restricted_cases",
    "restricted_case_refs",
    "case_refs",
    "case_ids",
)

#: Relationship properties which may pin the endpoint version used.
SOURCE_VERSION_PROPERTIES = (
    "x_source_version",
    "x_source_ref_version",
    "x_source_object_version",
    "x_source_version_used",
    "source_version",
    "source_ref_version",
)
TARGET_VERSION_PROPERTIES = (
    "x_target_version",
    "x_target_ref_version",
    "x_target_object_version",
    "x_target_version_used",
    "target_version",
    "target_ref_version",
)

_BLOCKED_RELEASE_STATUSES = {
    "blocked",
    "classified",
    "embargoed",
    "restricted",
    "withheld",
}
_RELEASED_RELEASE_STATUSES = {
    "declassified",
    "public",
    "released",
    "shareable",
}
_TRUE_VALUES = {True, 1, "1", "true", "yes", "y", "on"}
_FALSE_VALUES = {False, 0, "0", "false", "no", "n", "off"}

_MIN_TIME = dt.datetime.min.replace(tzinfo=dt.timezone.utc)


@dataclass(frozen=True)
class DeliveryPolicy:
    """Tunable rules used while building a delivery preview.

    The defaults implement the association's normal behaviour.  The policy is
    intentionally data-only so it can be loaded from a publishing backend's
    configuration.
    """

    embargo_properties: tuple[str, ...] = EMBARGO_PROPERTIES
    category_properties: tuple[str, ...] = CATEGORY_PROPERTIES
    case_properties: tuple[str, ...] = CASE_PROPERTIES
    require_endpoints: bool = True
    require_case_clearance: bool = True
    include_blocked_items: bool = True
    release_time_inclusive: bool = True


@dataclass(frozen=True)
class ReleasePermit:
    """The release decision for one delivery item.

    ``status`` is ``"granted"`` when the item may be published and
    ``"denied"`` otherwise.  A denied permit for a relationship which becomes
    public after both of its endpoints has
    ``still_blocks_publication=True``; this is the explicit record needed when
    the endpoints are public but the relationship must remain withheld.
    """

    item_id: str
    kind: str
    item_type: str
    status: str
    allowed: bool
    blocked: bool
    reason: str
    blocking_reasons: tuple[str, ...]
    evaluated_at: str
    release_at: Optional[str] = None
    embargo_until: Optional[str] = None
    source_ref: Optional[str] = None
    target_ref: Optional[str] = None
    direction: Optional[str] = None
    source_version: Optional[str] = None
    target_version: Optional[str] = None
    source_version_declared: Optional[str] = None
    target_version_declared: Optional[str] = None
    source_spec_version: Optional[str] = None
    target_spec_version: Optional[str] = None
    version_refs: dict[str, Any] = field(
        default_factory=dict, compare=False, hash=False
    )
    category_sets: dict[str, list[str]] = field(
        default_factory=dict, compare=False, hash=False
    )
    allowed_categories: list[str] = field(
        default_factory=list, compare=False, hash=False
    )
    case_refs: tuple[str, ...] = ()
    outlasts_endpoints: bool = False
    endpoint_release_at: Optional[str] = None
    still_blocks_publication: bool = False

    @property
    def granted(self) -> bool:
        """Whether the permit allows publication."""

        return self.allowed

    @property
    def denied(self) -> bool:
        """Whether the permit denies publication."""

        return not self.allowed

    @property
    def effect(self) -> str:
        """``"allow"`` or ``"deny"``."""

        return "allow" if self.allowed else "deny"

    @property
    def decision(self) -> str:
        return "released" if self.allowed else "blocked"

    @property
    def publication_status(self) -> str:
        return self.decision

    @property
    def release_status(self) -> str:
        return self.decision

    @property
    def still_blocked(self) -> bool:
        return self.still_blocks_publication

    @property
    def blocks_publication(self) -> bool:
        return self.still_blocks_publication

    @property
    def permit(self) -> "ReleasePermit":
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "item_id": self.item_id,
            "kind": self.kind,
            "item_type": self.item_type,
            "status": self.status,
            "decision": self.decision,
            "publication_status": self.publication_status,
            "effect": self.effect,
            "granted": self.granted,
            "allowed": self.allowed,
            "blocked": self.blocked,
            "reason": self.reason,
            "blocking_reasons": list(self.blocking_reasons),
            "evaluated_at": self.evaluated_at,
            "release_at": self.release_at,
            "embargo_until": self.embargo_until,
            "source_ref": self.source_ref,
            "target_ref": self.target_ref,
            "direction": self.direction,
            "source_version": self.source_version,
            "target_version": self.target_version,
            "source_version_declared": self.source_version_declared,
            "target_version_declared": self.target_version_declared,
            "source_spec_version": self.source_spec_version,
            "target_spec_version": self.target_spec_version,
            "version_refs": copy.deepcopy(self.version_refs),
            "category_sets": copy.deepcopy(self.category_sets),
            "allowed_categories": list(self.allowed_categories),
            "case_refs": list(self.case_refs),
            "outlasts_endpoints": self.outlasts_endpoints,
            "endpoint_release_at": self.endpoint_release_at,
            "still_blocks_publication": self.still_blocks_publication,
            "still_blocked": self.still_blocked,
        }

    def serialize(self, pretty: bool = False) -> str:
        return json.dumps(
            self.to_dict(),
            indent=2 if pretty else None,
            sort_keys=pretty,
            ensure_ascii=False,
        )

    to_json = serialize


# A descriptive alias used by some backends.
PublicationPermit = ReleasePermit


@dataclass
class DeliveryItem:
    """One selected STIX object or relationship and its release decision."""

    id: str
    kind: str
    type: str
    spec_version: str
    status: str
    allowed: bool
    revision: int
    updated_at: str
    release_at: Optional[str] = None
    embargo_until: Optional[str] = None
    release_at_property: Optional[str] = None
    version: Optional[str] = None
    version_property: Optional[str] = None
    version_rule: Optional[str] = None
    source_ref: Optional[str] = None
    target_ref: Optional[str] = None
    origin_ref: Optional[str] = None
    destination_ref: Optional[str] = None
    direction: Optional[str] = None
    source_version: Optional[str] = None
    target_version: Optional[str] = None
    source_version_used: Optional[str] = None
    target_version_used: Optional[str] = None
    source_version_declared: Optional[str] = None
    target_version_declared: Optional[str] = None
    source_spec_version: Optional[str] = None
    target_spec_version: Optional[str] = None
    version_refs: dict[str, Any] = field(default_factory=dict)
    category_sets: dict[str, list[str]] = field(default_factory=dict)
    allowed_categories: list[str] = field(default_factory=list)
    case_refs: list[str] = field(default_factory=list)
    cross_version_reference: bool = False
    cycle_id: Optional[int] = None
    cycle_path: Optional[list[str]] = None
    cycle_members: Optional[list[str]] = None
    cycle_direction: Optional[str] = None
    cycle_next_ref: Optional[str] = None
    outlasts_endpoints: bool = False
    endpoint_release_at: Optional[str] = None
    still_blocks_publication: bool = False
    reasons: list[str] = field(default_factory=list)
    blocked_by: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    extension_notes: list[str] = field(default_factory=list)
    version_note: Optional[str] = None
    permit: Optional[ReleasePermit] = None
    obj: Any = field(default=None, repr=False, compare=False)

    @property
    def object(self) -> Any:
        """The selected STIX object (or ``None`` when no version was usable)."""

        return self.obj

    @property
    def stix(self) -> Any:
        return self.obj

    @property
    def decision(self) -> str:
        return self.status

    @property
    def released(self) -> bool:
        return self.allowed

    @property
    def is_released(self) -> bool:
        return self.allowed

    @property
    def blocked(self) -> bool:
        return not self.allowed

    @property
    def stix_id(self) -> str:
        return self.id

    @property
    def available_at(self) -> Optional[str]:
        return self.release_at

    @property
    def declassify_at(self) -> Optional[str]:
        return self.release_at

    @property
    def public_at(self) -> Optional[str]:
        return self.release_at

    @property
    def category_sources(self) -> list[str]:
        return sorted(self.category_sets)

    @property
    def categories(self) -> list[str]:
        return list(self.allowed_categories)

    @property
    def receiving_categories(self) -> tuple[str, ...]:
        return tuple(self.allowed_categories)

    @property
    def cycle_next(self) -> Optional[str]:
        return self.cycle_next_ref

    @property
    def next_ref(self) -> Optional[str]:
        return self.destination_ref

    @property
    def destination(self) -> Optional[str]:
        return self.destination_ref

    @property
    def relationship(self) -> Any:
        return self.obj if self.kind == "relationship" else None

    def to_dict(self, include_object: bool = True) -> dict[str, Any]:
        data = {
            "id": self.id,
            "kind": self.kind,
            "type": self.type,
            "spec_version": self.spec_version,
            "status": self.status,
            "decision": self.decision,
            "allowed": self.allowed,
            "released": self.released,
            "blocked": self.blocked,
            "revision": self.revision,
            "updated_at": self.updated_at,
            "release_at": self.release_at,
            "embargo_until": self.embargo_until,
            "available_at": self.release_at,
            "declassify_at": self.release_at,
            "public_at": self.release_at,
            "release_at_property": self.release_at_property,
            "version": self.version,
            "version_property": self.version_property,
            "version_rule": self.version_rule,
            "source_ref": self.source_ref,
            "target_ref": self.target_ref,
            "origin_ref": self.origin_ref,
            "destination_ref": self.destination_ref,
            "direction": self.direction,
            "source_version": self.source_version,
            "target_version": self.target_version,
            "source_version_used": self.source_version_used,
            "target_version_used": self.target_version_used,
            "source_version_declared": self.source_version_declared,
            "target_version_declared": self.target_version_declared,
            "source_spec_version": self.source_spec_version,
            "target_spec_version": self.target_spec_version,
            "version_refs": copy.deepcopy(self.version_refs),
            "category_sets": copy.deepcopy(self.category_sets),
            "allowed_categories": list(self.allowed_categories),
            "case_refs": list(self.case_refs),
            "cross_version_reference": self.cross_version_reference,
            "cycle_id": self.cycle_id,
            "cycle_path": list(self.cycle_path) if self.cycle_path else None,
            "cycle_members": (
                list(self.cycle_members) if self.cycle_members else None
            ),
            "cycle_direction": self.cycle_direction,
            "cycle_next_ref": self.cycle_next_ref,
            "cycle_next": self.cycle_next_ref,
            "destination": self.destination_ref,
            "outlasts_endpoints": self.outlasts_endpoints,
            "endpoint_release_at": self.endpoint_release_at,
            "still_blocks_publication": self.still_blocks_publication,
            "reasons": list(self.reasons),
            "blocked_by": list(self.blocked_by),
            "warnings": list(self.warnings),
            "extension_notes": list(self.extension_notes),
            "version_note": self.version_note,
            "permit": self.permit.to_dict() if self.permit else None,
        }
        if include_object:
            data["object"] = _object_payload(self.obj) if self.obj is not None else None
        return data

    def serialize(self, pretty: bool = False) -> str:
        return json.dumps(
            self.to_dict(),
            indent=2 if pretty else None,
            sort_keys=pretty,
            ensure_ascii=False,
        )

    to_json = serialize

    def __getitem__(self, key: str) -> Any:
        if key == "object" and self.obj is not None:
            return _object_payload(self.obj)
        data = self.to_dict()
        try:
            return data[key]
        except KeyError:
            raise KeyError(key) from None

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key: str) -> bool:
        return key in self.to_dict()


@dataclass
class EmbargoTransition:
    """A before/after pair of previews around an embargo lifting time."""

    before: DeliveryPreview
    after: DeliveryPreview
    embargo_until: str
    before_path: Optional[str] = None
    after_path: Optional[str] = None

    @property
    def receiving_categories(self) -> tuple[str, ...]:
        return self.after.receiving_categories

    @property
    def delivery_at(self) -> str:
        return self.after.delivery_at

    @property
    def before_preview(self) -> DeliveryPreview:
        return self.before

    @property
    def after_preview(self) -> DeliveryPreview:
        return self.after

    @property
    def snapshots(self) -> dict[str, DeliveryPreview]:
        return {"before": self.before, "after": self.after}

    @property
    def before_snapshot(self) -> DeliveryPreview:
        return self.before

    @property
    def after_snapshot(self) -> DeliveryPreview:
        return self.after

    @property
    def files(self) -> tuple[Optional[str], Optional[str]]:
        return self.before_path, self.after_path

    @property
    def paths(self) -> tuple[Optional[str], Optional[str]]:
        return self.files

    @property
    def before_file(self) -> Optional[str]:
        return self.before_path

    @property
    def after_file(self) -> Optional[str]:
        return self.after_path

    def __getitem__(self, key: str) -> Any:
        if key in {"before", "after"}:
            return getattr(self, key)
        if key == "embargo_until":
            return self.embargo_until
        if key == "changed_ids":
            return self.changed_ids
        if key == "newly_released_ids":
            return self.newly_released_ids
        if key == "still_blocked_ids":
            return self.still_blocked_ids
        raise KeyError(key)

    @property
    def changed_ids(self) -> list[str]:
        return sorted(
            item_id
            for item_id in set(self.before.by_id) | set(self.after.by_id)
            if self._status(self.before, item_id)
            != self._status(self.after, item_id)
        )

    @property
    def newly_released_ids(self) -> list[str]:
        return [
            item_id
            for item_id in self.after.released_ids
            if self._status(self.before, item_id) != "released"
        ]

    @property
    def still_blocked_ids(self) -> list[str]:
        return list(self.after.blocked_ids)

    @staticmethod
    def _status(preview: DeliveryPreview, item_id: str) -> Optional[str]:
        item = preview.by_id.get(item_id)
        return item.status if item else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": "delivery-preview-transition",
            "embargo_until": self.embargo_until,
            "before": self.before.to_dict(),
            "after": self.after.to_dict(),
            "before_path": self.before_path,
            "after_path": self.after_path,
            "changed_ids": self.changed_ids,
            "newly_released_ids": self.newly_released_ids,
            "still_blocked_ids": self.still_blocked_ids,
        }

    def serialize(self, pretty: bool = False) -> str:
        return json.dumps(
            self.to_dict(),
            indent=2 if pretty else None,
            sort_keys=pretty,
            ensure_ascii=False,
        )

    to_json = serialize

    def save(
        self,
        directory: str | os.PathLike[str] = ".",
        stem: str = "delivery-preview",
        *,
        pretty: bool = True,
    ) -> tuple[str, str]:
        """Write the before and after previews as two JSON files.

        Returns the two paths, ``(<stem>-before.json, <stem>-after.json)``.
        """

        out_dir = Path(directory)
        out_dir.mkdir(parents=True, exist_ok=True)
        before_path = out_dir / f"{stem}-before.json"
        after_path = out_dir / f"{stem}-after.json"
        self.before_path = self.before.save(before_path, pretty=pretty)
        self.after_path = self.after.save(after_path, pretty=pretty)
        return self.before_path, self.after_path

    write = save
    dump = save


class DeliveryPreview:
    """A point-in-time preview of what a publisher may release.

    Parameters mirror :func:`preview_delivery`.  The constructor performs the
    evaluation immediately; no state is mutated afterwards except by
    :meth:`extend_embargo` (or its aliases).
    """

    def __init__(
        self,
        objects: Any = None,
        relationships: Any = None,
        receiving_categories: Any = None,
        at: Any = None,
        *,
        bundle: Any = None,
        object_list: Any = None,
        stix_objects: Any = None,
        rels: Any = None,
        relations: Any = None,
        sros: Any = None,
        receiving_category: Any = None,
        category: Any = None,
        categories: Any = None,
        receiver_categories: Any = None,
        audience: Any = None,
        audiences: Any = None,
        recipient: Any = None,
        recipients: Any = None,
        release_to: Any = None,
        release_scope: Any = None,
        groups: Any = None,
        delivery_at: Any = None,
        delivery_time: Any = None,
        when: Any = None,
        now: Any = None,
        as_of: Any = None,
        at_time: Any = None,
        timestamp: Any = None,
        time: Any = None,
        policy: Optional[DeliveryPolicy] = None,
        embargo_policy: Optional[DeliveryPolicy] = None,
        case_embargoes: Optional[Mapping[str, Any]] = None,
        case_embargo: Optional[Mapping[str, Any]] = None,
        case_policies: Optional[Mapping[str, Any]] = None,
        case_release_times: Optional[Mapping[str, Any]] = None,
        version_overrides: Optional[Mapping[str, Any]] = None,
        version_pins: Optional[Mapping[str, Any]] = None,
        generated_at: Any = None,
        _internal: Optional[dict[str, Any]] = None,
    ):
        if _internal is not None:
            self.__dict__.update(_internal)
            return

        objects = _first_not_none(objects, bundle, object_list, stix_objects)
        relationships = _first_not_none(relationships, rels, relations, sros)
        request = _request_fields(objects)
        if request is not None:
            objects = _first_not_none(
                request.get("objects"),
                request.get("bundle"),
                request.get("object_list"),
                request.get("stix_objects"),
            )
            relationships = _first_not_none(
                relationships,
                request.get("relationships"),
                request.get("rels"),
                request.get("relations"),
                request.get("sros"),
            )
            receiving_categories = _first_not_none(
                receiving_categories,
                request.get("receiving_categories"),
                request.get("receiving_category"),
                request.get("category"),
                request.get("categories"),
                request.get("receiver_categories"),
                request.get("audience"),
                request.get("audiences"),
                request.get("recipients"),
                request.get("release_to"),
                request.get("release_scope"),
                request.get("groups"),
            )
            at = _first_not_none(
                at,
                request.get("at"),
                request.get("delivery_at"),
                request.get("delivery_time"),
                request.get("when"),
                request.get("now"),
                request.get("as_of"),
                request.get("at_time"),
                request.get("timestamp"),
            )
            case_embargoes = _first_not_none(
                case_embargoes,
                request.get("case_embargoes"),
                request.get("case_embargo"),
                request.get("case_policies"),
                request.get("case_release_times"),
            )
            version_overrides = _first_not_none(
                version_overrides,
                request.get("version_overrides"),
                request.get("version_pins"),
            )
            policy = _first_not_none(policy, request.get("embargo_policy"))
            policy = _first_not_none(policy, request.get("policy"))
            generated_at = _first_not_none(
                generated_at, request.get("generated_at")
            )

        relationships, receiving_categories, at = _coerce_preview_args(
            relationships, receiving_categories, at
        )
        policy = _first_not_none(policy, embargo_policy)
        if isinstance(policy, Mapping):
            policy = DeliveryPolicy(**policy)
        case_embargoes = _first_not_none(
            case_embargoes,
            case_embargo,
            case_policies,
            case_release_times,
        )
        version_overrides = _first_not_none(
            version_overrides, version_pins
        )
        category_value = _first_not_none(
            receiving_categories,
            receiving_category,
            category,
            categories,
            receiver_categories,
            audience,
            audiences,
            recipient,
            recipients,
            release_to,
            release_scope,
            groups,
        )
        delivery_time = _first_not_none(
            at,
            delivery_at,
            delivery_time,
            when,
            now,
            as_of,
            at_time,
            timestamp,
            time,
        )
        if delivery_time is None:
            delivery_time = get_timestamp()

        self.policy = policy or DeliveryPolicy()
        self.at = _to_utc(delivery_time)
        self.delivery_at = _iso(self.at)
        self.receiving_categories = tuple(
            sorted(_normalise_categories(category_value) or {"*"})
        )
        self._raw_objects = _as_object_list(objects)
        self._raw_relationships = _as_object_list(relationships)
        self._case_embargoes = dict(case_embargoes or {})
        self._version_overrides = dict(version_overrides or {})
        self._overrides: dict[str, dict[str, Any]] = {}
        self.generated_at = _iso(
            generated_at if generated_at is not None else get_timestamp()
        )
        self.revision = 1
        self.parent_revision: Optional[int] = None
        self.updated_ids: list[str] = []
        self.change_log: list[dict[str, Any]] = []
        self.path: Optional[str] = None
        self._recompute()

    # ------------------------------------------------------------------
    # Construction / recomputation
    # ------------------------------------------------------------------
    def _recompute(self) -> None:
        built = _build_preview(
            self._raw_objects,
            self._raw_relationships,
            self.receiving_categories,
            self.at,
            self.policy,
            self._case_embargoes,
            self._version_overrides,
            self._overrides,
            self.generated_at,
        )
        self._built = built
        items = list(built["items"])
        if not self.policy.include_blocked_items:
            items = [item for item in items if item.allowed]
        self._items = items
        self._by_id = {item.id: item for item in items}
        self.object_items = tuple(
            item for item in self._items if item.kind == "object"
        )
        self.relationship_items = tuple(
            item for item in self._items if item.kind == "relationship"
        )
        self.warnings = list(built["warnings"])
        self.version_notes = list(built["version_notes"])
        self.cycles = list(built["cycles"])
        if not self.policy.include_blocked_items:
            self.cycles = [
                cycle
                for cycle in self.cycles
                if all(member in self._by_id for member in cycle["members"])
            ]

    # ------------------------------------------------------------------
    # Convenient immutable views
    # ------------------------------------------------------------------
    @property
    def items(self) -> tuple[DeliveryItem, ...]:
        return tuple(self._items)

    @property
    def preview_revision(self) -> int:
        return self.revision

    @property
    def changes(self) -> list[dict[str, Any]]:
        return self.change_log

    @property
    def revision_log(self) -> list[dict[str, Any]]:
        return self.change_log

    def build(self) -> "DeliveryPreview":
        return self

    def result(self) -> "DeliveryPreview":
        return self

    @property
    def updated_items(self) -> tuple[DeliveryItem, ...]:
        return tuple(
            self._by_id[item_id]
            for item_id in self.updated_ids
            if item_id in self._by_id
        )

    @property
    def updates(self) -> dict[str, DeliveryItem]:
        return {item.id: item for item in self.updated_items}

    @property
    def by_id(self) -> dict[str, DeliveryItem]:
        return self._by_id

    @property
    def item_by_id(self) -> dict[str, DeliveryItem]:
        return self._by_id

    @property
    def items_by_id(self) -> dict[str, DeliveryItem]:
        return self._by_id

    @property
    def case_embargoes(self) -> dict[str, Any]:
        return dict(self._case_embargoes)

    @property
    def version_overrides(self) -> dict[str, Any]:
        return dict(self._version_overrides)

    @property
    def version_refs(self) -> dict[str, dict[str, Any]]:
        return {
            item.id: copy.deepcopy(item.version_refs)
            for item in self._items
        }

    @property
    def overrides(self) -> dict[str, dict[str, Any]]:
        return copy.deepcopy(self._overrides)

    @property
    def objects(self) -> tuple[Any, ...]:
        return tuple(
            item.obj for item in self.object_items if item.obj is not None
        )

    @property
    def relationships(self) -> tuple[Any, ...]:
        return tuple(
            item.obj for item in self.relationship_items if item.obj is not None
        )

    @property
    def selected_objects(self) -> tuple[Any, ...]:
        return self.objects

    @property
    def released_items(self) -> tuple[DeliveryItem, ...]:
        return tuple(item for item in self._items if item.allowed)

    @property
    def allowed_items(self) -> tuple[DeliveryItem, ...]:
        return self.released_items

    @property
    def blocked_items(self) -> tuple[DeliveryItem, ...]:
        return tuple(item for item in self._items if not item.allowed)

    @property
    def embargoed_items(self) -> tuple[DeliveryItem, ...]:
        return self.blocked_items

    @property
    def released_object_items(self) -> tuple[DeliveryItem, ...]:
        return tuple(item for item in self.object_items if item.allowed)

    @property
    def released_relationship_items(self) -> tuple[DeliveryItem, ...]:
        return tuple(item for item in self.relationship_items if item.allowed)

    @property
    def allowed_object_items(self) -> tuple[DeliveryItem, ...]:
        return self.released_object_items

    @property
    def allowed_relationship_items(self) -> tuple[DeliveryItem, ...]:
        return self.released_relationship_items

    @property
    def blocked_object_items(self) -> tuple[DeliveryItem, ...]:
        return tuple(item for item in self.object_items if not item.allowed)

    @property
    def blocked_relationship_items(self) -> tuple[DeliveryItem, ...]:
        return tuple(item for item in self.relationship_items if not item.allowed)

    @property
    def released_objects(self) -> tuple[Any, ...]:
        return tuple(
            item.obj
            for item in self.object_items
            if item.allowed and item.obj is not None
        )

    @property
    def released_relationships(self) -> tuple[Any, ...]:
        return tuple(
            item.obj
            for item in self.relationship_items
            if item.allowed and item.obj is not None
        )

    @property
    def allowed_objects(self) -> tuple[Any, ...]:
        return self.released_objects

    @property
    def allowed_relationships(self) -> tuple[Any, ...]:
        return self.released_relationships

    @property
    def denied_items(self) -> tuple[DeliveryItem, ...]:
        return self.blocked_items

    @property
    def denied_objects(self) -> tuple[Any, ...]:
        return self.blocked_objects

    @property
    def denied_relationships(self) -> tuple[Any, ...]:
        return self.blocked_relationships

    @property
    def denied_ids(self) -> list[str]:
        return self.blocked_ids

    @property
    def embargoed_ids(self) -> list[str]:
        return self.blocked_ids

    @property
    def allowed(self) -> list[str]:
        return self.allowed_ids

    @property
    def publishable(self) -> list[str]:
        return self.allowed_ids

    @property
    def embargoed_objects(self) -> tuple[Any, ...]:
        return self.blocked_objects

    @property
    def embargoed_relationships(self) -> tuple[Any, ...]:
        return self.blocked_relationships

    @property
    def blocked_objects(self) -> tuple[Any, ...]:
        return tuple(
            item.obj
            for item in self.object_items
            if not item.allowed and item.obj is not None
        )

    @property
    def blocked_relationships(self) -> tuple[Any, ...]:
        return tuple(
            item.obj
            for item in self.relationship_items
            if not item.allowed and item.obj is not None
        )

    @property
    def released(self) -> dict[str, Any]:
        return {
            "ids": self.released_ids,
            "objects": self.released_objects,
            "relationships": self.released_relationships,
        }

    @property
    def blocked(self) -> dict[str, Any]:
        return {
            "ids": self.blocked_ids,
            "objects": self.blocked_objects,
            "relationships": self.blocked_relationships,
        }

    @property
    def permitted(self) -> dict[str, Any]:
        return self.released

    @property
    def published(self) -> dict[str, Any]:
        return self.released

    @property
    def denied(self) -> dict[str, Any]:
        return self.blocked

    @property
    def embargoed(self) -> dict[str, Any]:
        return self.blocked

    @property
    def category_sets(self) -> dict[str, dict[str, list[str]]]:
        return {
            item.id: copy.deepcopy(item.category_sets)
            for item in self._items
        }

    @property
    def category_sources(self) -> list[str]:
        return sorted(
            {
                source
                for item in self._items
                for source in item.category_sets
            }
        )

    @property
    def categories(self) -> list[str]:
        return self.allowed_categories

    @property
    def allowed_categories(self) -> list[str]:
        return sorted(
            {
                category
                for item in self._items
                for category in item.allowed_categories
            }
        )

    @property
    def allowed_ids(self) -> list[str]:
        return sorted(item.id for item in self._items if item.allowed)

    @property
    def released_ids(self) -> list[str]:
        return self.allowed_ids

    @property
    def published_ids(self) -> list[str]:
        return self.allowed_ids

    @property
    def released_object_ids(self) -> list[str]:
        return sorted(
            item.id for item in self.object_items if item.allowed
        )

    allowed_object_ids = released_object_ids

    @property
    def released_relationship_ids(self) -> list[str]:
        return sorted(
            item.id for item in self.relationship_items if item.allowed
        )

    allowed_relationship_ids = released_relationship_ids

    @property
    def blocked_ids(self) -> list[str]:
        return sorted(item.id for item in self._items if not item.allowed)

    @property
    def blocked_object_ids(self) -> list[str]:
        return sorted(
            item.id for item in self.object_items if not item.allowed
        )

    denied_object_ids = blocked_object_ids

    @property
    def blocked_relationship_ids(self) -> list[str]:
        return sorted(
            item.id for item in self.relationship_items if not item.allowed
        )

    denied_relationship_ids = blocked_relationship_ids

    @property
    def allowed_set(self) -> set[str]:
        return set(self.allowed_ids)

    @property
    def delivery_time(self) -> str:
        return self.delivery_at

    @property
    def at_iso(self) -> str:
        return self.delivery_at

    @property
    def filename(self) -> Optional[str]:
        return self.path

    @property
    def time(self) -> str:
        return self.delivery_at

    @property
    def receiving_category(self) -> Any:
        if len(self.receiving_categories) == 1:
            return self.receiving_categories[0]
        return self.receiving_categories

    @property
    def delivery_categories(self) -> tuple[str, ...]:
        return self.receiving_categories

    @property
    def item_ids(self) -> list[str]:
        return sorted(self._by_id)

    @property
    def object_ids(self) -> list[str]:
        return sorted(item.id for item in self.object_items)

    @property
    def relationship_ids(self) -> list[str]:
        return sorted(item.id for item in self.relationship_items)

    @property
    def released_set(self) -> set[str]:
        return set(self.released_ids)

    @property
    def release_set(self) -> set[str]:
        return self.released_set

    @property
    def allowed_item_ids(self) -> set[str]:
        return self.allowed_set

    @property
    def blocked_set(self) -> set[str]:
        return set(self.blocked_ids)

    @property
    def blocked_item_ids(self) -> set[str]:
        return self.blocked_set

    @property
    def permit_list(self) -> list[ReleasePermit]:
        return [
            item.permit for item in self._items if item.permit is not None
        ]

    @property
    def permits(self) -> dict[str, ReleasePermit]:
        return {
            item.id: item.permit
            for item in self._items
            if item.permit is not None
        }

    @property
    def permits_by_id(self) -> dict[str, ReleasePermit]:
        return self.permits

    @property
    def denied_permits(self) -> list[ReleasePermit]:
        return [permit for permit in self.permit_list if permit.denied]

    @property
    def granted_permits(self) -> list[ReleasePermit]:
        return [permit for permit in self.permit_list if permit.granted]

    @property
    def released_permits(self) -> list[ReleasePermit]:
        return self.granted_permits

    @property
    def still_blocked_permits(self) -> list[ReleasePermit]:
        return [
            permit
            for permit in self.permit_list
            if permit.still_blocks_publication
        ]

    @property
    def blocked_permits(self) -> list[ReleasePermit]:
        return self.denied_permits

    @property
    def embargoed_permits(self) -> list[ReleasePermit]:
        return self.denied_permits

    @property
    def permission_list(self) -> list[ReleasePermit]:
        return self.permit_list

    @property
    def permissions(self) -> dict[str, ReleasePermit]:
        return self.permits

    @property
    def authorizations(self) -> dict[str, ReleasePermit]:
        return self.permits

    @property
    def bundle(self) -> Bundle:
        return self.to_bundle()

    @property
    def released_bundle(self) -> Bundle:
        return self.to_bundle()

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------
    def to_bundle(self) -> Bundle:
        """Return a bundle containing all released objects and relationships."""

        selected = self.released_objects + self.released_relationships
        selected = sorted(selected, key=lambda obj: (obj.get("type", ""), obj.get("id", "")))
        bundle = Bundle(objects=selected, allow_custom=True)
        if not selected:
            bundle._inner["objects"] = []
        return bundle

    def to_dict(self, include_bundle: bool = True) -> dict[str, Any]:
        object_payloads = [
            item.to_dict() for item in self._items if item.kind == "object"
        ]
        relationship_payloads = [
            item.to_dict()
            for item in self._items
            if item.kind == "relationship"
        ]
        released_object_ids = [
            item.id
            for item in self._items
            if item.kind == "object" and item.allowed
        ]
        released_relationship_ids = [
            item.id
            for item in self._items
            if item.kind == "relationship" and item.allowed
        ]
        blocked_object_ids = [
            item.id
            for item in self._items
            if item.kind == "object" and not item.allowed
        ]
        blocked_relationship_ids = [
            item.id
            for item in self._items
            if item.kind == "relationship" and not item.allowed
        ]
        data = {
            "type": "delivery-preview",
            "format_version": "1.0",
            "generated_at": self.generated_at,
            "path": self.path,
            "delivery_at": self.delivery_at,
            "delivery_time": self.delivery_at,
            "receiving_categories": list(self.receiving_categories),
            "receiving_category": (
                self.receiving_categories[0]
                if len(self.receiving_categories) == 1
                else list(self.receiving_categories)
            ),
            "allowed_categories": self.allowed_categories,
            "categories": self.allowed_categories,
            "category_sets": {
                item.id: copy.deepcopy(item.category_sets)
                for item in self._items
            },
            "category_sources": self.category_sources,
            "case_embargoes": {
                str(key): _plain(value)
                for key, value in self._case_embargoes.items()
            },
            "version_overrides": {
                str(key): _plain(value)
                for key, value in self._version_overrides.items()
            },
            "revision": self.revision,
            "parent_revision": self.parent_revision,
            "updated_ids": list(self.updated_ids),
            "updated_items": {
                item.id: item.to_dict() for item in self.updated_items
            },
            "objects": object_payloads,
            "relationships": relationship_payloads,
            "object_items": object_payloads,
            "relationship_items": relationship_payloads,
            "items": [item.to_dict() for item in self._items],
            "stix_objects": [
                _object_payload(obj) for obj in self.objects
            ],
            "stix_relationships": [
                _object_payload(obj) for obj in self.relationships
            ],
            "released_objects": [
                _object_payload(obj) for obj in self.released_objects
            ],
            "released_relationships": [
                _object_payload(obj) for obj in self.released_relationships
            ],
            "blocked_objects": [
                _object_payload(obj) for obj in self.blocked_objects
            ],
            "blocked_relationships": [
                _object_payload(obj) for obj in self.blocked_relationships
            ],
            "released": {
                "object_ids": sorted(released_object_ids),
                "relationship_ids": sorted(released_relationship_ids),
                "ids": sorted(released_object_ids + released_relationship_ids),
            },
            "blocked": {
                "object_ids": sorted(blocked_object_ids),
                "relationship_ids": sorted(blocked_relationship_ids),
                "ids": sorted(blocked_object_ids + blocked_relationship_ids),
            },
            "released_object_ids": sorted(released_object_ids),
            "released_relationship_ids": sorted(released_relationship_ids),
            "allowed_object_ids": sorted(released_object_ids),
            "allowed_relationship_ids": sorted(released_relationship_ids),
            "denied_object_ids": self.blocked_object_ids,
            "denied_relationship_ids": self.blocked_relationship_ids,
            "object_ids": self.object_ids,
            "relationship_ids": self.relationship_ids,
            "allowed_ids": self.allowed_ids,
            "released_ids": self.released_ids,
            "blocked_ids": self.blocked_ids,
            "allowed_objects": [
                _object_payload(obj) for obj in self.released_objects
            ],
            "allowed_relationships": [
                _object_payload(obj) for obj in self.released_relationships
            ],
            "denied_objects": [
                _object_payload(obj) for obj in self.blocked_objects
            ],
            "denied_relationships": [
                _object_payload(obj) for obj in self.blocked_relationships
            ],
            "permits": [permit.to_dict() for permit in self.permit_list],
            "permit_by_id": {
                permit.item_id: permit.to_dict()
                for permit in self.permit_list
            },
            "permits_by_id": {
                permit.item_id: permit.to_dict()
                for permit in self.permit_list
            },
            "version_refs": {
                item.id: copy.deepcopy(item.version_refs)
                for item in self._items
            },
            "version_selections": {
                item.id: {
                    "kind": item.kind,
                    "version": item.version,
                    "version_property": item.version_property,
                    "version_rule": item.version_rule,
                    "source_version": item.source_version,
                    "target_version": item.target_version,
                    "source_version_declared": item.source_version_declared,
                    "target_version_declared": item.target_version_declared,
                    "source_spec_version": item.source_spec_version,
                    "target_spec_version": item.target_spec_version,
                    "cross_version_reference": item.cross_version_reference,
                    "version_refs": copy.deepcopy(item.version_refs),
                    "version_note": item.version_note,
                }
                for item in self._items
            },
            "cycles": copy.deepcopy(self.cycles),
            "version_notes": list(self.version_notes),
            "warnings": list(self.warnings),
            "change_log": copy.deepcopy(self.change_log),
            "changes": copy.deepcopy(self.change_log),
            "revision_log": copy.deepcopy(self.change_log),
        }
        if include_bundle:
            try:
                data["bundle"] = _object_payload(self.to_bundle())
            except Exception as exc:  # pragma: no cover - defensive
                data["bundle"] = None
                data["bundle_error"] = str(exc)
        return data

    def serialize(self, pretty: bool = False) -> str:
        return json.dumps(
            self.to_dict(),
            indent=2 if pretty else None,
            sort_keys=pretty,
            ensure_ascii=False,
        )

    to_json = serialize

    def save(
        self,
        path: str | os.PathLike[str] = ".",
        *,
        pretty: bool = True,
    ) -> str:
        """Write the preview to *path*.

        If *path* names an existing directory, a deterministic filename is
        generated inside it.
        """

        target = Path(path)
        as_directory = target.is_dir() or (
            not target.exists() and target.suffix == ""
        )
        if as_directory:
            target.mkdir(parents=True, exist_ok=True)
            compact = self.delivery_at.replace(":", "").replace("-", "")
            target = target / f"delivery-preview-r{self.revision}-{compact}.json"
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(self.serialize(pretty=pretty), encoding="utf-8")
        self.path = str(target)
        return self.path

    write = save
    dump = save

    # ------------------------------------------------------------------
    # Temporary extension
    # ------------------------------------------------------------------
    def extend_embargo(
        self,
        item_ids: str | Iterable[str],
        until: Any,
        reason: Optional[str] = None,
        *,
        in_place: bool = False,
        now: Any = None,
    ) -> "DeliveryPreview":
        """Temporarily extend the release time of selected delivery items.

        Only the named items and items whose decisions depend on them are
        revised.  All other items retain their original revision number and
        ``updated_at`` value, which is important when a preview has already
        been handed to a publishing backend.
        """

        ids = _normalise_ids(item_ids)
        unknown = [item_id for item_id in ids if item_id not in self._by_id]
        if unknown:
            raise KeyError(
                "unknown delivery item(s): {}".format(", ".join(sorted(unknown)))
            )
        if until is None:
            new_overrides = copy.deepcopy(self._overrides)
            for item_id in ids:
                new_overrides.pop(item_id, None)
        else:
            parsed_until = _to_utc(until)
            new_overrides = copy.deepcopy(self._overrides)
            for item_id in ids:
                current = new_overrides.get(item_id, {})
                current["until"] = _iso(parsed_until)
                if reason is not None:
                    current["reason"] = reason
                new_overrides[item_id] = current

        revision_at = _iso(now if now is not None else get_timestamp())
        new_preview = type(self)(
            self._raw_objects,
            self._raw_relationships,
            self.receiving_categories,
            self.at,
            policy=self.policy,
            case_embargoes=self._case_embargoes,
            version_overrides=self._version_overrides,
            generated_at=revision_at,
        )
        new_preview._overrides = new_overrides
        new_preview._recompute()

        updated_ids: list[str] = []
        merged_items: list[DeliveryItem] = []
        for new_item in new_preview._items:
            old_item = self._by_id.get(new_item.id)
            if old_item is not None and _same_decision(old_item, new_item):
                merged_items.append(old_item)
                continue
            new_item.revision = (
                old_item.revision + 1 if old_item is not None else 1
            )
            new_item.updated_at = revision_at
            new_item.permit = _permit_with_evaluated_at(
                new_item.permit, revision_at
            )
            updated_ids.append(new_item.id)
            merged_items.append(new_item)

        new_preview._items = merged_items
        new_preview.object_items = tuple(
            item for item in merged_items if item.kind == "object"
        )
        new_preview.relationship_items = tuple(
            item for item in merged_items if item.kind == "relationship"
        )
        new_preview._by_id = {item.id: item for item in merged_items}
        new_preview.parent_revision = self.revision
        new_preview.updated_ids = sorted(updated_ids)
        if updated_ids:
            new_preview.revision = self.revision + 1
            new_preview.change_log = copy.deepcopy(self.change_log)
            new_preview.change_log.append(
                {
                    "revision": new_preview.revision,
                    "parent_revision": self.revision,
                    "at": revision_at,
                    "requested_ids": sorted(ids),
                    "updated_ids": sorted(updated_ids),
                    "until": _iso(_to_utc(until)) if until is not None else None,
                    "reason": reason,
                }
            )
            # Cycles are structural, not decision state; keep their metadata
            # on the merged items and recompute the preview-level view.
            new_preview.cycles = list(new_preview._built["cycles"])
        else:
            new_preview.revision = self.revision
            new_preview.change_log = copy.deepcopy(self.change_log)

        if in_place:
            self.__dict__.update(new_preview.__dict__)
            return self
        return new_preview

    # Common aliases used by publishing backends.
    temporarily_extend_embargo = extend_embargo
    temporarily_extend_release = extend_embargo
    extend_embargo_until = extend_embargo
    extend_release = extend_embargo
    delay_release = extend_embargo

    def clear_embargo_extension(
        self,
        item_ids: str | Iterable[str],
        *,
        in_place: bool = False,
        now: Any = None,
    ) -> "DeliveryPreview":
        return self.extend_embargo(
            item_ids, None, in_place=in_place, now=now
        )

    clear_extension = clear_embargo_extension

    def extend_case_embargo(
        self,
        case_ids: str | Iterable[str],
        until: Any,
        reason: Optional[str] = None,
        *,
        in_place: bool = False,
        now: Any = None,
    ) -> "DeliveryPreview":
        wanted = set(_normalise_ids(case_ids))
        affected = sorted(
            item.id
            for item in self._items
            if wanted.intersection(item.case_refs)
        )
        if not affected:
            raise KeyError(
                "no delivery items reference restricted case(s): {}".format(
                    ", ".join(sorted(wanted))
                )
            )
        result = self.extend_embargo(
            affected,
            until,
            reason=reason,
            in_place=in_place,
            now=now,
        )
        for case_id in sorted(wanted):
            previous = result._case_embargoes.get(case_id)
            if isinstance(previous, Mapping):
                merged = dict(previous)
            elif previous is not None:
                merged = {"until": _plain(previous)}
            else:
                merged = {}
            merged["until"] = _iso(_to_utc(until))
            if reason is not None:
                merged["reason"] = reason
            result._case_embargoes[case_id] = merged
        return result

    extend_restricted_case_embargo = extend_case_embargo

    def clear_case_embargo_extension(
        self,
        case_ids: str | Iterable[str],
        *,
        in_place: bool = False,
        now: Any = None,
    ) -> "DeliveryPreview":
        wanted = set(_normalise_ids(case_ids))
        affected = sorted(
            item.id
            for item in self._items
            if wanted.intersection(item.case_refs)
        )
        result = self.clear_extension(
            affected, in_place=in_place, now=now
        )
        for case_id in wanted:
            result._case_embargoes.pop(case_id, None)
        return result

    clear_restricted_case_extension = clear_case_embargo_extension

    @classmethod
    def transition(
        cls,
        objects: Any = None,
        relationships: Any = None,
        receiving_categories: Any = None,
        embargo_until: Any = None,
        **kwargs: Any,
    ) -> "EmbargoTransition":
        return preview_transition(
            objects,
            relationships,
            receiving_categories,
            embargo_until,
            **kwargs,
        )

    around_embargo = transition
    before_after = transition

    def get_item(self, item_id: str) -> DeliveryItem:
        return self._by_id[item_id]

    def get_permit(self, item_id: str) -> ReleasePermit:
        return self._by_id[item_id].permit

    def permit(self, item_id: str) -> ReleasePermit:
        return self.get_permit(item_id)

    def permit_for(self, item_id: str) -> ReleasePermit:
        return self.get_permit(item_id)

    def item(self, item_id: str) -> DeliveryItem:
        return self.get_item(item_id)

    def item_for(self, item_id: str) -> DeliveryItem:
        return self.get_item(item_id)

    # ------------------------------------------------------------------
    # Mapping-like access
    # ------------------------------------------------------------------
    def __getitem__(self, key: str) -> Any:
        if key in self._by_id:
            return self._by_id[key]
        data = self.to_dict()
        try:
            return data[key]
        except KeyError:
            raise KeyError(key) from None

    def get(self, key: str, default: Any = None) -> Any:
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key: str) -> bool:
        return key in self._by_id or key in self.to_dict()

    def __iter__(self):
        return iter(sorted(self._by_id))

    def __len__(self) -> int:
        return len(self._items)


# ----------------------------------------------------------------------
# Public convenience functions
# ----------------------------------------------------------------------
def _looks_like_stix_collection(value: Any) -> bool:
    # Whether a positional value looks like objects, not category names.
    if value is None:
        return False
    if isinstance(value, Mapping):
        return True
    if isinstance(value, (str, bytes)):
        return False
    if hasattr(value, "query"):
        return True
    try:
        items = list(value)
    except TypeError:
        return False
    return any(isinstance(item, Mapping) for item in items)


def _looks_like_timestamp(value: Any) -> bool:
    if isinstance(value, (dt.date, dt.datetime)):
        return True
    if not isinstance(value, str):
        return False
    try:
        _to_utc(value)
    except (TypeError, ValueError):
        return False
    return True


def _request_fields(value: Any) -> Optional[dict[str, Any]]:
    if not isinstance(value, Mapping):
        return None
    if value.get("type") in {"bundle", "delivery-preview"}:
        return None
    if not any(
        key in value
        for key in ("objects", "bundle", "object_list", "stix_objects")
    ):
        return None
    return dict(value)


def _coerce_preview_args(
    relationships: Any,
    receiving_categories: Any,
    at: Any,
) -> tuple[Any, Any, Any]:
    # Support both (objects, relationships, categories, at) and the
    # backend-friendly (objects, categories, at) positional forms.
    if (
        relationships is not None
        and not isinstance(relationships, (str, bytes, Mapping))
        and not hasattr(relationships, "query")
    ):
        try:
            relationships = list(relationships)
        except TypeError:
            pass
    if relationships is not None and not _looks_like_stix_collection(relationships):
        if (
            at is None
            and receiving_categories is not None
            and _looks_like_timestamp(receiving_categories)
        ):
            at = receiving_categories
        receiving_categories = relationships
        relationships = None
    return relationships, receiving_categories, at


def preview_delivery(
    objects: Any = None,
    relationships: Any = None,
    receiving_categories: Any = None,
    at: Any = None,
    **kwargs: Any,
) -> DeliveryPreview:
    """Build a :class:`DeliveryPreview` for a publishing backend.

    ``objects`` may be a list of STIX objects/dicts, a STIX ``Bundle``, or an
    ``Environment``/data source with a ``query`` method.  Relationships may be
    supplied separately or mixed into ``objects``.
    """

    if objects is None:
        objects = _first_not_none(
            kwargs.pop("bundle", None),
            kwargs.pop("object_list", None),
            kwargs.pop("stix_objects", None),
        )
    if relationships is None:
        relationships = kwargs.pop("rels", None)
    return DeliveryPreview(
        objects=objects,
        relationships=relationships,
        receiving_categories=receiving_categories,
        at=at,
        **kwargs,
    )


delivery_preview = preview_delivery
build_delivery_preview = preview_delivery
compute_delivery_preview = preview_delivery


def preview_transition(
    objects: Any = None,
    relationships: Any = None,
    receiving_categories: Any = None,
    embargo_until: Any = None,
    *,
    before: Any = None,
    after: Any = None,
    at: Any = None,
    **kwargs: Any,
) -> EmbargoTransition:
    """Build before/after previews around an embargo lifting event.

    By default the "before" preview is evaluated one microsecond before
    ``embargo_until`` and the "after" preview exactly at ``embargo_until``.
    """

    if (
        relationships is not None
        and not isinstance(relationships, (str, bytes, Mapping))
        and not hasattr(relationships, "query")
    ):
        try:
            relationships = list(relationships)
        except TypeError:
            pass

    request = _request_fields(objects)
    if request is not None:
        embargo_until = _first_not_none(
            embargo_until,
            request.get("embargo_until"),
            request.get("embargo_time"),
            request.get("release_at"),
            request.get("declassify_at"),
        )
        before = _first_not_none(before, request.get("before"))
        after = _first_not_none(after, request.get("after"))
        at = _first_not_none(at, request.get("at"))

    before = _first_not_none(before, kwargs.pop("before_at", None))
    after = _first_not_none(after, kwargs.pop("after_at", None))

    if relationships is not None and not _looks_like_stix_collection(relationships):
        if (
            embargo_until is None
            and receiving_categories is not None
            and _looks_like_timestamp(receiving_categories)
        ):
            embargo_until = receiving_categories
        receiving_categories = relationships
        relationships = None

    target = _first_not_none(
        embargo_until,
        at,
        kwargs.pop("embargo_time", None),
        kwargs.pop("release_at", None),
        kwargs.pop("declassify_at", None),
    )
    if target is None:
        raise DeliveryPreviewError(
            "embargo_until is required for a delivery transition"
        )
    target_dt = _to_utc(target)
    before_dt = (
        _to_utc(before)
        if before is not None
        else target_dt - dt.timedelta(microseconds=1)
    )
    after_dt = _to_utc(after) if after is not None else target_dt
    if before_dt >= target_dt:
        raise DeliveryPreviewError("before time must be earlier than embargo_until")
    if after_dt < target_dt:
        raise DeliveryPreviewError(
            "after time must be at or later than embargo_until"
        )

    before_preview = preview_delivery(
        objects,
        relationships,
        receiving_categories,
        before_dt,
        **kwargs,
    )
    after_preview = preview_delivery(
        objects,
        relationships,
        receiving_categories,
        after_dt,
        **kwargs,
    )
    return EmbargoTransition(
        before=before_preview,
        after=after_preview,
        embargo_until=_iso(target_dt),
    )


preview_around_embargo = preview_transition
delivery_transition = preview_transition
embargo_transition = preview_transition
preview_release = preview_delivery
release_preview = preview_delivery
preview_release_set = preview_delivery
build_release_preview = preview_delivery
compute_release_set = preview_delivery
compute_delivery_set = preview_delivery

EmbargoPolicy = DeliveryPolicy
DeclassificationPolicy = DeliveryPolicy
ReleasePreview = DeliveryPreview
EmbargoPreview = DeliveryPreview
PublicationPreview = DeliveryPreview
DeliveryPlanner = DeliveryPreview
DeliveryPreviewBuilder = DeliveryPreview
ReleaseDecision = DeliveryItem
DeliveryPermit = ReleasePermit
EmbargoPermit = ReleasePermit
Permission = ReleasePermit


# ----------------------------------------------------------------------
# Internal data structures
# ----------------------------------------------------------------------
@dataclass
class _Selection:
    obj: Any
    id: str
    type: str
    spec_version: str
    version: Optional[str]
    version_property: Optional[str]
    version_dt: Optional[dt.datetime]
    rule: str
    pin: Optional[str]
    error: Optional[str] = None
    warning: Optional[str] = None
    candidates: int = 1


@dataclass
class _Restriction:
    release_at: Optional[dt.datetime] = None
    release_at_property: Optional[str] = None
    category_sets: list[tuple[str, frozenset[str]]] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    case_refs: list[str] = field(default_factory=list)
    times: list[tuple[dt.datetime, str]] = field(default_factory=list)


def _build_preview(
    raw_objects: list[Any],
    raw_relationships: list[Any],
    receiving_categories: Iterable[str],
    at: dt.datetime,
    policy: DeliveryPolicy,
    case_embargoes: Mapping[str, Any],
    version_overrides: Mapping[str, Any],
    overrides: Mapping[str, Mapping[str, Any]],
    generated_at: str,
) -> dict[str, Any]:
    warnings: list[str] = []
    version_notes: list[str] = []
    at_iso = _iso(at)
    categories = frozenset(_normalise_categories(receiving_categories))

    all_raw = _dedupe_objects(raw_objects + raw_relationships, warnings)
    object_groups: dict[str, list[Any]] = defaultdict(list)
    relationship_groups: dict[str, list[Any]] = defaultdict(list)
    type_hints: dict[str, str] = {}
    for obj in all_raw:
        obj_id = _obj_id(obj)
        if not obj_id:
            warnings.append("ignored an object without an 'id'")
            continue
        type_hints.setdefault(obj_id, str(obj.get("type", "unknown")))
        if _is_relationship(obj):
            relationship_groups[obj_id].append(obj)
        else:
            object_groups[obj_id].append(obj)

    # Object versions are selected independently for every STIX ID.  A
    # relationship is bound to the version chosen here and records it.
    object_selections: dict[str, _Selection] = {}
    for obj_id in sorted(object_groups):
        pin = version_overrides.get(obj_id)
        selection = _select_version(
            object_groups[obj_id],
            obj_id,
            at,
            pin=pin,
            strict_pin=pin is not None,
        )
        object_selections[obj_id] = selection
        if selection.warning:
            warnings.append(selection.warning)
        if selection.error:
            warnings.append(f"{obj_id}: {selection.error}")

    # Relationships may explicitly declare the endpoint version they were
    # written against (x_source_version / x_target_version).  Resolve those
    # pins before evaluating the objects, so the delivered object and the
    # relationship's version note cannot disagree.
    relationship_selections: dict[str, _Selection] = {}
    relationship_declarations: dict[str, tuple[Any, Any]] = {}
    relationship_declaration_errors: dict[str, list[str]] = defaultdict(list)
    for rel_id in sorted(relationship_groups):
        pin = version_overrides.get(rel_id)
        selection = _select_version(
            relationship_groups[rel_id],
            rel_id,
            at,
            pin=pin,
            strict_pin=pin is not None,
        )
        relationship_selections[rel_id] = selection
        if selection.warning:
            warnings.append(selection.warning)
        if selection.error:
            warnings.append(f"{rel_id}: {selection.error}")

        rel = selection.obj
        source_id = str(rel.get("source_ref")) if rel is not None else None
        target_id = str(rel.get("target_ref")) if rel is not None else None
        source_declared = _first_property_value(rel, SOURCE_VERSION_PROPERTIES)
        target_declared = _first_property_value(rel, TARGET_VERSION_PROPERTIES)
        relationship_declarations[rel_id] = (
            source_declared,
            target_declared,
        )

        for endpoint_id, declared, label in (
            (source_id, source_declared, "source"),
            (target_id, target_declared, "target"),
        ):
            if declared is None or endpoint_id not in object_groups:
                continue
            if version_overrides.get(endpoint_id) is not None:
                # An explicit backend pin wins over a relationship hint.
                continue
            pinned = _select_version(
                object_groups[endpoint_id],
                endpoint_id,
                at,
                pin=declared,
                strict_pin=True,
            )
            if pinned.error is None:
                object_selections[endpoint_id] = pinned
            else:
                message = (
                    f"{rel_id}: declared {label} version "
                    f"{declared!r} not usable ({pinned.error})"
                )
                warnings.append(message)
                relationship_declaration_errors[rel_id].append(message)

    marking_index = {
        obj_id: selection
        for obj_id, selection in object_selections.items()
        if selection.type == "marking-definition" and selection.obj is not None
    }
    referenced_case_ids: set[str] = set()
    for obj in all_raw:
        for prop in policy.case_properties:
            if prop in obj and obj.get(prop) is not None:
                referenced_case_ids.update(
                    str(case_ref)
                    for case_ref in _reference_list(obj.get(prop))
                )
        case_mapping = _first_property_value(
            obj,
            ("x_case_embargoes", "case_embargoes", "x_case_release_times"),
        )
        if isinstance(case_mapping, Mapping):
            referenced_case_ids.update(str(case_id) for case_id in case_mapping)
    case_policies = _build_case_policies(
        object_selections, case_embargoes, at, policy, referenced_case_ids
    )

    object_items: list[DeliveryItem] = []
    object_by_id: dict[str, DeliveryItem] = {}
    for obj_id in sorted(object_groups):
        selection = object_selections[obj_id]
        restriction = _restrictions_for(
            selection.obj,
            policy,
            marking_index,
            case_policies,
            overrides.get(obj_id),
        )
        item, item_warnings = _evaluate_object(
            selection,
            restriction,
            categories,
            at,
            at_iso,
            generated_at,
            policy,
        )
        if item_warnings:
            warnings.extend(item_warnings)
        object_items.append(item)
        object_by_id[obj_id] = item
        if item.version_note:
            version_notes.append(item.version_note)

    relationship_items: list[DeliveryItem] = []
    selected_relationship_ids: dict[str, Any] = {}
    for rel_id in sorted(relationship_groups):
        selection = relationship_selections[rel_id]
        selected_relationship_ids[rel_id] = selection.obj

        rel = selection.obj
        source_id = str(rel.get("source_ref")) if rel is not None else None
        target_id = str(rel.get("target_ref")) if rel is not None else None
        source_declared, target_declared = relationship_declarations[rel_id]
        source_selection = object_selections.get(source_id)
        target_selection = object_selections.get(target_id)

        restriction = _restrictions_for(
            rel,
            policy,
            marking_index,
            case_policies,
            overrides.get(rel_id),
        )
        restriction.reasons.extend(
            relationship_declaration_errors.get(rel_id, ())
        )
        item, item_warnings = _evaluate_relationship(
            selection,
            restriction,
            source_selection,
            target_selection,
            object_by_id,
            categories,
            at,
            at_iso,
            generated_at,
            policy,
            source_declared=source_declared,
            target_declared=target_declared,
        )
        if item_warnings:
            warnings.extend(item_warnings)
        relationship_items.append(item)
        if item.version_note:
            version_notes.append(item.version_note)

    items = object_items + relationship_items
    by_id = {item.id: item for item in items}

    cycles = _find_cycles(selected_relationship_ids)
    for cycle in cycles:
        cycle["released"] = bool(cycle["members"]) and all(
            by_id[rel_id].allowed
            for rel_id in cycle["members"]
            if rel_id in by_id
        )
        for rel_id in cycle["members"]:
            item = by_id.get(rel_id)
            if item is None:
                continue
            item.cycle_id = cycle["id"]
            item.cycle_path = list(cycle["path"])
            item.cycle_members = list(cycle["members"])
            item.cycle_direction = "source_ref->target_ref"
            item.cycle_next_ref = item.destination_ref

    return {
        "items": items,
        "by_id": by_id,
        "warnings": _dedupe_strings(warnings),
        "version_notes": _dedupe_strings(version_notes),
        "cycles": cycles,
    }


def _evaluate_object(
    selection: _Selection,
    restriction: _Restriction,
    receiving_categories: frozenset[str],
    at: dt.datetime,
    at_iso: str,
    generated_at: str,
    policy: DeliveryPolicy,
) -> tuple[DeliveryItem, list[str]]:
    reasons: list[str] = []
    warnings = list(restriction.warnings)
    blocked_by: list[str] = []
    obj = selection.obj

    if selection.error:
        reasons.append(selection.error)
    if obj is not None and _is_revoked(obj):
        reasons.append("object is revoked")
    reasons.extend(restriction.reasons)

    category_misses = _category_misses(
        restriction.category_sets, receiving_categories
    )
    reasons.extend(category_misses)

    if restriction.release_at is not None:
        if policy.release_time_inclusive:
            still_embargoed = at < restriction.release_at
        else:
            still_embargoed = at <= restriction.release_at
        if still_embargoed:
            reasons.append(
                _embargo_reason(restriction.release_at, restriction.release_at_property)
            )

    allowed = not reasons
    status = "released" if allowed else "blocked"
    version_note = _object_version_note(selection, at_iso)
    item = DeliveryItem(
        id=selection.id,
        kind="object",
        type=selection.type,
        spec_version=selection.spec_version,
        status=status,
        allowed=allowed,
        revision=1,
        updated_at=generated_at,
        release_at=_optional_iso(restriction.release_at),
        embargo_until=_optional_iso(restriction.release_at),
        release_at_property=restriction.release_at_property,
        version=selection.version,
        version_property=selection.version_property,
        version_rule=selection.rule,
        version_refs={
            "self": {
                "id": selection.id,
                "version": selection.version,
                "version_property": selection.version_property,
                "spec_version": selection.spec_version,
                "rule": selection.rule,
            }
        },
        category_sets=_category_map(restriction.category_sets),
        allowed_categories=sorted(
            {
                category
                for _source, categories in restriction.category_sets
                for category in categories
            }
        ),
        reasons=_dedupe_strings(reasons),
        blocked_by=blocked_by,
        warnings=_dedupe_strings(warnings),
        extension_notes=_extension_notes(restriction),
        case_refs=list(restriction.case_refs),
        version_note=version_note,
        obj=obj,
    )
    item.permit = _make_permit(item, generated_at)
    return item, warnings


def _evaluate_relationship(
    selection: _Selection,
    restriction: _Restriction,
    source_selection: Optional[_Selection],
    target_selection: Optional[_Selection],
    object_by_id: Mapping[str, DeliveryItem],
    receiving_categories: frozenset[str],
    at: dt.datetime,
    at_iso: str,
    generated_at: str,
    policy: DeliveryPolicy,
    *,
    source_declared: Any = None,
    target_declared: Any = None,
) -> tuple[DeliveryItem, list[str]]:
    reasons: list[str] = []
    warnings = list(restriction.warnings)
    blocked_by: list[str] = []
    rel = selection.obj

    source_ref = str(rel.get("source_ref")) if rel is not None else None
    target_ref = str(rel.get("target_ref")) if rel is not None else None
    direction = (
        f"{source_ref}->{target_ref}" if source_ref and target_ref else None
    )

    if selection.error:
        reasons.append(selection.error)
    if rel is not None and _is_revoked(rel):
        reasons.append("relationship is revoked")
    if rel is not None and not source_ref:
        reasons.append("relationship has no source_ref")
    if rel is not None and not target_ref:
        reasons.append("relationship has no target_ref")
    reasons.extend(restriction.reasons)
    reasons.extend(
        _category_misses(restriction.category_sets, receiving_categories)
    )

    if restriction.release_at is not None:
        if policy.release_time_inclusive:
            still_embargoed = at < restriction.release_at
        else:
            still_embargoed = at <= restriction.release_at
        if still_embargoed:
            reasons.append(
                _embargo_reason(restriction.release_at, restriction.release_at_property)
            )

    source_item = object_by_id.get(source_ref) if source_ref else None
    target_item = object_by_id.get(target_ref) if target_ref else None
    if source_ref and source_item is None:
        reasons.append(f"source endpoint {source_ref} is not present")
        blocked_by.append(source_ref)
    if target_ref and target_item is None:
        reasons.append(f"target endpoint {target_ref} is not present")
        blocked_by.append(target_ref)

    if policy.require_endpoints:
        if source_item is not None and not source_item.allowed:
            reasons.append(f"source endpoint {source_ref} is not released")
            blocked_by.append(source_ref)
        if target_item is not None and not target_item.allowed:
            reasons.append(f"target endpoint {target_ref} is not released")
            blocked_by.append(target_ref)

    endpoint_times: list[dt.datetime] = []
    for endpoint in (source_item, target_item):
        if endpoint is None:
            continue
        endpoint_dt = _parse_stored_time(endpoint.release_at)
        if endpoint_dt is not None:
            endpoint_times.append(endpoint_dt)
    endpoint_release_at = max(endpoint_times) if endpoint_times else None
    endpoint_public_at = endpoint_release_at or _MIN_TIME
    both_endpoints_public = bool(
        source_item is not None
        and target_item is not None
        and source_item.allowed
        and target_item.allowed
    )

    outlasts_endpoints = bool(
        both_endpoints_public
        and restriction.release_at is not None
        and restriction.release_at > endpoint_public_at
    )
    if outlasts_endpoints and reasons:
        endpoint_text = (
            _iso(endpoint_release_at)
            if endpoint_release_at is not None
            else "endpoints are already public"
        )
        reasons.append(
            "relationship release outlasts both endpoints "
            f"(relationship {_iso(restriction.release_at)}, "
            f"{endpoint_text}); publication remains blocked"
        )

    allowed = not reasons
    status = "released" if allowed else "blocked"
    still_blocks_publication = bool(not allowed and outlasts_endpoints)
    source_spec = source_selection.spec_version if source_selection else None
    target_spec = target_selection.spec_version if target_selection else None
    rel_spec = selection.spec_version
    cross_version = bool(
        (source_spec and source_spec != rel_spec)
        or (target_spec and target_spec != rel_spec)
        or (source_spec and target_spec and source_spec != target_spec)
    )
    version_note = _relationship_version_note(
        selection,
        source_selection,
        target_selection,
        source_declared,
        target_declared,
        cross_version,
        at_iso,
    )

    item = DeliveryItem(
        id=selection.id,
        kind="relationship",
        type=selection.type,
        spec_version=selection.spec_version,
        status=status,
        allowed=allowed,
        revision=1,
        updated_at=generated_at,
        release_at=_optional_iso(restriction.release_at),
        embargo_until=_optional_iso(restriction.release_at),
        release_at_property=restriction.release_at_property,
        version=selection.version,
        version_property=selection.version_property,
        version_rule=selection.rule,
        source_ref=source_ref,
        target_ref=target_ref,
        origin_ref=source_ref,
        destination_ref=target_ref,
        direction=direction,
        source_version=(
            source_selection.version if source_selection else None
        ),
        target_version=(
            target_selection.version if target_selection else None
        ),
        source_version_used=(
            source_selection.version if source_selection else None
        ),
        target_version_used=(
            target_selection.version if target_selection else None
        ),
        source_version_declared=(
            str(source_declared) if source_declared is not None else None
        ),
        target_version_declared=(
            str(target_declared) if target_declared is not None else None
        ),
        source_spec_version=source_spec,
        target_spec_version=target_spec,
        category_sets=_category_map(restriction.category_sets),
        allowed_categories=sorted(
            {
                category
                for _source, categories in restriction.category_sets
                for category in categories
            }
        ),
        version_refs={
            "source": {
                "id": source_ref,
                "version": (
                    source_selection.version if source_selection else None
                ),
                "version_property": (
                    source_selection.version_property
                    if source_selection
                    else None
                ),
                "spec_version": source_spec,
                "declared": (
                    str(source_declared)
                    if source_declared is not None
                    else None
                ),
            },
            "target": {
                "id": target_ref,
                "version": (
                    target_selection.version if target_selection else None
                ),
                "version_property": (
                    target_selection.version_property
                    if target_selection
                    else None
                ),
                "spec_version": target_spec,
                "declared": (
                    str(target_declared)
                    if target_declared is not None
                    else None
                ),
            },
        },
        cross_version_reference=cross_version,
        outlasts_endpoints=outlasts_endpoints,
        endpoint_release_at=_optional_iso(endpoint_release_at),
        still_blocks_publication=still_blocks_publication,
        reasons=_dedupe_strings(reasons),
        blocked_by=sorted(set(blocked_by)),
        warnings=_dedupe_strings(warnings),
        extension_notes=_extension_notes(restriction),
        case_refs=list(restriction.case_refs),
        version_note=version_note,
        obj=rel,
    )
    item.permit = _make_permit(item, generated_at)
    return item, warnings


def _make_permit(item: DeliveryItem, generated_at: str) -> ReleasePermit:
    if item.allowed:
        reason = "release permitted"
    elif item.reasons:
        reason = "; ".join(item.reasons)
    else:
        reason = "release denied"
    return ReleasePermit(
        item_id=item.id,
        kind=item.kind,
        item_type=item.type,
        status="granted" if item.allowed else "denied",
        allowed=item.allowed,
        blocked=not item.allowed,
        reason=reason,
        blocking_reasons=tuple(item.reasons),
        evaluated_at=generated_at,
        release_at=item.release_at,
        embargo_until=item.embargo_until,
        source_ref=item.source_ref,
        target_ref=item.target_ref,
        direction=item.direction,
        source_version=item.source_version,
        target_version=item.target_version,
        source_version_declared=item.source_version_declared,
        target_version_declared=item.target_version_declared,
        source_spec_version=item.source_spec_version,
        target_spec_version=item.target_spec_version,
        version_refs=copy.deepcopy(item.version_refs),
        category_sets=copy.deepcopy(item.category_sets),
        allowed_categories=list(item.allowed_categories),
        case_refs=tuple(item.case_refs),
        outlasts_endpoints=item.outlasts_endpoints,
        endpoint_release_at=item.endpoint_release_at,
        still_blocks_publication=item.still_blocks_publication,
    )


def _permit_with_evaluated_at(
    permit: Optional[ReleasePermit], evaluated_at: str
) -> Optional[ReleasePermit]:
    if permit is None:
        return None
    data = permit.to_dict()
    for derived_key in (
        "effect",
        "granted",
        "denied",
        "decision",
        "publication_status",
        "release_status",
        "still_blocked",
    ):
        data.pop(derived_key, None)
    data["evaluated_at"] = evaluated_at
    return ReleasePermit(
        **{
            key: tuple(value)
            if key in {"blocking_reasons", "case_refs"}
            else value
            for key, value in data.items()
        }
    )


def _same_decision(old: DeliveryItem, new: DeliveryItem) -> bool:
    old_data = old.to_dict()
    new_data = new.to_dict()
    for key in ("revision", "updated_at"):
        old_data.pop(key, None)
        new_data.pop(key, None)
    old_permit = old_data.get("permit")
    new_permit = new_data.get("permit")
    if old_permit:
        old_permit.pop("evaluated_at", None)
    if new_permit:
        new_permit.pop("evaluated_at", None)
    return old_data == new_data


def _select_version(
    candidates: list[Any],
    obj_id: str,
    at: dt.datetime,
    *,
    pin: Any = None,
    strict_pin: bool = False,
) -> _Selection:
    if isinstance(pin, Mapping):
        pin = _first_not_none(
            pin.get("version"),
            pin.get("modified"),
            pin.get("created"),
            pin.get("spec_version"),
        )
    if pin is False or pin == 0:
        pin = None
    if isinstance(pin, str) and (
        not pin.strip() or pin.strip().lower() in {"latest", "*", "any"}
    ):
        pin = None

    if not candidates:
        return _Selection(
            obj=None,
            id=obj_id,
            type="unknown",
            spec_version="unknown",
            version=None,
            version_property=None,
            version_dt=None,
            rule="none",
            pin=None,
            error="no versions supplied",
            candidates=0,
        )

    metas: list[tuple[Any, Optional[dt.datetime], Optional[str], str]] = []
    errors: list[str] = []
    for obj in candidates:
        dt_value, prop, err = _object_version_time(obj)
        if err:
            errors.append(err)
            continue
        metas.append((obj, dt_value, prop, _spec_version(obj)))
    if not metas:
        first = candidates[0]
        return _Selection(
            obj=None,
            id=obj_id,
            type=str(first.get("type", "unknown")),
            spec_version=_spec_version(first),
            version=None,
            version_property=None,
            version_dt=None,
            rule="none",
            pin=str(pin) if pin is not None else None,
            error="; ".join(errors) or "no usable version",
            candidates=len(candidates),
        )

    pin_note: Optional[str] = None
    selected_pool = metas
    rule = "latest_at_or_before_delivery"
    if pin is not None:
        pin_text = str(pin)
        if pin_text in {"2.0", "2.1"}:
            pinned_pool = [meta for meta in metas if meta[3] == pin_text]
            if pinned_pool:
                selected_pool = pinned_pool
                rule = f"pinned_spec_version:{pin_text}"
            else:
                selected_pool = []
        else:
            pinned_pool = [
                meta
                for meta in metas
                if _version_matches(meta[0], meta[1], meta[2], pin_text)
            ]
            if pinned_pool:
                selected_pool = pinned_pool
                rule = f"pinned_version:{pin_text}"
            else:
                selected_pool = []

    if not selected_pool:
        first = candidates[0]
        error = (
            f"declared/pinned version {pin!r} not found"
            if pin is not None
            else "no version available at delivery time"
        )
        if pin is not None and not strict_pin:
            pin_note = error + "; using latest available version"
            selected_pool = metas
            rule = "latest_at_or_before_delivery"
        else:
            return _Selection(
                obj=None,
                id=obj_id,
                type=str(first.get("type", "unknown")),
                spec_version=_spec_version(first),
                version=None,
                version_property=None,
                version_dt=None,
                rule=rule,
                pin=str(pin),
                error=error,
                candidates=len(candidates),
            )

    eligible = [
        meta
        for meta in selected_pool
        if meta[1] is None or meta[1] <= at
    ]
    if not eligible:
        first = candidates[0]
        earliest = min(
            (meta[1] for meta in selected_pool if meta[1] is not None),
            default=None,
        )
        return _Selection(
            obj=None,
            id=obj_id,
            type=str(first.get("type", "unknown")),
            spec_version=_spec_version(first),
            version=None,
            version_property=None,
            version_dt=earliest,
            rule=rule,
            pin=str(pin) if pin is not None else None,
            error=(
                "no version at or before delivery time"
                + (f" (earliest is {_iso(earliest)})" if earliest else "")
            ),
            candidates=len(candidates),
        )

    # Stable tie-break when 2.0's millisecond precision produces equal
    # timestamps, or when a pin selects more than one candidate.
    selected = max(
        eligible,
        key=lambda meta: (
            meta[1] or _MIN_TIME,
            _canonical(meta[0]),
        ),
    )
    obj, version_dt, version_prop, spec_version = selected
    version = None
    if version_dt is not None:
        version = _iso(version_dt)
    elif version_prop is None:
        # An unversioned object (custom/auxiliary) is still usable.
        version = None
    return _Selection(
        obj=obj,
        id=obj_id,
        type=str(obj.get("type", "unknown")),
        spec_version=spec_version,
        version=version,
        version_property=version_prop,
        version_dt=version_dt,
        rule=rule,
        pin=str(pin) if pin is not None else None,
        warning=pin_note,
        candidates=len(candidates),
    )


def _build_case_policies(
    object_selections: Mapping[str, _Selection],
    case_embargoes: Mapping[str, Any],
    at: dt.datetime,
    policy: Optional[DeliveryPolicy] = None,
    referenced_case_ids: Optional[Iterable[str]] = None,
) -> dict[str, _Restriction]:
    policies: dict[str, _Restriction] = {}
    referenced_case_ids = set(referenced_case_ids or ())
    for case_id, selection in object_selections.items():
        if selection.obj is None:
            continue
        if case_id not in referenced_case_ids and not _looks_like_case(selection.obj):
            continue
        restriction = _restrictions_for(
            selection.obj,
            policy or DeliveryPolicy(),
            {},
            {},
            None,
        )
        if restriction.release_at is not None or restriction.category_sets:
            policies[case_id] = restriction

    for case_id, value in case_embargoes.items():
        key = str(case_id)
        restriction = policies.setdefault(key, _Restriction())
        until, cats, reason = _parse_case_embargo_value(value)
        if until is not None:
            restriction.times.append((until, f"case embargo {key}"))
            if restriction.release_at is None or until > restriction.release_at:
                restriction.release_at = until
                restriction.release_at_property = f"case embargo {key}"
        if cats:
            restriction.category_sets.append((f"case:{key}", frozenset(cats)))
        if reason:
            restriction.reasons.append(reason)
    return policies


def _restrictions_for(
    obj: Any,
    policy: DeliveryPolicy,
    marking_index: Mapping[str, _Selection],
    case_policies: Mapping[str, _Restriction],
    override: Optional[Mapping[str, Any]] = None,
) -> _Restriction:
    restriction = _Restriction()
    if obj is None:
        if override:
            _apply_override(restriction, override)
        return restriction

    _collect_time_and_status(obj, policy, restriction)
    own_category_values: set[str] = set()
    for category_prop in policy.category_properties:
        own_category_values.update(
            _normalise_categories(obj.get(category_prop))
        )
    own_categories = frozenset(own_category_values)
    if own_categories:
        restriction.category_sets.append(
            ("object-category", own_categories)
        )

    for policy_prop in ("x_release_policy", "x_embargo"):
        policy_value = obj.get(policy_prop)
        if not isinstance(policy_value, Mapping):
            continue
        nested_categories = frozenset(
            _normalise_categories(
                _first_not_none(
                    policy_value.get("categories"),
                    policy_value.get("release_categories"),
                    policy_value.get("audience"),
                    policy_value.get("audiences"),
                )
            )
        )
        if nested_categories:
            restriction.category_sets.append(
                (policy_prop, nested_categories)
            )

    for marking_id in _reference_list(obj.get("object_marking_refs")):
        selection = marking_index.get(marking_id)
        if selection is None or selection.obj is None:
            continue
        marking = selection.obj
        marking_restriction = _Restriction()
        _collect_time_and_status(marking, policy, marking_restriction)
        if marking_restriction.times:
            marking_release_at, marking_release_prop = max(
                marking_restriction.times, key=lambda item: item[0]
            )
            marking_restriction.release_at = marking_release_at
            marking_restriction.release_at_property = marking_release_prop
        if marking_restriction.release_at is not None:
            restriction.times.append(
                (
                    marking_restriction.release_at,
                    f"marking {marking_id}",
                )
            )
        marking_category_values: set[str] = set()
        for category_prop in policy.category_properties:
            marking_category_values.update(
                _normalise_categories(marking.get(category_prop))
            )
        marking_categories = frozenset(marking_category_values)
        if marking_categories:
            restriction.category_sets.append(
                (f"marking:{marking_id}", marking_categories)
            )
        restriction.reasons.extend(marking_restriction.reasons)

    case_mapping = _first_property_value(
        obj,
        ("x_case_embargoes", "case_embargoes", "x_case_release_times"),
    )
    if isinstance(case_mapping, Mapping):
        for case_id, case_value in case_mapping.items():
            case_id = str(case_id)
            if case_id not in restriction.case_refs:
                restriction.case_refs.append(case_id)
            until, cats, reason = _parse_case_embargo_value(case_value)
            if until is not None:
                restriction.times.append(
                    (until, f"case embargo {case_id}")
                )
            if cats:
                restriction.category_sets.append(
                    (f"case:{case_id}", frozenset(cats))
                )
            if reason:
                restriction.reasons.append(reason)

    case_ids: list[str] = list(restriction.case_refs)
    for prop in policy.case_properties:
        if prop in obj and obj.get(prop) is not None:
            for case_id in _reference_list(obj.get(prop)):
                case_id = str(case_id)
                if case_id not in case_ids:
                    case_ids.append(case_id)
    restriction.case_refs = list(case_ids)

    for case_id in case_ids:
        case_policy = case_policies.get(case_id)
        if case_policy is None:
            message = f"restricted case {case_id} has no embargo policy"
            restriction.warnings.append(message)
            if policy.require_case_clearance:
                restriction.reasons.append(message + "; release denied")
            continue
        if case_policy.release_at is not None:
            restriction.times.append(
                (
                    case_policy.release_at,
                    f"restricted case {case_id}",
                )
            )
        for source, cats in case_policy.category_sets:
            restriction.category_sets.append(
                (f"case:{case_id}", frozenset(cats))
            )
        restriction.reasons.extend(case_policy.reasons)

    if override:
        _apply_override(restriction, override)

    if restriction.times:
        release_at, prop = max(restriction.times, key=lambda item: item[0])
        restriction.release_at = release_at
        restriction.release_at_property = prop
    return restriction


def _collect_time_and_status(
    obj: Any,
    policy: DeliveryPolicy,
    restriction: _Restriction,
) -> None:
    for prop in policy.embargo_properties:
        if prop not in obj:
            continue
        value = obj.get(prop)
        if value is None or value == "":
            continue
        if isinstance(value, (list, tuple, set, frozenset)) and not value:
            continue
        if isinstance(value, Mapping) and not value:
            continue
        parsed_values = _timestamp_values_from_property(value)
        if not parsed_values:
            restriction.reasons.append(
                f"invalid release time in {prop}: {value!r}"
            )
            continue
        for parsed in parsed_values:
            restriction.times.append((parsed, prop))

    status = _first_property_value(
        obj,
        (
            "x_release_status",
            "x_declassification_status",
            "x_publication_status",
            "x_release_restriction",
            "x_classification",
            "release_status",
        ),
    )
    if status is not None:
        status_text = str(status).strip().lower()
        if status_text in _BLOCKED_RELEASE_STATUSES:
            restriction.reasons.append(f"release status is {status_text}")
        elif status_text not in _RELEASED_RELEASE_STATUSES:
            restriction.warnings.append(
                f"unrecognised release status {status_text!r}"
            )

    for prop in (
        "x_releasable",
        "x_shareable",
        "x_public",
        "x_is_public",
        "x_declassified",
    ):
        if prop not in obj:
            continue
        value = obj.get(prop)
        if _as_bool(value) is False:
            restriction.reasons.append(f"{prop} is false")

    for prop in (
        "x_embargoed",
        "x_restricted",
        "x_classified",
        "x_withheld",
    ):
        if prop in obj and _as_bool(obj.get(prop)) is True:
            restriction.reasons.append(f"{prop} is true")


def _apply_override(
    restriction: _Restriction, override: Mapping[str, Any]
) -> None:
    until = override.get("until")
    if until is None:
        return
    parsed = _to_utc(until)
    restriction.times.append((parsed, "temporary embargo extension"))
    note = f"temporary embargo extension until {_iso(parsed)}"
    reason = override.get("reason")
    if reason:
        note += f": {reason}"
    restriction.warnings.append(note)


def _extension_notes(restriction: _Restriction) -> list[str]:
    return [
        warning
        for warning in restriction.warnings
        if warning.startswith("temporary embargo extension")
    ]


def _category_map(
    category_sets: Iterable[tuple[str, frozenset[str]]],
) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for source, categories in category_sets:
        result.setdefault(source, []).extend(sorted(categories))
    return {source: sorted(set(values)) for source, values in result.items()}


def _category_misses(
    category_sets: Iterable[tuple[str, frozenset[str]]],
    receiving_categories: frozenset[str],
) -> list[str]:
    if "*" in receiving_categories:
        return []
    reasons: list[str] = []
    for source, allowed in category_sets:
        if not allowed or "*" in allowed:
            continue
        if not receiving_categories.intersection(allowed):
            reasons.append(
                f"receiving categories {sorted(receiving_categories)} "
                f"not allowed by {source} {sorted(allowed)}"
            )
    return reasons


def _find_cycles(relationship_objects: Mapping[str, Any]) -> list[dict[str, Any]]:
    adjacency: dict[str, list[tuple[str, str]]] = defaultdict(list)
    nodes: set[str] = set()
    for rel_id, rel in relationship_objects.items():
        if rel is None:
            continue
        source = rel.get("source_ref")
        target = rel.get("target_ref")
        if not source or not target:
            continue
        source = str(source)
        target = str(target)
        nodes.add(source)
        nodes.add(target)
        adjacency[source].append((target, rel_id))
    for source in adjacency:
        adjacency[source].sort(key=lambda item: (item[0], item[1]))

    index = 0
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    stack: list[str] = []
    on_stack: set[str] = set()
    components: list[list[str]] = []

    def strongconnect(node: str) -> None:
        nonlocal index
        indices[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)

        for target, _rel_id in adjacency.get(node, []):
            if target not in indices:
                strongconnect(target)
                lowlinks[node] = min(lowlinks[node], lowlinks[target])
            elif target in on_stack:
                lowlinks[node] = min(lowlinks[node], indices[target])

        if lowlinks[node] == indices[node]:
            component: list[str] = []
            while True:
                member = stack.pop()
                on_stack.remove(member)
                component.append(member)
                if member == node:
                    break
            components.append(sorted(component))

    for node in sorted(nodes):
        if node not in indices:
            strongconnect(node)

    cycles: list[dict[str, Any]] = []
    for component in sorted(components):
        component_set = set(component)
        self_loops = [
            (source, target, rel_id)
            for source in component
            for target, rel_id in adjacency.get(source, [])
            if target == source
        ]
        if len(component) == 1 and not self_loops:
            continue
        start = component[0]
        path, edges = _representative_cycle(
            start, component_set, adjacency, self_loops
        )
        if not path:
            continue
        members = sorted(
            {
                rel_id
                for source in component
                for target, rel_id in adjacency.get(source, [])
                if target in component_set
            }
        )
        cycles.append(
            {
                "id": len(cycles) + 1,
                "path": path,
                "relationship_path": [rel_id for _s, _t, rel_id in edges],
                "start": path[0],
                "end": path[-1],
                "direction": "source_ref->target_ref",
                "component": list(component),
                "edges": [
                    {
                        "relationship_id": rel_id,
                        "source_ref": source,
                        "target_ref": target,
                        "next_ref": target,
                        "destination_ref": target,
                        "direction": f"{source}->{target}",
                    }
                    for source, target, rel_id in edges
                ],
                "members": members,
                "released": None,
            }
        )
    return cycles


def _representative_cycle(
    start: str,
    component: set[str],
    adjacency: Mapping[str, list[tuple[str, str]]],
    self_loops: list[tuple[str, str, str]],
) -> tuple[list[str], list[tuple[str, str, str]]]:
    if self_loops and len(component) == 1:
        source, target, rel_id = sorted(self_loops)[0]
        return [source, target], [(source, target, rel_id)]

    path = [start]
    path_set = {start}
    edges: list[tuple[str, str, str]] = []

    def walk(node: str) -> bool:
        for target, rel_id in adjacency.get(node, []):
            if target not in component:
                continue
            if target == node and len(component) > 1:
                continue
            if target == start:
                edges.append((node, target, rel_id))
                path.append(target)
                return True
            if target in path_set:
                continue
            path.append(target)
            path_set.add(target)
            edges.append((node, target, rel_id))
            if walk(target):
                return True
            edges.pop()
            path.pop()
            path_set.remove(target)
        return False

    if walk(start):
        return path, edges
    return [], []


def _object_version_time(
    obj: Any,
) -> tuple[Optional[dt.datetime], Optional[str], Optional[str]]:
    for prop in ("modified", "created"):
        if prop not in obj:
            continue
        value = obj.get(prop)
        if value is None:
            continue
        try:
            return _to_utc(value), prop, None
        except (TypeError, ValueError) as exc:
            return None, prop, f"invalid {prop} timestamp {value!r}: {exc}"
    return None, None, None


def _version_matches(
    obj: Any,
    version_dt: Optional[dt.datetime],
    version_property: Optional[str],
    pin: str,
) -> bool:
    if pin in {"2.0", "2.1"}:
        return _spec_version(obj) == pin
    if version_dt is not None:
        if _iso(version_dt) == pin:
            return True
        try:
            if _to_utc(pin) == version_dt:
                return True
        except (TypeError, ValueError):
            pass
    if version_property:
        raw = obj.get(version_property)
        if str(raw) == pin:
            return True
    return False


def _object_version_note(selection: _Selection, at_iso: str) -> str:
    if selection.obj is None:
        return f"{selection.id}: no selected version at {at_iso}"
    if selection.version is None:
        return (
            f"{selection.id}: unversioned object used "
            f"(spec {selection.spec_version}) at {at_iso}"
        )
    return (
        f"{selection.id}: used version {selection.version} "
        f"from {selection.version_property} "
        f"({selection.rule}) at {at_iso} (spec {selection.spec_version})"
    )


def _relationship_version_note(
    selection: _Selection,
    source: Optional[_Selection],
    target: Optional[_Selection],
    source_declared: Any,
    target_declared: Any,
    cross_version: bool,
    at_iso: str,
) -> str:
    def describe(label: str, endpoint: Optional[_Selection], declared: Any) -> str:
        if endpoint is None:
            return f"{label}=<missing>"
        version = endpoint.version or "unversioned"
        text = (
            f"{label}={endpoint.id}@{version} "
            f"({endpoint.version_property or 'none'}, "
            f"spec {endpoint.spec_version})"
        )
        if declared is not None:
            text += f" declared={declared}"
        return text

    note = (
        f"{selection.id}: {describe('source', source, source_declared)}; "
        f"{describe('target', target, target_declared)}; "
        f"at {at_iso}"
    )
    if cross_version:
        note += "; cross-version reference"
    return note


def _parse_case_embargo_value(
    value: Any,
) -> tuple[Optional[dt.datetime], frozenset[str], Optional[str]]:
    until = None
    cats: frozenset[str] = frozenset()
    reason = None
    if isinstance(value, Mapping):
        raw_until = _first_not_none(
            value.get("until"),
            value.get("release_at"),
            value.get("declassified_at"),
            value.get("public_at"),
            value.get("expires_at"),
        )
        if raw_until is not None:
            until = _to_utc(raw_until)
        cats = frozenset(
            _normalise_categories(
                _first_not_none(
                    value.get("categories"),
                    value.get("receiving_categories"),
                    value.get("release_categories"),
                )
            )
        )
        reason = value.get("reason")
    elif value is not None and value != "":
        until = _to_utc(value)
    return until, cats, reason


def _looks_like_case(obj: Any) -> bool:
    obj_type = str(obj.get("type", "")).lower()
    return (
        "case" in obj_type
        or bool(_first_property_value(obj, CASE_PROPERTIES))
        or bool(obj.get("x_case"))
        or bool(obj.get("case_id"))
    )


def _is_relationship(obj: Any) -> bool:
    obj_type = str(obj.get("type", "")).lower()
    return obj_type == "relationship" or (
        obj.get("source_ref") is not None and obj.get("target_ref") is not None
    )


def _is_revoked(obj: Any) -> bool:
    return _as_bool(obj.get("revoked")) is True


def _spec_version(obj: Any) -> str:
    value = obj.get("spec_version")
    if value:
        return str(value)
    module = type(obj).__module__
    if ".v20." in module:
        return "2.0"
    if ".v21." in module:
        return "2.1"
    # STIX 2.0 objects do not carry spec_version.
    return "2.0"


def _object_payload(obj: Any) -> Any:
    if obj is None:
        return None
    if isinstance(obj, Mapping) and not hasattr(obj, "serialize"):
        return _plain(obj)
    try:
        return json.loads(obj.serialize())
    except (AttributeError, TypeError, ValueError):
        return _plain(obj)


def _plain(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dt.datetime):
        return _iso(value)
    if isinstance(value, dt.date):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_plain(item) for item in value]
    if hasattr(value, "serialize"):
        try:
            return json.loads(value.serialize())
        except (TypeError, ValueError):
            pass
    return str(value)


def _canonical(obj: Any) -> str:
    return json.dumps(
        _object_payload(obj), sort_keys=True, ensure_ascii=False, default=str
    )


def _timestamp_values_from_property(value: Any) -> list[dt.datetime]:
    if isinstance(value, Mapping):
        found: list[dt.datetime] = []
        for key in (
            "until",
            "release_at",
            "released_at",
            "declassified_at",
            "declassify_at",
            "declassification_date",
            "public_at",
            "publication_date",
            "expires_at",
            "available_at",
            "date",
            "at",
        ):
            if key in value and value[key] is not None:
                try:
                    found.append(_to_utc(value[key]))
                except (TypeError, ValueError):
                    continue
        return found
    if isinstance(value, (list, tuple, set, frozenset)):
        found = []
        for item in value:
            try:
                found.append(_to_utc(item))
            except (TypeError, ValueError):
                continue
        return found
    try:
        return [_to_utc(value)]
    except (TypeError, ValueError):
        return []


def _reference_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        # Some backends use {"case_refs": [...]} or {"id": "..."}.
        for key in ("refs", "ids", "cases", "id"):
            if key in value:
                return _reference_list(value[key])
        return []
    try:
        return [str(item) for item in value]
    except TypeError:
        return [str(value)]


def _first_property_value(obj: Any, properties: Iterable[str]) -> Any:
    if obj is None:
        return None
    for prop in properties:
        if prop in obj and obj.get(prop) is not None:
            return obj.get(prop)
    return None


def _normalise_categories(value: Any) -> frozenset[str]:
    if value is None:
        return frozenset()
    if isinstance(value, Mapping):
        for key in (
            "categories",
            "include",
            "values",
            "names",
            "ids",
            "allowed",
        ):
            if key in value:
                return _normalise_categories(value[key])
        return frozenset(
            str(key)
            for key, enabled in value.items()
            if _as_bool(enabled) is not False
        )
    if isinstance(value, str):
        parts = [part.strip() for part in value.split(",")]
        return frozenset(part for part in parts if part)
    try:
        return frozenset(
            str(item).strip() for item in value if str(item).strip()
        )
    except TypeError:
        return frozenset({str(value).strip()})


def _as_bool(value: Any) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        if value == 1:
            return True
        if value == 0:
            return False
        return None
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "y", "on"}:
            return True
        if lowered in {"0", "false", "no", "n", "off"}:
            return False
    return None


def _as_object_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if hasattr(value, "read") and not isinstance(value, (str, bytes)):
        value = json.load(value)
    if isinstance(value, (str, bytes)):
        try:
            value = json.loads(value)
        except (TypeError, ValueError) as exc:
            raise DeliveryPreviewError(
                "objects must be STIX objects, bundles, or JSON"
            ) from exc
    if isinstance(value, Mapping):
        if value.get("type") == "bundle":
            return list(value.get("objects") or [])
        if (
            "type" not in value
            and value
            and all(isinstance(item, Mapping) for item in value.values())
        ):
            return list(value.values())
        return [value]
    if hasattr(value, "objects") and getattr(value, "type", None) == "bundle":
        return list(value.objects)
    if hasattr(value, "query") and not isinstance(value, Mapping):
        try:
            return list(value.query())
        except TypeError:
            pass
    try:
        items = list(value)
    except TypeError:
        return [value]
    flattened: list[Any] = []
    for item in items:
        if isinstance(item, Mapping) and item.get("type") == "bundle":
            flattened.extend(item.get("objects") or [])
        else:
            flattened.append(item)
    return flattened


def _dedupe_objects(
    objects: Iterable[Any], warnings: list[str]
) -> list[Any]:
    seen: set[str] = set()
    result: list[Any] = []
    for obj in objects:
        if obj is None:
            continue
        if not isinstance(obj, Mapping):
            warnings.append(f"ignored non-STIX value {obj!r}")
            continue
        key = _canonical(obj)
        if key in seen:
            continue
        seen.add(key)
        result.append(obj)
    return result


def _obj_id(obj: Any) -> Optional[str]:
    value = obj.get("id")
    return str(value) if value is not None else None


def _normalise_ids(value: str | Iterable[str]) -> list[str]:
    if isinstance(value, str):
        return [value]
    return [str(item) for item in value]


def _dedupe_strings(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _first_not_none(*values: Any) -> Any:
    for value in values:
        if value is not None:
            return value
    return None


def _to_utc(value: Any) -> dt.datetime:
    if isinstance(value, dt.datetime):
        result = value
    elif isinstance(value, dt.date):
        result = dt.datetime.combine(
            value, dt.time(0, 0), tzinfo=dt.timezone.utc
        )
    elif isinstance(value, str):
        text = value.strip()
        try:
            result = dt.datetime.fromisoformat(
                text.replace("Z", "+00:00").replace("z", "+00:00")
            )
        except ValueError as exc:
            raise ValueError(f"invalid timestamp {value!r}") from exc
    else:
        raise TypeError(f"expected a timestamp, got {type(value).__name__}")
    if result.tzinfo is None:
        result = result.replace(tzinfo=dt.timezone.utc)
    else:
        result = result.astimezone(dt.timezone.utc)
    return result


def _iso(value: Any) -> str:
    return format_datetime(_to_utc(value))


def _optional_iso(value: Optional[Any]) -> Optional[str]:
    return _iso(value) if value is not None else None


def _parse_stored_time(value: Optional[str]) -> Optional[dt.datetime]:
    if value is None:
        return None
    try:
        return _to_utc(value)
    except (TypeError, ValueError):
        return None


def _embargo_reason(
    release_at: dt.datetime, release_property: Optional[str]
) -> str:
    source = f" from {release_property}" if release_property else ""
    return f"embargoed until {_iso(release_at)}{source}"


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
def _parse_key_value(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("expected KEY=VALUE")
    key, item = value.split("=", 1)
    return key, item


def _load_cli_input(path: Optional[str]) -> dict[str, Any]:
    if path:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
    else:
        payload = json.load(sys.stdin)
    if not isinstance(payload, dict):
        raise DeliveryPreviewError("CLI input must be a JSON object")
    return payload


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build an embargo-aware STIX delivery preview"
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="JSON request file (default: stdin); may be a bundle",
    )
    parser.add_argument("--categories", help="comma-separated receiving categories")
    parser.add_argument("--at", help="delivery time (ISO-8601)")
    parser.add_argument(
        "--transition",
        action="store_true",
        help="build before/after previews around an embargo time",
    )
    parser.add_argument(
        "--embargo-until",
        help="embargo lifting time for --transition",
    )
    parser.add_argument("--before", help="explicit before time")
    parser.add_argument("--after", help="explicit after time")
    parser.add_argument(
        "--case-embargo",
        action="append",
        default=[],
        type=_parse_key_value,
        metavar="CASE=TIMESTAMP",
    )
    parser.add_argument(
        "--version-override",
        action="append",
        default=[],
        type=_parse_key_value,
        metavar="ID=VERSION",
    )
    parser.add_argument(
        "--out",
        help="output file or directory (two files for --transition)",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="pretty-print JSON output",
    )
    args = parser.parse_args(argv)

    request = _load_cli_input(args.input)
    objects = request.get("objects", request)
    relationships = request.get("relationships")
    categories = args.categories or request.get("receiving_categories")
    at = args.at or request.get("at")
    case_embargoes = dict(request.get("case_embargoes") or {})
    case_embargoes.update(dict(args.case_embargo))
    version_overrides = dict(request.get("version_overrides") or {})
    version_overrides.update(dict(args.version_override))
    shared = {
        "objects": objects,
        "relationships": relationships,
        "receiving_categories": categories,
        "case_embargoes": case_embargoes,
        "version_overrides": version_overrides,
    }
    if request.get("policy") is not None:
        shared["policy"] = request["policy"]
    if request.get("generated_at") is not None:
        shared["generated_at"] = request["generated_at"]

    if args.transition:
        transition = preview_transition(
            embargo_until=args.embargo_until or request.get("embargo_until"),
            before=args.before or request.get("before"),
            after=args.after or request.get("after"),
            **shared,
        )
        if args.out:
            target = Path(args.out)
            if target.suffix.lower() == ".json":
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(
                    transition.serialize(pretty=True), encoding="utf-8"
                )
                transition.save(target.parent, stem=target.stem)
            else:
                transition.save(target)
        output = transition.serialize(pretty=args.pretty or True)
    else:
        preview = preview_delivery(at=at, **shared)
        if args.out:
            preview.save(args.out, pretty=args.pretty or True)
        output = preview.serialize(pretty=args.pretty or True)
    print(output)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
