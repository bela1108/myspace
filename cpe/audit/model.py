#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""
Input models for advisory withdrawal impact auditing.

The models deliberately keep evidence references next to every fact that can
influence the audit result.  A report can therefore show which inventory,
replacement, and scope records support each conclusion.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional


def parse_timestamp(value):
    """Parse an ISO-8601 timestamp into an aware UTC datetime."""

    if value is None:
        return None
    if isinstance(value, datetime):
        result = value
    else:
        text = str(value).strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        result = datetime.fromisoformat(text)
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result.astimezone(timezone.utc)


def format_timestamp(value):
    """Render an aware timestamp as a stable UTC ISO-8601 string."""

    if value is None:
        return None
    return (value.astimezone(timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"))


@dataclass(frozen=True)
class TimeInterval:
    """A closed time interval; an omitted end means an open interval."""

    start: datetime
    end: Optional[datetime] = None

    def __post_init__(self):
        object.__setattr__(self, "start", parse_timestamp(self.start))
        object.__setattr__(self, "end", parse_timestamp(self.end))
        if self.end is not None and self.end < self.start:
            raise ValueError("interval end precedes interval start")

    def contains(self, moment):
        moment = parse_timestamp(moment)
        if moment < self.start:
            return False
        return self.end is None or moment <= self.end

    def covers(self, other):
        """Return True when this interval fully covers ``other``."""

        if other is None:
            return False
        if self.start > other.start:
            return False
        if self.end is None:
            return True
        if other.end is None:
            return False
        return self.end >= other.end

    def label(self):
        end = format_timestamp(self.end) if self.end is not None else "open"
        return "{0} ~ {1}".format(format_timestamp(self.start), end)


@dataclass
class Advisory:
    """A withdrawn advisory and its CPE applicability expression."""

    advisory_id: str
    published_at: datetime
    withdrawn_at: Optional[datetime]
    expression: List[dict]
    title: str = ""
    source: str = ""

    def __post_init__(self):
        self.published_at = parse_timestamp(self.published_at)
        self.withdrawn_at = parse_timestamp(self.withdrawn_at)
        if isinstance(self.expression, str):
            text = self.expression.strip()
            if text.startswith("[") or text.startswith("{"):
                self.expression = json.loads(text)
        if isinstance(self.expression, dict):
            self.expression = [self.expression]
        if self.expression is None:
            self.expression = []
        if self.withdrawn_at is not None and self.withdrawn_at < self.published_at:
            raise ValueError("advisory withdrawn before publication")

    @property
    def applicability_interval(self):
        return TimeInterval(self.published_at, self.withdrawn_at)

    @classmethod
    def from_dict(cls, data):
        return cls(
            advisory_id=data["advisory_id"],
            title=data.get("title", ""),
            published_at=data["published_at"],
            withdrawn_at=data.get("withdrawn_at"),
            expression=data.get("expression", []),
            source=data.get("source", ""),
        )

    def to_dict(self):
        return {
            "advisory_id": self.advisory_id,
            "title": self.title,
            "source": self.source,
            "published_at": format_timestamp(self.published_at),
            "withdrawn_at": format_timestamp(self.withdrawn_at),
            "applicability_interval": {
                "start": format_timestamp(self.published_at),
                "end": format_timestamp(self.withdrawn_at),
            },
            "expression": self.expression,
        }


@dataclass
class FamilyCoverage:
    """
    Evidence that an asset family's inventory is complete.

    ``covered_from``/``covered_to`` state the period over which the evidence
    claims continuous inventory coverage.  A family may only be excluded when
    this period covers the advisory applicability interval.
    """

    family: str
    complete: bool
    evidence_ref: str
    asset_ids: List[str] = field(default_factory=list)
    covered_from: Optional[datetime] = None
    covered_to: Optional[datetime] = None
    source: str = ""

    def __post_init__(self):
        self.covered_from = parse_timestamp(self.covered_from)
        self.covered_to = parse_timestamp(self.covered_to)

    @classmethod
    def from_dict(cls, family, data):
        return cls(
            family=family,
            complete=bool(data.get("complete", False)),
            evidence_ref=data.get("evidence_ref", ""),
            asset_ids=list(data.get("asset_ids", [])),
            covered_from=data.get("covered_from"),
            covered_to=data.get("covered_to"),
            source=data.get("source", ""),
        )

    @property
    def coverage_interval(self):
        if self.covered_from is None and self.covered_to is None:
            return None
        return TimeInterval(self.covered_from or datetime.min.replace(tzinfo=timezone.utc),
                            self.covered_to)

    def covers(self, interval):
        coverage = self.coverage_interval
        return bool(self.complete and coverage is not None and coverage.covers(interval))

    def to_dict(self):
        return {
            "family": self.family,
            "complete": self.complete,
            "evidence_ref": self.evidence_ref,
            "asset_ids": list(self.asset_ids),
            "covered_from": format_timestamp(self.covered_from),
            "covered_to": format_timestamp(self.covered_to),
            "source": self.source,
        }


@dataclass
class InventoryScope:
    """The inventory scope explicitly approved by the audit caller."""

    approved_asset_ids: List[str]
    family_coverage: Dict[str, FamilyCoverage] = field(default_factory=dict)
    approved_by: str = ""
    approved_at: Optional[datetime] = None
    scope_ref: str = ""

    def __post_init__(self):
        self.approved_asset_ids = list(self.approved_asset_ids)
        self.approved_at = parse_timestamp(self.approved_at)
        converted = {}
        for family, coverage in self.family_coverage.items():
            if isinstance(coverage, dict):
                coverage = FamilyCoverage.from_dict(family, coverage)
            converted[family] = coverage
        self.family_coverage = converted

    def is_approved(self, asset_id):
        return asset_id in self.approved_asset_ids

    def coverage_for(self, family):
        return self.family_coverage.get(family)

    @classmethod
    def from_dict(cls, data):
        return cls(
            approved_asset_ids=data.get("approved_asset_ids", []),
            family_coverage=data.get("family_coverage", {}),
            approved_by=data.get("approved_by", ""),
            approved_at=data.get("approved_at"),
            scope_ref=data.get("scope_ref", ""),
        )

    def to_dict(self):
        return {
            "approved_by": self.approved_by,
            "approved_at": format_timestamp(self.approved_at),
            "scope_ref": self.scope_ref,
            "approved_asset_ids": list(self.approved_asset_ids),
            "family_coverage": {
                family: coverage.to_dict()
                for family, coverage in sorted(self.family_coverage.items())
            },
        }


@dataclass(frozen=True)
class ComponentRecord:
    """One installed component in an asset inventory record."""

    slot: str
    cpe: str
    evidence_ref: str = ""

    @classmethod
    def from_dict(cls, data):
        return cls(
            slot=data["slot"],
            cpe=data["cpe"],
            evidence_ref=data.get("evidence_ref", ""),
        )

    def to_dict(self):
        return {
            "slot": self.slot,
            "cpe": self.cpe,
            "evidence_ref": self.evidence_ref,
        }


@dataclass
class AssetSnapshot:
    """An observed asset state at a point in time."""

    asset_id: str
    family: str
    observed_at: datetime
    manifest_complete: bool
    components: List[ComponentRecord] = field(default_factory=list)
    evidence_ref: str = ""

    def __post_init__(self):
        self.observed_at = parse_timestamp(self.observed_at)
        converted = []
        for component in self.components:
            if isinstance(component, dict):
                component = ComponentRecord.from_dict(component)
            converted.append(component)
        self.components = converted

    def component_for_slot(self, slot):
        for component in self.components:
            if component.slot == slot:
                return component
        return None

    @classmethod
    def from_dict(cls, data, default_observed_at=None):
        return cls(
            asset_id=data["asset_id"],
            family=data.get("family", ""),
            observed_at=data.get("observed_at", default_observed_at),
            manifest_complete=bool(data.get("manifest_complete", False)),
            components=data.get("components", []),
            evidence_ref=data.get("evidence_ref", ""),
        )

    def to_dict(self):
        return {
            "asset_id": self.asset_id,
            "family": self.family,
            "observed_at": format_timestamp(self.observed_at),
            "manifest_complete": self.manifest_complete,
            "evidence_ref": self.evidence_ref,
            "components": [component.to_dict() for component in self.components],
        }


@dataclass
class InventorySnapshot:
    """A named set of asset records observed at one time."""

    snapshot_id: str
    observed_at: datetime
    assets: Dict[str, AssetSnapshot] = field(default_factory=dict)
    evidence_ref: str = ""

    def __post_init__(self):
        self.observed_at = parse_timestamp(self.observed_at)
        converted = {}
        for asset_id, asset in self.assets.items():
            if isinstance(asset, dict):
                asset = AssetSnapshot.from_dict(asset, self.observed_at)
            converted[asset_id] = asset
        self.assets = converted

    def get(self, asset_id):
        return self.assets.get(asset_id)

    @classmethod
    def from_dict(cls, data):
        observed_at = data["observed_at"]
        assets = {}
        for asset_data in data.get("assets", []):
            asset = AssetSnapshot.from_dict(asset_data, observed_at)
            assets[asset.asset_id] = asset
        return cls(
            snapshot_id=data["snapshot_id"],
            observed_at=observed_at,
            assets=assets,
            evidence_ref=data.get("evidence_ref", ""),
        )

    def to_dict(self):
        return {
            "snapshot_id": self.snapshot_id,
            "observed_at": format_timestamp(self.observed_at),
            "evidence_ref": self.evidence_ref,
            "assets": {
                asset_id: asset.to_dict()
                for asset_id, asset in sorted(self.assets.items())
            },
        }


@dataclass
class ReplacementEvidence:
    """Evidence that one component slot was replaced."""

    asset_id: str
    slot: str
    old_cpe: str
    new_cpe: str
    effective_at: datetime
    credential_ref: str
    verified: bool = False
    evidence_ref: str = ""
    source: str = ""

    def __post_init__(self):
        self.effective_at = parse_timestamp(self.effective_at)
        self.verified = bool(self.verified)

    @classmethod
    def from_dict(cls, data):
        return cls(
            asset_id=data["asset_id"],
            slot=data["slot"],
            old_cpe=data["old_cpe"],
            new_cpe=data["new_cpe"],
            effective_at=data["effective_at"],
            credential_ref=data.get("credential_ref", ""),
            verified=data.get("verified", False),
            evidence_ref=data.get("evidence_ref", ""),
            source=data.get("source", ""),
        )

    def to_dict(self):
        return {
            "asset_id": self.asset_id,
            "slot": self.slot,
            "old_cpe": self.old_cpe,
            "new_cpe": self.new_cpe,
            "effective_at": format_timestamp(self.effective_at),
            "credential_ref": self.credential_ref,
            "verified": self.verified,
            "evidence_ref": self.evidence_ref,
            "source": self.source,
        }
