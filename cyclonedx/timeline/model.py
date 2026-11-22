# This file is part of CycloneDX Python Library
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) OWASP Foundation. All Rights Reserved.

"""Data model for the offline CycloneDX timeline audit."""

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(frozen=True)
class TimeSpan:
    """The inclusive interval in which an evidence item is known to have occurred.

    ``start`` and ``end`` are microseconds since the Unix epoch, inclusive.
    ``None`` means that side of the interval is unknown.
    """

    start: Optional[int]
    end: Optional[int]
    precision: str
    raw: str = ''
    timezone: str = 'UTC'

    @property
    def bounded(self) -> bool:
        return self.start is not None and self.end is not None

    def to_json(self) -> dict[str, Any]:
        from .timeutil import format_microseconds

        return {
            'start': format_microseconds(self.start),
            'end': format_microseconds(self.end),
            'precision': self.precision,
            'raw': self.raw,
            'timezone': self.timezone,
        }


UNKNOWN_SPAN = TimeSpan(start=None, end=None, precision='unknown')


@dataclass
class Evidence:
    """A dated object extracted from one CycloneDX document."""

    id: str
    kind: str
    bom_id: str
    source: str
    span: TimeSpan
    label: str
    phase: Optional[str] = None
    lifecycle_name: Optional[str] = None
    description: Optional[str] = None
    component_ref: Optional[str] = None
    component_name: Optional[str] = None
    component_version: Optional[str] = None
    purl: Optional[str] = None
    location: Optional[str] = None
    occurrence_ref: Optional[str] = None
    property_name: Optional[str] = None
    time_source: str = 'unknown'
    details: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            'id': self.id,
            'kind': self.kind,
            'bomId': self.bom_id,
            'source': self.source,
            'label': self.label,
            'span': self.span.to_json(),
            'timeSource': self.time_source,
        }
        for key, value in (
            ('phase', self.phase),
            ('lifecycleName', self.lifecycle_name),
            ('description', self.description),
            ('componentRef', self.component_ref),
            ('componentName', self.component_name),
            ('componentVersion', self.component_version),
            ('purl', self.purl),
            ('location', self.location),
            ('occurrenceRef', self.occurrence_ref),
            ('propertyName', self.property_name),
        ):
            if value is not None:
                result[key] = value
        if self.details:
            result['details'] = self.details
        return result


@dataclass
class ConstraintEdge:
    """One resolved atomic ordering relation."""

    id: str
    constraint_id: str
    before: str
    after: str
    kind: str = 'strict_before'

    def to_json(self) -> dict[str, Any]:
        return {
            'id': self.id,
            'constraintId': self.constraint_id,
            'before': self.before,
            'after': self.after,
            'kind': self.kind,
        }


@dataclass
class OrderConstraint:
    """An ordering claim supplied by the caller (or inferred by a policy)."""

    id: str
    before_selector: str
    after_selector: str
    relation: str
    origin: str = 'caller'
    note: Optional[str] = None
    source: Optional[str] = None
    edges: list[ConstraintEdge] = field(default_factory=list)

    def to_json(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            'id': self.id,
            'origin': self.origin,
            'before': self.before_selector,
            'after': self.after_selector,
            'relation': self.relation,
            'edges': [edge.to_json() for edge in self.edges],
        }
        if self.note is not None:
            result['note'] = self.note
        if self.source is not None:
            result['source'] = self.source
        return result


@dataclass
class Conflict:
    """A minimal set of ordering claims that cannot hold simultaneously."""

    constraint_ids: list[str]
    edge_ids: list[str]
    evidence_ids: list[str]
    bom_ids: list[str]
    sources: list[str]
    constraints: list[dict[str, Any]]
    reason: str

    def to_json(self) -> dict[str, Any]:
        return {
            'constraintIds': self.constraint_ids,
            'edgeIds': self.edge_ids,
            'evidenceIds': self.evidence_ids,
            'bomIds': self.bom_ids,
            'sources': self.sources,
            'constraints': self.constraints,
            'reason': self.reason,
        }
