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


"""Data model for the offline risk-acceptance sign-off analysis.

These objects are plain analysis results. They intentionally do not extend the
CycloneDX serialization model: the encoding into BOM properties and external
references lives in :mod:`cyclonedx.riskacceptance.encoding`.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class SignOffStatus(str, Enum):
    """Verdict for a single risk-acceptance sign-off."""

    INDEPENDENTLY_SUPPORTED = 'independently_supported'
    """At least one attached piece of material independently backs the
    declared artifact and version of the sign-off."""

    EVIDENCE_INCOMPLETE = 'evidence_incomplete'
    """The reference chain never reaches independent material, but no cycle
    is involved -- evidence is simply still missing."""

    CIRCULAR_REFERENCE = 'circular_reference'
    """The sign-off is part of (or only reaches nodes within) a reference
    cycle that has no independent material attached."""


@dataclass(frozen=True)
class ArtifactCoordinates:
    """The declared identity of the artifact a sign-off or piece of evidence
    applies to.

    ``bom_ref`` is recorded for traceability but never used for matching: a
    component replacement can legitimately change the ``bom-ref`` while the
    declared ``group``/``name``/``version`` stay authoritative.
    """

    group: Optional[str]
    name: str
    version: Optional[str]
    bom_ref: Optional[str] = None

    def matches(self, other: 'ArtifactCoordinates') -> bool:
        """Whether two coordinate sets describe the same artifact release.

        Matching is deliberately strict on the declared version, because a
        risk acceptance for one release must not silently cover a replacement
        release.
        """
        return (
            (self.group or None) == (other.group or None)
            and self.name == other.name
            and (self.version or None) == (other.version or None)
        )


@dataclass(frozen=True)
class Evidence:
    """A piece of material offered as independent support."""

    url: str
    reference_type: str
    scope: Optional[ArtifactCoordinates]
    hashes: tuple[str, ...] = ()

    def covers(self, artifact: ArtifactCoordinates) -> bool:
        """Whether the evidence was explicitly scoped to ``artifact``.

        Material without an explicit artifact/version scope can never back a
        sign-off: after a component replacement unscoped material would be
        inherited by an unrelated release.
        """
        return self.scope is not None and self.scope.matches(artifact)


@dataclass
class SignOff:
    """One risk-acceptance sign-off as extracted from the BOM."""

    signoff_id: str
    owner: Optional[str]
    artifact: ArtifactCoordinates
    references: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)

    @property
    def has_independent_material(self) -> bool:
        return any(item.covers(self.artifact) for item in self.evidence)


@dataclass(frozen=True)
class SignOffEvaluation:
    """Classification result for one sign-off."""

    signoff_id: str
    status: SignOffStatus
    supporting_evidence: tuple[str, ...]
    chain: tuple[str, ...]
    reason: str
