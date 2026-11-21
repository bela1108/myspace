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


"""
Downgrade loss reporting.

When a :class:`~cyclonedx.model.bom.Bom` that was authored against a recent
CycloneDX schema version is serialized to an older schema version, some of the
modelled information cannot be represented anymore.  The objects in this module
describe exactly which pieces of information are affected *before* the document
is generated, so that a release pipeline can decide whether the information
loss is acceptable or whether the release has to be blocked.

The loss judgment is purely based on the model and the two schema versions
involved.  It is therefore identical for the JSON and the XML output formats.
"""

from dataclasses import dataclass, field
from enum import Enum, auto, unique
from typing import TYPE_CHECKING, Optional

from ..schema import SchemaVersion

if TYPE_CHECKING:  # pragma: no cover
    from collections.abc import Iterable, Iterator


@unique
class LossCategory(Enum):
    """High-level grouping of the information that is lost during downgrade."""

    VULNERABILITY_ANALYSIS = auto()
    """Vulnerability analysis (triage) state, e.g. ``analysis`` data."""

    CRYPTO_ASSET = auto()
    """Cryptographic assets and their properties (``cryptoProperties``)."""

    REFERENCE = auto()
    """Cross-source vulnerability references and related advisory links."""


@unique
class LossKind(Enum):
    """How the affected information is handled by the older schema."""

    DROPPED = auto()
    """The information has no representation at all in the target schema and
    is silently omitted from the generated document."""

    NORMALIZED = auto()
    """The information is still emitted, but only through a coarser, lossy
    equivalent representation (for example an unknown enum value is mapped to
    a generic ``other`` value)."""


@dataclass(frozen=True)
class DowngradeLoss:
    """A single piece of information that is affected by a schema downgrade.

    Instances are immutable and hashable so that callers can de-duplicate or
    build sets of expected losses in tests.
    """

    category: LossCategory
    kind: LossKind
    source: str
    """Stable, machine-readable identifier of the affected model element,
    for example ``Vulnerability.analysis`` or ``Component.cryptoProperties``."""

    introduced_in: SchemaVersion
    """Schema version in which the affected element became available, so that
    it is only lost when targeting an older version."""

    location: str
    """Human-readable pointer to the affected BOM node, for example the
    component name or the vulnerability identifier."""

    detail: str
    """Human-readable explanation of what disappears or how it is mapped."""

    equivalent: Optional[str] = None
    """Description of the equivalent (lossy) representation that remains in
    the target document, or ``None`` when the element is dropped entirely."""

    def __str__(self) -> str:
        head = f'[{self.category.name}/{self.kind.name}] {self.source} @ {self.location}'
        if self.equivalent:
            return f'{head}: {self.detail} (equivalent: {self.equivalent})'
        return f'{head}: {self.detail}'


@dataclass(frozen=True)
class DowngradeLossReport:
    """Result of analyzing a BOM against a target (older) schema version.

    The report is a frozen container of :class:`DowngradeLoss` items.  It does
    not hold a reference to the BOM and never mutates it, hence the same BOM
    instance can still be serialized against the current/newer schema version.
    """

    target_version: SchemaVersion
    losses: tuple[DowngradeLoss, ...] = field(default_factory=tuple)

    def __iter__(self) -> 'Iterator[DowngradeLoss]':
        return iter(self.losses)

    def __len__(self) -> int:
        return len(self.losses)

    def __bool__(self) -> bool:
        return bool(self.losses)

    def for_category(self, category: LossCategory) -> 'tuple[DowngradeLoss, ...]':
        """Return only the losses belonging to ``category``."""
        return tuple(loss for loss in self.losses if loss.category is category)

    def of_kind(self, kind: LossKind) -> 'tuple[DowngradeLoss, ...]':
        """Return only the losses of the given :class:`LossKind`."""
        return tuple(loss for loss in self.losses if loss.kind is kind)

    def categories(self) -> 'frozenset[LossCategory]':
        """All categories that have at least one loss."""
        return frozenset(loss.category for loss in self.losses)

    def render_text(self) -> str:
        """Render a human-readable loss list, suitable for release reports."""
        lines = [
            f'Downgrade loss report for target CycloneDX '
            f'v{self.target_version.to_version()}: {len(self.losses)} loss item(s)'
        ]
        lines.extend(f'- {loss}' for loss in self.losses)
        return '\n'.join(lines)

    @classmethod
    def empty(cls, target_version: SchemaVersion) -> 'DowngradeLossReport':
        return cls(target_version=target_version, losses=())

    @classmethod
    def collect(cls, target_version: SchemaVersion,
                losses: 'Iterable[DowngradeLoss]') -> 'DowngradeLossReport':
        return cls(target_version=target_version, losses=tuple(dict.fromkeys(losses)))
