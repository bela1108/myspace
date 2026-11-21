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
Configurable release gate for downgrade losses.

A :class:`DowngradePolicy` decides which of the losses collected in a
:class:`~cyclonedx.downgrade.report.DowngradeLossReport` should abort a release.
The policy is intentionally independent of the output format, matching the
format-agnostic loss analysis.
"""

from abc import ABC, abstractmethod
from collections.abc import Iterable
from typing import AbstractSet, Optional, Tuple

from ..exception import CycloneDxException

from .report import DowngradeLoss, DowngradeLossReport, LossCategory, LossKind


class BaseDowngradePolicy(ABC):
    """Protocol-like base for objects that decide whether losses block release."""

    @abstractmethod
    def is_blocking(self, loss: DowngradeLoss) -> bool:
        """Return ``True`` if this single loss must abort the release."""
        ...  # pragma: no cover

    def blocking_losses(self, report: DowngradeLossReport) -> Tuple[DowngradeLoss, ...]:
        return tuple(loss for loss in report if self.is_blocking(loss))

    def allows(self, report: DowngradeLossReport) -> bool:
        """Return ``True`` if none of the losses in ``report`` block the release."""
        return not self.blocking_losses(report)


class DowngradePolicy(BaseDowngradePolicy):
    """Default policy driven by explicit category/kind/pair blocklists.

    A loss blocks the release when its ``(category, kind)`` pair is listed in
    ``blocked_pairs``, or when its category is in ``blocked_categories`` (any
    kind), or when its kind is in ``blocked_kinds`` (any category). The default
    constructor blocks nothing, so callers opt in to the losses they care about.
    """

    def __init__(
        self,
        *,
        blocked_categories: Iterable[LossCategory] = (),
        blocked_kinds: Iterable[LossKind] = (),
        blocked_pairs: Iterable[Tuple[LossCategory, LossKind]] = (),
    ) -> None:
        self._blocked_categories = frozenset(blocked_categories)
        self._blocked_kinds = frozenset(blocked_kinds)
        self._blocked_pairs = frozenset(blocked_pairs)

    @property
    def blocked_categories(self) -> AbstractSet[LossCategory]:
        return self._blocked_categories

    @property
    def blocked_kinds(self) -> AbstractSet[LossKind]:
        return self._blocked_kinds

    @property
    def blocked_pairs(self) -> AbstractSet[Tuple[LossCategory, LossKind]]:
        return self._blocked_pairs

    def is_blocking(self, loss: DowngradeLoss) -> bool:
        return (
            loss.category in self._blocked_categories
            or loss.kind in self._blocked_kinds
            or (loss.category, loss.kind) in self._blocked_pairs
        )

    @classmethod
    def report_only(cls) -> "DowngradePolicy":
        """Never block; the report is informational only."""
        return cls()

    @classmethod
    def block_dropped(cls) -> "DowngradePolicy":
        """Block every loss where information disappears entirely."""
        return cls(blocked_kinds=(LossKind.DROPPED,))

    @classmethod
    def block_any(cls) -> "DowngradePolicy":
        """Block any detected loss, including value normalizations."""
        return cls(blocked_kinds=(LossKind.DROPPED, LossKind.NORMALIZED))



class DowngradeRejectedError(CycloneDxException):
    """Raised when a configured downgrade policy blocks the release.

    Carries the full :class:`DowngradeLossReport` (which still lists every
    detected loss) and the subset of losses that triggered the rejection.
    """

    def __init__(self, report: DowngradeLossReport,
                 blocking: Iterable[DowngradeLoss]) -> None:
        self.report = report
        self.blocking_losses = tuple(blocking)
        super().__init__(
            "Downgrade to CycloneDX v" + report.target_version.to_version()
            + " rejected by policy; " + str(len(self.blocking_losses))
            + " blocking loss(es)"
        )


def enforce(policy: Optional[BaseDowngradePolicy],
            report: DowngradeLossReport) -> DowngradeLossReport:
    """Raise :class:`DowngradeRejectedError` if ``policy`` blocks ``report``.

    A ``None`` policy is treated as report-only (never block). The BOM behind
    the report is left untouched, so the same instance can still be serialized
    to a newer schema.
    """
    if policy is not None:
        blocking = policy.blocking_losses(report)
        if blocking:
            raise DowngradeRejectedError(report, blocking)
    return report
