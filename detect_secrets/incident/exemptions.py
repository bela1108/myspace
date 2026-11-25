"""Time-limited exemptions and the rules for using them.

An exemption is never a free-floating pass: it is bound to both a finding id
and the path the finding occupied when granted.  Moves and forks produce
occurrences at other paths that the exemption cannot cover, so one expired
exemption can never close two sibling occurrences.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable
from typing import List
from typing import Optional

from detect_secrets.incident.enums import ExemptionStatus
from detect_secrets.incident.exceptions import InvalidEventError
from detect_secrets.incident.models import Exemption


@dataclass(frozen=True)
class CoverageDecision:
    allowed: bool
    exemption_id: Optional[str]
    reason: str
    status: ExemptionStatus


class ExemptionRegistry:
    """Single source of truth for whether an exemption is live."""

    def __init__(self, exemptions: Iterable[Exemption]) -> None:
        self._exemptions: dict[str, Exemption] = {}
        for exemption in exemptions:
            if exemption.exemption_id in self._exemptions:
                raise InvalidEventError(
                    f"duplicate exemption id: {exemption.exemption_id}",
                )
            self._exemptions[exemption.exemption_id] = exemption

    def get(self, exemption_id: str) -> Exemption:
        if exemption_id not in self._exemptions:
            raise InvalidEventError(f"unknown exemption id: {exemption_id}")
        return self._exemptions[exemption_id]

    def status_at(self, exemption: Exemption, at: str) -> ExemptionStatus:
        if exemption.is_revoked_at(at):
            return ExemptionStatus.REVOKED
        if exemption.is_expired_at(at):
            return ExemptionStatus.EXPIRED
        return ExemptionStatus.ACTIVE

    def active_for(self, finding_id: str, path: str, at: str) -> List[Exemption]:
        return [
            exemption
            for exemption in self._exemptions.values()
            if exemption.covers(finding_id, path, at)
        ]

    def next_expiry(
        self,
        finding_id: str,
        path: str,
        at: str,
    ) -> Optional[str]:
        active = self.active_for(finding_id, path, at)
        if not active:
            return None
        return max(exemption.expires_at for exemption in active)

    def evaluate(
        self,
        finding_id: str,
        path: str,
        at: str,
        exemption_id: Optional[str] = None,
    ) -> CoverageDecision:
        """Decide whether a suppression request may close this occurrence.

        A rejection (rather than a silent close) is deliberate: an expired,
        revoked or path-mismatched exemption must never close a live finding.
        """
        if exemption_id is not None:
            exemption = self.get(exemption_id)
            if exemption.finding_id != finding_id:
                return CoverageDecision(
                    False,
                    exemption_id,
                    f"exemption {exemption_id} belongs to another finding",
                    self.status_at(exemption, at),
                )
            if exemption.path != path:
                return CoverageDecision(
                    False,
                    exemption_id,
                    (
                        f"exemption {exemption_id} is bound to "
                        f"{exemption.path}, not current path {path}"
                    ),
                    self.status_at(exemption, at),
                )
            status = self.status_at(exemption, at)
            if status != ExemptionStatus.ACTIVE:
                return CoverageDecision(
                    False,
                    exemption_id,
                    f"exemption {exemption_id} is {status.value}",
                    status,
                )
            return CoverageDecision(
                True,
                exemption_id,
                "active exemption covers this occurrence",
                status,
            )

        active = self.active_for(finding_id, path, at)
        if not active:
            return CoverageDecision(
                False,
                None,
                "no active exemption for this finding and path",
                ExemptionStatus.EXPIRED,
            )
        active.sort(key=lambda item: item.expires_at, reverse=True)
        chosen = active[0]
        return CoverageDecision(
            True,
            chosen.exemption_id,
            "active exemption covers this occurrence",
            ExemptionStatus.ACTIVE,
        )
