from dataclasses import dataclass
from dataclasses import field
from datetime import datetime
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple


STATUS_CLOSED = 'closed'
STATUS_OPEN = 'open'


@dataclass
class ReceiptFailure:
    """Why a receipt failed to support closing an alert.

    Each dimension is validated independently, so a single receipt may
    fail several of them at once.
    """
    receipt_id: str
    ineligible: Optional[str] = None
    window: Optional[str] = None
    environment: Optional[str] = None
    revocation_scope: Optional[str] = None

    def to_dict(self) -> Dict[str, str]:
        output = {'receipt_id': self.receipt_id}
        for key in ('ineligible', 'window', 'environment', 'revocation_scope'):
            value = getattr(self, key)
            if value is not None:
                output[key] = value
        return output


@dataclass
class Decision:
    """The closure decision for one (fingerprint, branch) pair."""
    fingerprint: str
    branch: str
    status: str
    justification: Tuple[str, ...] = ()
    support: Dict[str, Tuple[str, ...]] = field(default_factory=dict)
    failures: Tuple[ReceiptFailure, ...] = ()

    @property
    def is_closed(self) -> bool:
        return self.status == STATUS_CLOSED

    def to_dict(self) -> Dict[str, Any]:
        return {
            'status': self.status,
            'justification': list(self.justification),
            'support': {
                receipt_id: list(supporters)
                for receipt_id, supporters in sorted(self.support.items())
            },
            'failures': [failure.to_dict() for failure in self.failures],
        }


class ClosureReport:
    """The outcome of evaluating one evidence bundle."""

    def __init__(
        self,
        evidence_version: str,
        environment: str,
        as_of: datetime,
        decisions: Dict[Tuple[str, str], Decision],
        cycles: List[List[str]],
        warnings: List[str],
    ) -> None:
        self.evidence_version = evidence_version
        self.environment = environment
        self.as_of = as_of
        self.decisions = decisions
        self.cycles = cycles
        self.warnings = warnings

    def decision(self, fingerprint: str, branch: str) -> Decision:
        """
        :raises: KeyError
        """
        return self.decisions[(fingerprint, branch)]

    def closed_branches(self, fingerprint: str) -> List[str]:
        return sorted(
            branch
            for (fp, branch), decision in self.decisions.items()
            if fp == fingerprint and decision.is_closed
        )

    def open_branches(self, fingerprint: str) -> List[str]:
        return sorted(
            branch
            for (fp, branch), decision in self.decisions.items()
            if fp == fingerprint and not decision.is_closed
        )

    def to_dict(self) -> Dict[str, Any]:
        decisions: Dict[str, Dict[str, Any]] = {}
        for (fingerprint, branch), decision in sorted(self.decisions.items()):
            decisions.setdefault(fingerprint, {})[branch] = decision.to_dict()

        return {
            'evidence_version': self.evidence_version,
            'environment': self.environment,
            'as_of': self.as_of.isoformat(),
            'cycles': self.cycles,
            'warnings': self.warnings,
            'decisions': decisions,
        }


class ClosureJournal:
    """An append-only log of reports, keyed by evidence version.

    Lets an auditor compare decisions across evidence versions: which
    branches were reopened by a revocation, which remain closable, and
    under which evidence version an earlier decision held.
    """

    def __init__(self) -> None:
        self._reports: Dict[str, ClosureReport] = {}
        self._order: List[str] = []

    @property
    def versions(self) -> List[str]:
        return list(self._order)

    def record(self, report: ClosureReport) -> str:
        """Records a report and returns its evidence version."""
        version = report.evidence_version
        if version not in self._reports:
            self._reports[version] = report
            self._order.append(version)
        return version

    def report(self, version: str) -> ClosureReport:
        """
        :raises: KeyError
        """
        return self._reports[version]

    def decision_history(self, fingerprint: str, branch: str) -> List[Tuple[str, str]]:
        """Returns (evidence_version, status) pairs in recording order."""
        history = []
        for version in self._order:
            decision = self._reports[version].decisions.get((fingerprint, branch))
            if decision is not None:
                history.append((version, decision.status))
        return history

    def reopened(self, old_version: str, new_version: str) -> List[Tuple[str, str]]:
        return [entry['key'] for entry in self._diff_entries(old_version, new_version, 'reopened')]

    def still_closed(self, old_version: str, new_version: str) -> List[Tuple[str, str]]:
        return [entry['key'] for entry in self._diff_entries(old_version, new_version, 'still')]

    def diff(self, old_version: str, new_version: str) -> Dict[str, Any]:
        """Compares two recorded evidence versions.

        Reopened entries carry ``previously_closed_under``: the most recent
        recorded evidence version, up to ``old_version``, under which the
        original closure decision held.
        """
        return {
            'from': old_version,
            'to': new_version,
            'reopened': [
                {
                    'fingerprint': fingerprint,
                    'branch': branch,
                    'previously_closed_under': self._last_closed_version(
                        fingerprint,
                        branch,
                        up_to=old_version,
                    ),
                }
                for fingerprint, branch in self.reopened(old_version, new_version)
            ],
            'still_closed': [
                {'fingerprint': fingerprint, 'branch': branch}
                for fingerprint, branch in self.still_closed(old_version, new_version)
            ],
            'newly_closed': [
                {'fingerprint': fingerprint, 'branch': branch}
                for fingerprint, branch in self._newly_closed(old_version, new_version)
            ],
        }

    def _diff_entries(
        self,
        old_version: str,
        new_version: str,
        kind: str,
    ) -> List[Dict[str, Any]]:
        old = self._reports[old_version]
        new = self._reports[new_version]
        entries = []
        for key in sorted(old.decisions):
            was_closed = old.decisions[key].is_closed
            is_closed = key in new.decisions and new.decisions[key].is_closed
            if kind == 'reopened' and was_closed and not is_closed:
                entries.append({'key': key})
            elif kind == 'still' and was_closed and is_closed:
                entries.append({'key': key})
        return entries

    def _newly_closed(self, old_version: str, new_version: str) -> List[Tuple[str, str]]:
        old = self._reports[old_version]
        new = self._reports[new_version]
        return [
            key
            for key in sorted(new.decisions)
            if new.decisions[key].is_closed
            and (key not in old.decisions or not old.decisions[key].is_closed)
        ]

    def _last_closed_version(
        self,
        fingerprint: str,
        branch: str,
        up_to: str,
    ) -> Optional[str]:
        result = None
        for version in self._order:
            decision = self._reports[version].decisions.get((fingerprint, branch))
            if decision is not None and decision.is_closed:
                result = version
            if version == up_to:
                break
        return result
