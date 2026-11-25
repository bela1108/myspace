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
On-call duty ticket for the decommissioning of an internal interface.

A :class:`DutyTicket` wraps a
:class:`~cyclonedx.retirement.engine.ReconciliationReport` and renders the
human-readable handover for the on-call rotation. The last section of the
rendered ticket always lists the services whose confirmation receipts are
still missing, so the reader can answer "who is still missing?" without
re-parsing the report.
"""

from dataclasses import dataclass
from typing import Optional

from .engine import ReconciliationReport
from .model import ReconciliationLine


@dataclass(frozen=True)
class MissingReceipt:
    """A single outstanding confirmation receipt."""

    service_name: str
    bom_ref: str
    bom_revision: str
    role: str
    direction: str
    credential_name: str
    reason: str

    def render(self) -> str:
        """Render one missing-receipt line for the duty ticket."""
        return (
            f'- {self.service_name} '
            f'(bom-ref={self.bom_ref}, revision={self.bom_revision}, '
            f'{self.role}/{self.direction}, '
            f'credential={self.credential_name}): {self.reason}'
        )


class DutyTicket:
    """
    Read-only view of a reconciliation report for the on-call rotation.

    Args:
        interface_name: name or identifier of the interface being retired.
        report: result of the offline reconciliation.
    """

    def __init__(self, interface_name: str, report: ReconciliationReport) -> None:
        self._interface_name = interface_name
        self._report = report

    @property
    def interface_name(self) -> str:
        """Name of the decommissioned interface."""
        return self._interface_name

    @property
    def report(self) -> ReconciliationReport:
        """The underlying reconciliation report."""
        return self._report

    @property
    def missing_receipts(self) -> tuple[MissingReceipt, ...]:
        """All outstanding receipts, in report order."""
        return tuple(
            self._to_missing(line)
            for line in self._report.lines
            if line.is_pending
        )

    @staticmethod
    def _to_missing(line: ReconciliationLine) -> MissingReceipt:
        declaration = line.declaration
        return MissingReceipt(
            service_name=line.service_name,
            bom_ref=declaration.bom_ref,
            bom_revision=declaration.bom_revision,
            role=declaration.role.value,
            direction=declaration.direction.value,
            credential_name=declaration.credential_name,
            reason=line.missing_reason or 'confirmation receipt missing',
        )

    def render(self) -> str:
        """
        Render the duty ticket as plain text.

        The final section is always the list of missing receipts; when every
        line is confirmed the final line states that no receipt is pending.
        """
        confirmed = self._report.confirmed_lines
        pending = self._report.pending_lines
        lines = [
            f'Duty ticket - interface retirement: {self._interface_name}',
            f'reconciliation lines: {len(self._report.lines)}',
            f'confirmed: {len(confirmed)}',
            f'pending confirmation: {len(pending)}',
            '',
            'Missing receipts:',
        ]
        missing = self.missing_receipts
        if missing:
            lines.extend(item.render() for item in missing)
        else:
            lines.append('- none, every consumer confirmed retirement')
        return '\n'.join(lines)

    @property
    def is_complete(self) -> bool:
        """Whether no line still waits for a confirmation receipt."""
        return not any(line.is_pending for line in self._report.lines)

    def line_for(
        self, *, bom_ref: str, bom_revision: str,
    ) -> Optional[ReconciliationLine]:
        """Look up a reconciliation line by its service identity."""
        for line in self._report.lines:
            declaration = line.declaration
            if (
                declaration.bom_ref == bom_ref
                and declaration.bom_revision == bom_revision
            ):
                return line
        return None

    @property
    def status_summary(self) -> dict[str, int]:
        """Count of lines per :class:`ReconciliationStatus` value."""
        summary: dict[str, int] = {}
        for line in self._report.lines:
            key = line.status.value
            summary[key] = summary.get(key, 0) + 1
        return summary

    def __str__(self) -> str:
        return self.render()
