"""
Three-way receipt evidence reconciliation.

The reconciler joins the local plan, the repository shipping manifest and the
transit receipt using each distribution's concrete file identity (filename
plus digest) rather than the bare (name, version) coordinate. Every piece of
evidence attached to a result retains the document and provider that supplied
it, so a conflict between two handoffs can be traced back to the exact stage
and originating document.
"""

from __future__ import annotations

from pip_audit._receipt.model import (
    EvidenceRecord,
    HandoffStage,
    MissingMaterial,
    ReconciliationReport,
    ReconciliationRow,
    ReconciliationStatus,
    StageConflict,
)
from pip_audit._receipt.source import ReceiptDocument


class _Index:
    """Lookup tables built for a manifest or receipt document."""

    def __init__(self) -> None:
        self.by_filename: dict[str, EvidenceRecord] = {}
        self.by_coordinate: dict[tuple[str, str], list[EvidenceRecord]] = {}

    @classmethod
    def build(cls, document: ReceiptDocument) -> "_Index":
        index = cls()
        for record in document.records:
            if record.filename is not None:
                index.by_filename.setdefault(record.filename, record)
            index.by_coordinate.setdefault(record.coordinate.key, []).append(record)
        return index


class ReceiptReconciler:
    """
    Reconcile local-plan artifacts against shipped and received evidence.
    """

    def __init__(
        self,
        plan: ReceiptDocument,
        manifest: ReceiptDocument,
        receipt: ReceiptDocument,
    ) -> None:
        self._plan = plan
        self._manifest = manifest
        self._receipt = receipt
        self._manifest_index = _Index.build(manifest)
        self._receipt_index = _Index.build(receipt)
        self._consumed_manifest: set[str] = set()
        self._consumed_receipt: set[str] = set()

    def reconcile(self) -> ReconciliationReport:
        """Run the full reconciliation and return one row per distribution file."""

        rows = [self._reconcile_plan_record(record) for record in self._plan.records]
        rows.extend(self._orphan_rows())
        return ReconciliationReport(rows=tuple(rows))

    def _reconcile_plan_record(self, plan_record: EvidenceRecord) -> ReconciliationRow:
        evidence: list[EvidenceRecord] = [plan_record]
        missing: list[MissingMaterial] = []
        conflicts: list[StageConflict] = []

        if not plan_record.has_identity:
            # A legacy record without artifact identity is still opened, but
            # cannot be matched on a distribution file and stays pending.
            for material in plan_record.identity.missing_materials:
                missing.append(
                    MissingMaterial(
                        stage=HandoffStage.LOCAL_PLAN,
                        material=material,
                        detail=(
                            f"local plan record from {plan_record.source_document} "
                            f"has no {material}; legacy report cannot be file-matched"
                        ),
                    )
                )
            return ReconciliationRow(
                coordinate=plan_record.coordinate,
                filename=plan_record.filename,
                status=ReconciliationStatus.PENDING,
                evidence=tuple(evidence),
                conflicts=tuple(conflicts),
                missing_materials=tuple(missing),
            )

        filename = plan_record.filename
        assert filename is not None
        shipped = self._manifest_index.by_filename.get(filename)
        received = self._receipt_index.by_filename.get(filename)

        if shipped is not None:
            self._consumed_manifest.add(filename)
            evidence.append(shipped)
        else:
            missing.append(
                MissingMaterial(
                    stage=HandoffStage.WAREHOUSE,
                    material="shipped_artifact",
                    detail=(
                        f"no warehouse manifest entry for distribution file {filename} "
                        f"from {self._manifest.source_document}"
                    ),
                )
            )

        if received is not None:
            self._consumed_receipt.add(filename)
            evidence.append(received)
        else:
            missing.append(
                MissingMaterial(
                    stage=HandoffStage.TRANSIT,
                    material="received_artifact",
                    detail=(
                        f"no transit receipt entry for distribution file {filename} "
                        f"from {self._receipt.source_document}"
                    ),
                )
            )

        conflicts.extend(self._detect_conflicts(plan_record, shipped, received))

        if conflicts:
            status = ReconciliationStatus.CONFLICT
        elif shipped is not None and received is not None:
            status = ReconciliationStatus.MATCHED
        else:
            status = ReconciliationStatus.PENDING

        return ReconciliationRow(
            coordinate=plan_record.coordinate,
            filename=filename,
            status=status,
            evidence=tuple(evidence),
            conflicts=tuple(conflicts),
            missing_materials=tuple(missing),
        )

    def _detect_conflicts(
        self,
        plan: EvidenceRecord,
        shipped: EvidenceRecord | None,
        received: EvidenceRecord | None,
    ) -> list[StageConflict]:
        conflicts: list[StageConflict] = []

        if shipped is not None and shipped.digest != plan.digest:
            conflicts.append(
                StageConflict(
                    stage=HandoffStage.WAREHOUSE,
                    expected_digest=plan.digest,
                    observed_digest=shipped.digest,
                    expected_source=plan.source_document,
                    observed_source=shipped.source_document,
                    detail=(
                        f"warehouse handoff changed the digest for {plan.filename}; "
                        f"provided by {shipped.provided_by}"
                    ),
                )
            )

        if received is not None and shipped is not None and received.digest != shipped.digest:
            # The shipment is the prior handoff, so the divergence is first
            # observable at the transit handoff.
            conflicts.append(
                StageConflict(
                    stage=HandoffStage.TRANSIT,
                    expected_digest=shipped.digest,
                    observed_digest=received.digest,
                    expected_source=shipped.source_document,
                    observed_source=received.source_document,
                    detail=(
                        f"transit handoff recorded a different digest for {plan.filename} "
                        f"than the warehouse manifest; provided by {received.provided_by}"
                    ),
                )
            )
        elif received is not None and shipped is None and received.digest != plan.digest:
            conflicts.append(
                StageConflict(
                    stage=HandoffStage.TRANSIT,
                    expected_digest=plan.digest,
                    observed_digest=received.digest,
                    expected_source=plan.source_document,
                    observed_source=received.source_document,
                    detail=(
                        f"transit receipt digest disagrees with the local plan for "
                        f"{plan.filename}; provided by {received.provided_by}"
                    ),
                )
            )

        return conflicts

    def _orphan_rows(self) -> list[ReconciliationRow]:
        """Rows for shipped/received artifacts that have no planned distribution file."""

        rows: list[ReconciliationRow] = []
        for filename, record in self._manifest_index.by_filename.items():
            if filename in self._consumed_manifest:
                continue
            rows.append(self._orphan_row(record, HandoffStage.WAREHOUSE))
        for filename, record in self._receipt_index.by_filename.items():
            if filename in self._consumed_receipt:
                continue
            rows.append(self._orphan_row(record, HandoffStage.TRANSIT))
        return rows

    def _orphan_row(
        self, record: EvidenceRecord, observed_stage: HandoffStage
    ) -> ReconciliationRow:
        return ReconciliationRow(
            coordinate=record.coordinate,
            filename=record.filename,
            status=ReconciliationStatus.PENDING,
            evidence=(record,),
            missing_materials=(
                MissingMaterial(
                    stage=HandoffStage.LOCAL_PLAN,
                    material="planned_artifact",
                    detail=(
                        f"{observed_stage.value} document {record.source_document} carries "
                        f"{record.filename} but the local plan lists no such distribution file"
                    ),
                ),
            ),
        )
