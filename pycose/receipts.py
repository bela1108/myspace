from datetime import date
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from pycose.exceptions import CoseReceiptAuditError


BUILDER_ROLE = "builder"
REVIEWER_ROLE = "reviewer"
REQUIRED_ROLES = frozenset((BUILDER_ROLE, REVIEWER_ROLE))


class SignatureAttestation:
    """Cryptographic verification result and caller-provided key ownership."""

    def __init__(self,
                 key_id: Any,
                 signature_valid: bool,
                 person_id: Any,
                 role: str,
                 effective_date: date):
        self.key_id = key_id
        self.signature_valid = signature_valid
        self.person_id = person_id
        self.role = role
        self.effective_date = effective_date


class IndependentWitness:
    """A signed material and the independent duties recorded for it."""

    def __init__(self, material_id: Any, attestations: Iterable[SignatureAttestation]):
        self.material_id = material_id
        self.attestations = list(attestations)


class ReceiptAuditResult:
    """Outcome of an offline receipt separation-of-duties audit."""

    def __init__(self, valid: bool, missing_responsibilities: Optional[Dict[Any, List[str]]] = None):
        self.valid = valid
        self.missing_responsibilities = missing_responsibilities or {}


class OfflineReceiptAuditor:
    """Audit already-verified COSE receipts using externally supplied key ownership."""

    def __init__(self, receipt_date: date, accepted_roles: Optional[Iterable[str]] = None):
        self.receipt_date = receipt_date
        self.accepted_roles = frozenset(accepted_roles or REQUIRED_ROLES)

    def audit(self, witnesses: Iterable[IndependentWitness]) -> ReceiptAuditResult:
        missing_responsibilities = {}
        saw_witness = False

        for witness in witnesses:
            saw_witness = True
            missing = self._audit_witness(witness)
            if missing:
                missing_responsibilities[witness.material_id] = missing

        return ReceiptAuditResult(saw_witness and not missing_responsibilities, missing_responsibilities)

    def _audit_witness(self, witness: IndependentWitness) -> List[str]:
        assignments: Dict[str, Tuple[Any, Any]] = {}
        key_ids: Set[Any] = set()

        for attestation in witness.attestations:
            if not attestation.signature_valid:
                continue

            if attestation.key_id in key_ids:
                raise CoseReceiptAuditError(f"Duplicate key attestation: {attestation.key_id}")
            key_ids.add(attestation.key_id)

            if attestation.effective_date > self.receipt_date:
                continue

            if attestation.role not in self.accepted_roles:
                continue

            if attestation.role in assignments:
                raise CoseReceiptAuditError(f"Duplicate role assignment: {attestation.role}")

            if not attestation.person_id:
                continue

            assignments[attestation.role] = (attestation.key_id, attestation.person_id)

        missing_roles = self.accepted_roles.difference(assignments)
        if missing_roles:
            return [f"independent {role} duty" for role in sorted(missing_roles)]

        people = {person_id for key_id, person_id in assignments.values()}
        if len(people) != len(assignments):
            return ["independent natural person for builder and reviewer duties"]

        return []
