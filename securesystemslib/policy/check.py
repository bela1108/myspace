"""Combine policy, material purpose and verification capability into reports.

The checker keeps the three concerns separate and records, for every receipt,
which of them is responsible for the outcome:

* a scheme that the policy does not permit for the stated purpose requires a
  **policy change**,
* a permitted scheme that no available backend can verify requires a
  **verification environment change** (install an optional capability or
  restore the partial backend),
* everything else is either compliant or carries an invalid signature.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from enum import StrEnum

from securesystemslib.exceptions import UnverifiedSignatureError
from securesystemslib.policy.policy import (
    MaterialPurpose,
    VerificationPolicy,
)
from securesystemslib.policy.receipt import Receipt, UnsupportedKey
from securesystemslib.policy.verifier import (
    BackendUnavailableError,
    VerifierBackend,
    VerifierCapabilityError,
)


class CheckOutcome(StrEnum):
    """Final verdict for a single receipt."""

    COMPLIANT = "compliant"
    POLICY_CHANGE_REQUIRED = "policy_change_required"
    ENVIRONMENT_CHANGE_REQUIRED = "environment_change_required"
    SIGNATURE_INVALID = "signature_invalid"


@dataclass
class CheckResult:
    """Verdict for one receipt.

    Attributes:
        receipt: The receipt that was checked.
        outcome: Final verdict.
        policy_version: Policy version used for the decision.
        backend_name: Backend used for verification, if one was reached.
        reasons: Human-readable explanations supporting the verdict.
        policy_blocks: The policy alone forbids this usage.
        environment_blocks: The available backends cannot verify this usage.
    """

    receipt: Receipt
    outcome: CheckOutcome
    policy_version: str
    backend_name: str | None
    reasons: list[str] = field(default_factory=list)
    policy_blocks: bool = False
    environment_blocks: bool = False

    @property
    def scheme(self) -> str:
        """Scheme claimed by the checked receipt."""
        return self.receipt.scheme


@dataclass
class ComplianceReport:
    """Aggregate verdict over one or more receipts.

    The report is intentionally serializable-friendly: every attribute uses
    plain types or dataclasses with explicit ``to_dict`` helpers.
    """

    policy_version: str
    backend_name: str | None
    results: list[CheckResult] = field(default_factory=list)

    @property
    def compliant(self) -> bool:
        """True when every receipt is compliant."""
        return all(result.outcome is CheckOutcome.COMPLIANT for result in self.results)

    def outcomes(self) -> Counter[CheckOutcome]:
        """Count of receipts per :class:`CheckOutcome`."""
        return Counter(result.outcome for result in self.results)

    def policy_changes(self) -> list[CheckResult]:
        """Receipts that require a policy decision or policy update."""
        return [
            result
            for result in self.results
            if result.outcome is CheckOutcome.POLICY_CHANGE_REQUIRED
        ]

    def environment_changes(self) -> list[CheckResult]:
        """Receipts that require a verification environment change only."""
        return [
            result
            for result in self.results
            if result.outcome is CheckOutcome.ENVIRONMENT_CHANGE_REQUIRED
        ]

    def to_dict(self) -> dict:
        """Return a JSON-serializable representation of the report."""
        return {
            "policy_version": self.policy_version,
            "backend_name": self.backend_name,
            "compliant": self.compliant,
            "outcome_counts": {
                outcome.value: count
                for outcome, count in sorted(self.outcomes().items())
            },
            "results": [
                {
                    "outcome": result.outcome.value,
                    "purpose": result.receipt.purpose.value,
                    "scheme": result.scheme,
                    "keyid": result.receipt.key.keyid,
                    "policy_blocks": result.policy_blocks,
                    "environment_blocks": result.environment_blocks,
                    "reasons": list(result.reasons),
                }
                for result in self.results
            ],
        }

    def to_text(self) -> str:
        """Render a short human-readable report stating who must change what."""
        lines = [
            f"Compliance report (policy {self.policy_version}, "
            f"backend {self.backend_name or 'unreachable'})",
            f"Overall: {'PASS' if self.compliant else 'ACTION REQUIRED'}",
        ]
        for outcome, count in sorted(self.outcomes().items()):
            lines.append(f"  {outcome.value}: {count}")

        for result in self.results:
            lines.append(
                f"- {result.scheme} [{result.receipt.purpose.value}] "
                f"keyid={result.receipt.key.keyid}: {result.outcome.value}"
            )
            for reason in result.reasons:
                lines.append(f"    * {reason}")
        return "\n".join(lines)


def check_receipt(
    receipt: Receipt,
    policy: VerificationPolicy,
    backends: VerifierBackend | list[VerifierBackend],
) -> CheckResult:
    """Check one receipt against a policy and one or more verifier backends.

    Backends are tried in order; the first backend that supports the scheme
    performs the verification. A partial deployment where every backend lacks
    an optional capability is reported as an environment change, never as an
    invalid signature.
    """
    if isinstance(backends, VerifierBackend):
        backend_list = [backends]
    else:
        backend_list = list(backends)

    backend_name = _reachable_backend_name(backend_list)
    result = CheckResult(
        receipt=receipt,
        outcome=CheckOutcome.COMPLIANT,
        policy_version=policy.version,
        backend_name=backend_name,
    )

    policy_result = _evaluate_policy(result, policy)
    if policy_result is not None:
        return policy_result

    return _verify_with_backends(result, policy, backend_list)


def _evaluate_policy(
    result: CheckResult, policy: VerificationPolicy
) -> CheckResult | None:
    """Apply policy rules; return a final result when the policy blocks."""
    receipt = result.receipt
    scheme = receipt.scheme
    purpose = receipt.purpose

    # An unknown scheme is always a policy question, independent of whether
    # the environment can verify it.
    if not policy.is_known_scheme(scheme):
        result.outcome = CheckOutcome.POLICY_CHANGE_REQUIRED
        result.policy_blocks = True
        result.reasons.append(
            f"scheme {scheme!r} is not covered by policy {policy.version}: "
            "retire, explicitly allow-list, or review-list it"
        )
        return result

    if not policy.is_allowed_for(scheme, purpose):
        result.outcome = CheckOutcome.POLICY_CHANGE_REQUIRED
        result.policy_blocks = True
        if purpose is MaterialPurpose.NEW_MATERIAL:
            result.reasons.append(
                f"scheme {scheme!r} is review-only under policy "
                f"{policy.version}: re-sign new material with an allowed "
                "scheme, or change the policy to re-enable it"
            )
        else:
            result.reasons.append(
                f"scheme {scheme!r} is not reviewable under policy {policy.version}"
            )
        return result

    # Historical review-only receipts must stay readable: when no verifier is
    # installed, parsing still succeeded, so record the skipped crypto check
    # as informational rather than blocking the review workflow.
    if (
        purpose is MaterialPurpose.HISTORICAL_REVIEW
        and policy.is_review_only(scheme)
        and isinstance(receipt.key, UnsupportedKey)
    ):
        result.reasons.append(
            f"review-only receipt for {scheme!r} is readable; no local "
            "verifier is installed, so cryptographic re-verification was "
            "skipped"
        )
        return result

    return None


def _verify_with_backends(
    result: CheckResult,
    policy: VerificationPolicy,
    backend_list: list[VerifierBackend],
) -> CheckResult:
    """Try backends in order and attribute remaining gaps to the environment."""
    receipt = result.receipt
    scheme = receipt.scheme
    capability_reasons: list[str] = []

    for backend in backend_list:
        try:
            if not backend.supports(scheme):
                capability_reasons.append(f"{backend.name} does not support {scheme!r}")
                continue
        except BackendUnavailableError as error:
            capability_reasons.append(str(error))
            continue

        try:
            backend.verify(receipt.key, receipt.signature, receipt.payload)
        except VerifierCapabilityError as error:
            # Race between supports() and verify(): a capability gap.
            capability_reasons.append(str(error))
            continue
        except UnverifiedSignatureError as error:
            result.outcome = CheckOutcome.SIGNATURE_INVALID
            result.backend_name = backend.name
            result.reasons.append(str(error))
            return result
        else:
            result.backend_name = backend.name
            if (
                policy.is_review_only(scheme)
                and receipt.purpose is MaterialPurpose.HISTORICAL_REVIEW
            ):
                result.reasons.append(
                    f"{scheme!r} is accepted for historical review only "
                    f"under policy {policy.version}"
                )
            return result

    # No backend could verify a scheme that the policy permits.
    result.environment_blocks = True
    result.reasons.extend(capability_reasons)
    if isinstance(receipt.key, UnsupportedKey):
        result.reasons.append(
            f"install the optional verifier for {scheme!r} so that the "
            "receipt can be cryptographically checked"
        )
    result.outcome = CheckOutcome.ENVIRONMENT_CHANGE_REQUIRED
    return result


def check_receipts(
    receipts: list[Receipt],
    policy: VerificationPolicy,
    backends: VerifierBackend | list[VerifierBackend],
) -> ComplianceReport:
    """Check many receipts and collect a single :class:`ComplianceReport`."""
    backend_list = (
        [backends] if isinstance(backends, VerifierBackend) else list(backends)
    )
    report = ComplianceReport(
        policy_version=policy.version,
        backend_name=_reachable_backend_name(backend_list),
    )
    report.results = [
        check_receipt(receipt, policy, backend_list) for receipt in receipts
    ]
    return report


def _reachable_backend_name(backends: list[VerifierBackend]) -> str | None:
    for backend in backends:
        try:
            backend.supported_schemes()
        except BackendUnavailableError:
            continue
        return backend.name
    return None
