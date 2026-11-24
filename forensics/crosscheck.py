"""Compare release statements that two parties verified independently.

The cross-check never downloads anything and never asks one party to trust
the other party's root. Each :class:`~forensics.models.PartyInput` is first
verified against its own root by
:mod:`forensics.verification`. Only afterwards are the resulting
:class:`~forensics.models.Statement` objects compared.

The decision rules deliberately keep the three outcomes apart:

* ``consistent`` - both sides verified a statement and length, hashes and
  signed custom fields are identical,
* ``conflict`` - both sides verified a statement but the published content
  claims differ; the verdict carries evidence pointing at both originals,
* ``undecided`` - only one side could provide an in-scope, verified
  statement. Missing material or an unverifiable trust chain can never prove
  a disagreement, so such records stay open.
"""

from __future__ import annotations

from fnmatch import fnmatchcase

from forensics.models import (
    CONFLICT,
    CONSISTENT,
    UNDECIDED,
    CrosscheckReport,
    PartyInput,
    PartyResult,
    REASON_CUSTOM,
    REASON_HASH,
    REASON_LENGTH,
    REASON_MISSING,
    REASON_OUT_OF_SCOPE,
    REASON_TRUST,
    Statement,
    TargetVerdict,
)
from forensics.verification import verify_party_input

# Re-exported for the package level API.
__all__ = ["run_crosscheck", "compare_statements", "in_scope"]


def in_scope(target_path: str, patterns: tuple[str, ...]) -> bool:
    """Return whether ``target_path`` matches any of the scope ``patterns``.

    Scope patterns use the same semantics as TUF delegated role path
    patterns: every ``/`` separated part is matched independently with
    shell-style wildcards, so a ``*`` never crosses a directory boundary.
    An empty scope means "no observation was declared", which matches
    nothing: a party must explicitly claim a target to have observed it.
    """

    if not patterns:
        return False
    path_parts = target_path.split("/")
    for pattern in patterns:
        pattern_parts = pattern.split("/")
        if len(path_parts) != len(pattern_parts):
            continue
        pairs = zip(path_parts, pattern_parts, strict=True)
        if all(fnmatchcase(part, pat) for part, pat in pairs):
            return True
    return False


def compare_statements(
    target_path: str,
    first: Statement | None,
    second: Statement | None,
    first_verified: bool,
    second_verified: bool,
) -> TargetVerdict:
    """Decide the verdict for one target from the two statements.

    ``None`` means the party had no statement for the path inside its
    verified metadata. The ``*_verified`` flags additionally tell whether
    the party's bundle as a whole verified: if it did not, even an existing
    statement cannot be treated as independently verifiable evidence.
    """

    statements: dict[str, Statement] = {}
    if first is not None:
        statements["alpha"] = first
    if second is not None:
        statements["beta"] = second

    first_usable = first is not None and first_verified
    second_usable = second is not None and second_verified

    if first_usable and second_usable:
        reasons: list[str] = []
        assert first is not None
        assert second is not None
        if first.length != second.length:
            reasons.append(REASON_LENGTH)

        # Compare only hash algorithms that both statements publish.
        shared_algorithms = set(first.hashes) & set(second.hashes)
        if any(
            first.hashes[algo] != second.hashes[algo]
            for algo in sorted(shared_algorithms)
        ):
            reasons.append(REASON_HASH)

        if first.custom != second.custom:
            reasons.append(REASON_CUSTOM)

        verdict = CONFLICT if reasons else CONSISTENT
        return TargetVerdict(target_path, verdict, reasons, statements)

    reasons = []
    if not first_verified or not second_verified:
        reasons.append(REASON_TRUST)
    if first is None or second is None:
        reasons.append(REASON_MISSING)
    return TargetVerdict(target_path, UNDECIDED, reasons, statements)


def run_crosscheck(inputs: tuple[PartyInput, PartyInput]) -> CrosscheckReport:
    """Verify both parties independently and compare their statements.

    Exactly two parties are supported, mirroring the two incident mirrors.
    The first input is reported as ``alpha`` and the second as ``beta``.
    """

    if len(inputs) != 2:  # defensive: type is a 2-tuple but fail clearly
        raise ValueError("cross-check expects exactly two parties")

    results: dict[str, PartyResult] = {}
    for party_input in inputs:
        results[party_input.party] = verify_party_input(party_input)

    alpha = results[inputs[0].party]
    beta = results[inputs[1].party]

    alpha_scope = inputs[0].scope
    beta_scope = inputs[1].scope

    candidate_paths = set(alpha.statements) | set(beta.statements)
    verdicts: list[TargetVerdict] = []

    for target_path in sorted(candidate_paths):
        alpha_in = in_scope(target_path, alpha_scope)
        beta_in = in_scope(target_path, beta_scope)

        # A path that one party never declared as observed cannot be
        # compared: absence from a declared scope is not a signed claim.
        if not alpha_in or not beta_in:
            statements = {}
            alpha_statement = alpha.statements.get(target_path)
            beta_statement = beta.statements.get(target_path)
            if alpha_statement is not None:
                statements["alpha"] = alpha_statement
            if beta_statement is not None:
                statements["beta"] = beta_statement
            verdicts.append(
                TargetVerdict(
                    target_path,
                    UNDECIDED,
                    [REASON_OUT_OF_SCOPE],
                    statements,
                )
            )
            continue

        verdicts.append(
            compare_statements(
                target_path,
                alpha.statements.get(target_path),
                beta.statements.get(target_path),
                alpha.verified,
                beta.verified,
            )
        )

    return CrosscheckReport(parties=results, verdicts=verdicts)
