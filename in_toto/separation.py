# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""
<Program Name>
  separation.py

<Purpose>
  Provides an offline separation-of-duties audit for links that have already
  passed in-toto signature and threshold verification.

  The audit does not talk to an identity service. The caller supplies the
  affiliations of signing keys, and constraints describing which steps must be
  controlled by independent parties. The audit then searches the verified
  evidence for assignments that satisfy those constraints.

  Ambiguous evidence is not collapsed into an arbitrary choice. All retained
  assignments, evidence alternatives, caller notes, and conflicts are reported.
"""

import itertools
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

DEFAULT_MAX_SOLUTIONS = 100

_CONSTRAINT_KINDS = {
    "affiliation": "affiliation",
    "independent": "independent",
    "person": "person",
    "identity": "person",
    "signer": "person",
    "separation": "independent",
    "separate": "independent",
    "team": "affiliation",
}


@dataclass(frozen=True)
class SignerInfo:
    """Caller-provided affiliation information for one signing key."""

    keyid: str
    affiliations: tuple[str, ...]
    identity: str
    note: str = ""


@dataclass(frozen=True)
class SeparationConstraint:
    """A requirement that two steps must not share a control domain."""

    steps: tuple[str, str]
    kind: str = "independent"
    reason: str = ""


@dataclass(frozen=True)
class EvidenceOption:
    """One set of verified evidence that can satisfy a step under one domain."""

    control_domain: str
    keyids: tuple[str, ...]
    identities: tuple[str, ...]
    common_affiliations: tuple[str, ...]


@dataclass
class SeparationReport:
    """Result of an offline separation-of-duties audit."""

    satisfied: bool
    solutions: list[dict[str, dict[str, Any]]] = field(default_factory=list)
    steps: dict[str, dict[str, Any]] = field(default_factory=dict)
    conflicts: list[dict[str, Any]] = field(default_factory=list)
    explanations: list[str] = field(default_factory=list)
    truncated: bool = False

    def to_dict(self):
        """Return a JSON-serializable representation of the report."""
        return {
            "satisfied": self.satisfied,
            "solutions": self.solutions,
            "steps": self.steps,
            "conflicts": self.conflicts,
            "explanations": self.explanations,
            "truncated": self.truncated,
        }

    def explain(self):
        """Return the retained explanations as one printable string."""
        if not self.explanations:
            return ""
        return "\n".join(
            ["Separation-of-duties explanations:"]
            + [f"- {line}" for line in self.explanations]
        )

    def message(self):
        """Return a concise pass/fail message suitable for an exception."""
        if self.satisfied:
            count = len(self.solutions)
            return (
                "Separation-of-duties check passed with"
                f" {count} compatible role assignment(s)."
            )

        messages = [
            conflict["message"]
            for conflict in self.conflicts
            if conflict.get("message")
        ]
        if not messages:
            messages = ["no compatible role assignment was found"]

        unique = []
        for message in messages:
            if message not in unique:
                unique.append(message)

        return "Separation-of-duties check failed: " + "; ".join(unique)


def verify_separation_policy(layout, verified_links, policy):
    """Run a separation audit from a dictionary policy.

    The policy format is::

        {
          "affiliations": {
            "<keyid>": ["build-team"],
            "<other-keyid>": {
              "affiliations": ["acceptance-team", "platform-team"],
              "identity": "carol",
              "note": "temporarily covering acceptance"
            }
          },
          "separation_constraints": [
            {
              "steps": ["build", "accept"],
              "kind": "independent",
              "reason": "build and acceptance must be independent"
            }
          ],
          "max_solutions": 100
        }

    ``signer_affiliations`` and ``constraints`` are accepted as aliases for
    ``affiliations`` and ``separation_constraints``.
    """
    if not isinstance(policy, Mapping):
        raise ValueError("separation policy must be a mapping")

    affiliations = policy.get("affiliations")
    if affiliations is None:
        affiliations = policy.get("signer_affiliations")
    if affiliations is None:
        raise ValueError(
            "separation policy requires 'affiliations' or 'signer_affiliations'"
        )

    constraints = policy.get("separation_constraints")
    if constraints is None:
        constraints = policy.get("constraints", [])

    identities = policy.get("signer_identities")
    if identities is None:
        identities = policy.get("identities")

    return verify_separation_of_duties(
        layout,
        verified_links,
        affiliations,
        constraints,
        signer_identities=identities,
        max_solutions=policy.get("max_solutions", DEFAULT_MAX_SOLUTIONS),
    )


def verify_separation_of_duties(  # noqa: C901, PLR0912, PLR0913, PLR0915
    layout,
    verified_links,
    signer_affiliations,
    separation_constraints=None,
    signer_identities=None,
    max_solutions=DEFAULT_MAX_SOLUTIONS,
):
    """Audit verified links against caller-provided separation constraints.

    Args:
      layout: Layout whose steps define the evidence thresholds.

      verified_links: Link evidence that already passed signature and link
          threshold verification, keyed by step name and signer keyid, e.g.
          ``{step_name: {keyid: Link or Metadata}}``. This is the shape
          returned by ``verify_link_signature_thresholds`` and
          ``verify_sublayouts``.

      signer_affiliations: Mapping (or list of records) from keyid to a single
          affiliation, an iterable of affiliations, or a mapping with
          ``affiliations``/``teams``, ``identity``/``person`` and
          ``note``/``reason`` fields. Affiliations are control domains, not
          proof of organizational independence.

      separation_constraints: Iterable of two-step pairs or constraint
          mappings. The default ``kind`` is ``"independent"``, which requires
          both different control domains and disjoint signers/identities.
          ``"affiliation"`` checks domains only; ``"person"`` checks
          signers/identities only.

      signer_identities: Optional mapping from keyid to person identity. Use
          this when one person can hold several signing keys, so two keys do
          not count as two independent people.

      max_solutions: Maximum number of compatible assignments to retain. The
          step reports still keep all evidence and evidence options, and the
          report marks truncation explicitly.

    Returns:
      SeparationReport: All retained assignments, per-step evidence
          alternatives, conflicts, and explanations. The function does not
          raise when the audit fails; callers that require a hard failure
          should inspect ``report.satisfied`` or use the optional integration
          in ``in_toto_verify``.

    Raises:
      ValueError: The policy, constraints, or verified link mapping is
          malformed.
    """
    if not isinstance(max_solutions, int) or max_solutions < 1:
        raise ValueError("max_solutions must be a positive integer")
    if not hasattr(layout, "steps"):
        raise ValueError("layout must provide a list of steps")
    if not isinstance(verified_links, Mapping):
        raise ValueError("verified_links must be a mapping")

    signers = _normalize_signers(signer_affiliations, signer_identities)
    step_names = {step.name for step in layout.steps}
    constraints = _normalize_constraints(separation_constraints, step_names)

    explanations: list[str] = []
    conflicts: list[dict[str, Any]] = []
    step_reports: dict[str, dict[str, Any]] = {}
    evidence_by_step: dict[str, list[dict[str, Any]]] = {}
    options_by_step: dict[str, list[EvidenceOption]] = {}

    for unknown_step in verified_links:
        if unknown_step not in step_names:
            _add_explanation(
                explanations,
                f"Verified links for unknown step '{unknown_step}' were"
                " ignored by the separation audit.",
            )

    for step in layout.steps:
        threshold = max(1, int(step.threshold))
        evidence = _collect_step_evidence(
            step.name, verified_links.get(step.name, {}), signers, explanations
        )
        options = _build_step_options(
            step.name, threshold, evidence, signers, explanations
        )

        evidence_by_step[step.name] = evidence
        options_by_step[step.name] = options
        step_reports[step.name] = {
            "step": step.name,
            "threshold": threshold,
            "evidence": evidence,
            "options": [
                _serialize_option(option, signers) for option in options
            ],
            "explanations": [],
        }

        if not options:
            conflicts.append(
                _step_conflict(step.name, threshold, evidence, explanations)
            )

    had_step_conflicts = bool(conflicts)
    if not had_step_conflicts:
        raw_solutions, truncated = _enumerate_solutions(
            options_by_step, constraints, max_solutions
        )
    else:
        raw_solutions = []
        truncated = False

    if raw_solutions:
        usage = _solution_usage(raw_solutions)
        _annotate_evidence(evidence_by_step, options_by_step, usage)
        solutions = [
            _serialize_solution(
                solution, layout.steps, signers, options_by_step
            )
            for solution in raw_solutions
        ]
        for step in layout.steps:
            step_reports[step.name]["explanations"] = _step_explanations(
                step.name,
                evidence_by_step[step.name],
                options_by_step[step.name],
            )
            for line in step_reports[step.name]["explanations"]:
                _add_explanation(explanations, line)

        for index, assignment in enumerate(solutions, 1):
            parts = []
            for step_name, record in assignment.items():
                keyids = ", ".join(record["keyids"])
                domain = record["control_domain"]
                parts.append(f"{step_name}->{domain} via {keyids}")
            _add_explanation(
                explanations,
                f"Role assignment {index}: " + "; ".join(parts) + ".",
            )
    else:
        solutions = []
        _annotate_evidence(evidence_by_step, options_by_step, {})
        for step in layout.steps:
            step_reports[step.name]["explanations"] = _step_explanations(
                step.name,
                evidence_by_step[step.name],
                options_by_step[step.name],
            )
            for line in step_reports[step.name]["explanations"]:
                _add_explanation(explanations, line)

        conflicts.extend(_pair_conflicts(options_by_step, constraints))
        if not had_step_conflicts:
            core = _minimal_unsat_core(options_by_step, constraints)
            if len(core) > 1:
                conflicts.append(
                    _constraint_set_conflict(
                        core, layout.steps, options_by_step
                    )
                )

    if truncated:
        _add_explanation(
            explanations,
            "Compatible assignment listing stopped at max_solutions="
            f"{max_solutions}; per-step evidence alternatives are still"
            " reported in full.",
        )

    if not solutions:
        for conflict in conflicts:
            _add_explanation(
                explanations,
                conflict.get("message", "separation constraint failed"),
            )

    return SeparationReport(
        satisfied=bool(solutions),
        solutions=solutions,
        steps=step_reports,
        conflicts=conflicts,
        explanations=explanations,
        truncated=truncated,
    )


def _normalize_signers(  # noqa: C901, PLR0912
    signer_affiliations, signer_identities
):
    if isinstance(signer_affiliations, Mapping):
        items = list(signer_affiliations.items())
    elif isinstance(signer_affiliations, (list, tuple)):
        items = []
        for index, record in enumerate(signer_affiliations):
            if not isinstance(record, Mapping) or "keyid" not in record:
                raise ValueError(
                    "affiliation list entries must be mappings with a"
                    f" 'keyid' field (entry {index} is invalid)"
                )
            items.append((record["keyid"], record))
    else:
        raise ValueError(
            "signer_affiliations must be a mapping or a list of records"
        )

    signers: dict[str, SignerInfo] = {}
    for keyid, entry in items:
        if not isinstance(keyid, str) or not keyid:
            raise ValueError("signer keyids must be non-empty strings")
        if keyid in signers:
            raise ValueError(f"duplicate affiliation entry for keyid '{keyid}'")
        signers[keyid] = _parse_signer_entry(keyid, entry)

    if signer_identities is not None:
        if not isinstance(signer_identities, Mapping):
            raise ValueError("signer_identities must be a mapping")
        for keyid, identity in signer_identities.items():
            if not isinstance(keyid, str) or not keyid:
                raise ValueError("identity keyids must be non-empty strings")
            if not isinstance(identity, str) or not identity:
                raise ValueError(
                    f"identity for keyid '{keyid}' must be a non-empty string"
                )
            existing = signers.get(keyid)
            if existing is None:
                signers[keyid] = SignerInfo(keyid, (), identity)
            else:
                signers[keyid] = SignerInfo(
                    keyid, existing.affiliations, identity, existing.note
                )

    return signers


def _parse_signer_entry(keyid, entry):
    if isinstance(entry, Mapping):
        value = _first_present(
            entry, ("affiliations", "teams", "domains", "groups")
        )
        if value is None:
            raise ValueError(
                f"affiliation entry for keyid '{keyid}' has no affiliations"
            )
        identity = _first_present(entry, ("identity", "person")) or keyid
        note = _first_present(entry, ("note", "reason")) or ""
    else:
        value = entry
        identity = keyid
        note = ""

    if not isinstance(identity, str) or not identity:
        raise ValueError(
            f"identity for keyid '{keyid}' must be a non-empty string"
        )
    if not isinstance(note, str):
        raise ValueError(f"note for keyid '{keyid}' must be a string")

    return SignerInfo(keyid, _coerce_affiliations(value, keyid), identity, note)


def _first_present(mapping, names):
    for name in names:
        if name in mapping:
            return mapping[name]
    return None


def _coerce_affiliations(value, keyid):
    if isinstance(value, str):
        values = [value]
    elif isinstance(value, (list, tuple, set, frozenset)):
        values = list(value)
    else:
        raise ValueError(
            f"affiliations for keyid '{keyid}' must be a string or a list"
        )

    for affiliation in values:
        if not isinstance(affiliation, str) or not affiliation:
            raise ValueError(
                f"affiliations for keyid '{keyid}' must be non-empty strings"
            )

    return tuple(sorted(set(values)))


def _normalize_constraints(separation_constraints, step_names):
    if separation_constraints is None:
        return []

    constraints = []
    for raw in separation_constraints:
        if isinstance(raw, SeparationConstraint):
            constraint = raw
        elif isinstance(raw, Mapping):
            steps = _first_present(raw, ("steps", "between"))
            kind = _first_present(raw, ("kind", "mode")) or "independent"
            reason = _first_present(raw, ("reason", "note")) or ""
            constraint = SeparationConstraint(
                _coerce_constraint_steps(steps), kind, reason
            )
        else:
            constraint = SeparationConstraint(
                _coerce_constraint_steps(raw), "independent"
            )

        if not isinstance(constraint.kind, str):
            raise ValueError("separation constraint kind must be a string")
        kind = _CONSTRAINT_KINDS.get(constraint.kind, constraint.kind)
        if kind not in ("affiliation", "person", "independent"):
            raise ValueError(
                f"unsupported separation constraint kind '{constraint.kind}'"
            )
        if constraint.steps[0] == constraint.steps[1]:
            raise ValueError(
                "a separation constraint must reference two different steps"
            )
        unknown = set(constraint.steps) - step_names
        if unknown:
            raise ValueError(
                "separation constraint references unknown step(s): "
                + ", ".join(sorted(unknown))
            )
        if not isinstance(constraint.reason, str):
            raise ValueError("separation constraint reason must be a string")

        constraints.append(
            SeparationConstraint(constraint.steps, kind, constraint.reason)
        )

    return constraints


def _coerce_constraint_steps(steps):
    if isinstance(steps, str) or not isinstance(steps, (list, tuple)):
        raise ValueError(
            "separation constraint steps must be a pair of step names"
        )
    if len(steps) != 2 or not all(
        isinstance(step, str) and step for step in steps
    ):
        raise ValueError(
            "separation constraint steps must be a pair of non-empty strings"
        )
    return (steps[0], steps[1])


def _collect_step_evidence(step_name, step_links, signers, explanations):
    if not isinstance(step_links, Mapping):
        raise ValueError(
            f"verified links for step '{step_name}' must be a mapping"
        )

    evidence = []
    for keyid in sorted(step_links, key=str):
        if not isinstance(keyid, str) or not keyid:
            raise ValueError(
                f"signing keyids for step '{step_name}' must be strings"
            )
        signer = signers.get(keyid)
        if signer is None or not signer.affiliations:
            evidence.append(
                {
                    "keyid": keyid,
                    "identity": signer.identity if signer else keyid,
                    "affiliations": (
                        list(signer.affiliations) if signer else []
                    ),
                    "note": signer.note if signer else "",
                    "status": "unclassified",
                    "selected_in_solutions": 0,
                    "reason": "no caller-provided affiliation",
                }
            )
            _add_explanation(
                explanations,
                f"Signer '{keyid}' for step '{step_name}' has no"
                " caller-provided affiliation; the evidence was retained but"
                " cannot be assigned to a control domain.",
            )
            continue

        evidence.append(
            {
                "keyid": keyid,
                "identity": signer.identity,
                "affiliations": list(signer.affiliations),
                "note": signer.note,
                "status": "candidate",
                "selected_in_solutions": 0,
            }
        )

    for row in evidence:
        if len(row["affiliations"]) > 1:
            _add_explanation(
                explanations,
                f"Signer '{row['keyid']}' (identity '{row['identity']}')"
                " holds multiple affiliations "
                f"({', '.join(row['affiliations'])}); each assignment may"
                " use only one of them, and the selected domain is recorded"
                " explicitly.",
            )
        if row["note"]:
            _add_explanation(
                explanations,
                f"Signer '{row['keyid']}' note retained: {row['note']}",
            )

    return evidence


def _build_step_options(step_name, threshold, evidence, signers, explanations):
    candidates = [
        signers[row["keyid"]]
        for row in evidence
        if signers.get(row["keyid"]) and signers[row["keyid"]].affiliations
    ]
    if len(candidates) < threshold:
        return []

    options = []
    for combination in itertools.combinations(candidates, threshold):
        keyids = tuple(signer.keyid for signer in combination)
        identities = tuple(signer.identity for signer in combination)
        if len(set(identities)) < threshold:
            _add_explanation(
                explanations,
                f"Step '{step_name}' evidence set {list(keyids)} resolves to"
                " fewer distinct people under caller-provided identities, so"
                " it does not satisfy the step threshold.",
            )
            continue

        common = set(combination[0].affiliations)
        for signer in combination[1:]:
            common.intersection_update(signer.affiliations)
        if not common:
            _add_explanation(
                explanations,
                f"Step '{step_name}' evidence set {list(keyids)} has no"
                " common control domain.",
            )
            continue

        options.extend(
            EvidenceOption(
                control_domain=domain,
                keyids=keyids,
                identities=identities,
                common_affiliations=tuple(sorted(common)),
            )
            for domain in sorted(common)
        )

    if len(evidence) > 1:
        _add_explanation(
            explanations,
            f"Step '{step_name}' has {len(evidence)} qualified evidence"
            f" item(s) and {len(options)} retained evidence/domain option(s);"
            " alternatives are listed in the step report.",
        )

    return options


def _step_conflict(step_name, threshold, evidence, explanations):
    classified = [row for row in evidence if row["status"] != "unclassified"]
    if len(classified) < threshold:
        reason = (
            f"step requires {threshold} distinct qualified evidence item(s)"
            f" with caller-provided affiliations, found {len(classified)}"
        )
    else:
        reason = (
            "no evidence combination has a common control domain and enough"
            " distinct people"
        )

    message = f"step '{step_name}' has no assignable role: {reason}"
    _add_explanation(explanations, message)
    return {
        "type": "step",
        "step": step_name,
        "threshold": threshold,
        "reason": reason,
        "evidence": evidence,
        "message": message,
    }


def _compatible(first, second, kind):
    if (
        kind in ("affiliation", "independent")
        and first.control_domain == second.control_domain
    ):
        return False
    return not (
        kind in ("person", "independent")
        and (
            set(first.keyids) & set(second.keyids)
            or set(first.identities) & set(second.identities)
        )
    )


def _enumerate_solutions(options_by_step, constraints, max_solutions):
    order = sorted(
        options_by_step, key=lambda name: (len(options_by_step[name]), name)
    )
    neighbours: dict[str, list[SeparationConstraint]] = {
        name: [] for name in options_by_step
    }
    for constraint in constraints:
        neighbours[constraint.steps[0]].append(constraint)
        neighbours[constraint.steps[1]].append(constraint)

    assigned: dict[str, EvidenceOption] = {}
    solutions = []
    truncated = False

    def search(index):
        nonlocal truncated
        if len(solutions) >= max_solutions:
            truncated = True
            return
        if index == len(order):
            solutions.append(dict(assigned))
            return

        step_name = order[index]
        for option in options_by_step[step_name]:
            if not _option_fits(step_name, option, assigned, neighbours):
                continue
            assigned[step_name] = option
            search(index + 1)
            del assigned[step_name]

    search(0)
    return solutions, truncated


def _option_fits(step_name, option, assigned, neighbours):
    for constraint in neighbours[step_name]:
        other = (
            constraint.steps[1]
            if constraint.steps[0] == step_name
            else constraint.steps[0]
        )
        if other not in assigned:
            continue
        if not _compatible(option, assigned[other], constraint.kind):
            return False
    return True


def _pair_conflicts(options_by_step, constraints):
    conflicts = []
    for constraint in constraints:
        first_options = options_by_step.get(constraint.steps[0], [])
        second_options = options_by_step.get(constraint.steps[1], [])
        if not first_options or not second_options:
            continue
        if any(
            _compatible(first, second, constraint.kind)
            for first in first_options
            for second in second_options
        ):
            continue

        first_domains = {option.control_domain for option in first_options}
        second_domains = {option.control_domain for option in second_options}
        shared_domains = sorted(first_domains & second_domains)
        first_keyids = {
            keyid for option in first_options for keyid in option.keyids
        }
        second_keyids = {
            keyid for option in second_options for keyid in option.keyids
        }
        shared_keyids = sorted(first_keyids & second_keyids)
        first_identities = {
            identity
            for option in first_options
            for identity in option.identities
        }
        second_identities = {
            identity
            for option in second_options
            for identity in option.identities
        }
        shared_identities = sorted(first_identities & second_identities)

        message = _constraint_message(
            constraint, shared_domains, shared_keyids, shared_identities
        )
        conflicts.append(
            {
                "type": "constraint",
                "steps": list(constraint.steps),
                "kind": constraint.kind,
                "reason": constraint.reason,
                "step_domains": {
                    constraint.steps[0]: sorted(first_domains),
                    constraint.steps[1]: sorted(second_domains),
                },
                "shared_domains": shared_domains,
                "shared_keyids": shared_keyids,
                "shared_identities": shared_identities,
                "message": message,
            }
        )
    return conflicts


def _constraint_message(
    constraint, shared_domains, shared_keyids, shared_identities
):
    steps = f"steps '{constraint.steps[0]}' and '{constraint.steps[1]}'"
    pieces = []
    if shared_domains:
        pieces.append(f"share control domain(s) {', '.join(shared_domains)}")
    if shared_keyids:
        pieces.append(f"share signer(s) {', '.join(shared_keyids)}")
    if shared_identities:
        pieces.append(
            "share identity/identities " + ", ".join(shared_identities)
        )
    if not pieces:  # pragma: no cover - defensive fallback
        pieces.append("have no compatible control-domain assignment")

    message = f"{steps} " + " and ".join(pieces)
    if constraint.reason:
        message += f" ({constraint.reason})"
    return message


def _minimal_unsat_core(options_by_step, constraints):
    core = list(constraints)
    index = 0
    while index < len(core):
        trial = core[:index] + core[index + 1 :]
        if _has_solution(options_by_step, trial):
            index += 1
        else:
            core = trial
    return core


def _has_solution(options_by_step, constraints):
    solutions, _ = _enumerate_solutions(options_by_step, constraints, 1)
    return bool(solutions)


def _constraint_set_conflict(core, layout_steps, options_by_step):
    step_order = [step.name for step in layout_steps]
    steps = [name for name in step_order if any(name in c.steps for c in core)]
    domains = {
        step: sorted(
            {option.control_domain for option in options_by_step.get(step, [])}
        )
        for step in steps
    }
    message = (
        "constraint set for "
        + ", ".join(f"'{step}'" for step in steps)
        + " cannot be satisfied together"
    )
    return {
        "type": "constraint_set",
        "steps": steps,
        "constraints": [
            {
                "steps": list(constraint.steps),
                "kind": constraint.kind,
                "reason": constraint.reason,
            }
            for constraint in core
        ],
        "step_domains": domains,
        "message": message,
    }


def _solution_usage(raw_solutions):
    usage: dict[str, Counter] = {}
    for solution in raw_solutions:
        for step_name, option in solution.items():
            counts = usage.setdefault(step_name, Counter())
            for keyid in option.keyids:
                counts[keyid] += 1
    return usage


def _annotate_evidence(evidence_by_step, options_by_step, usage):
    for step_name, evidence in evidence_by_step.items():
        option_keyids = {
            keyid
            for option in options_by_step.get(step_name, [])
            for keyid in option.keyids
        }
        counts = usage.get(step_name, Counter())
        for row in evidence:
            if row["status"] == "unclassified":
                continue
            count = counts.get(row["keyid"], 0)
            row["selected_in_solutions"] = count
            if count:
                row["status"] = "selected"
                row["reason"] = "used in at least one retained assignment"
            elif row["keyid"] in option_keyids:
                row["status"] = "eligible"
                row["reason"] = (
                    "retained as an alternative, but not used in the retained"
                    " assignment(s)"
                )
            else:
                row["status"] = "unused"
                row["reason"] = "no assignable combination or control domain"


def _step_explanations(step_name, evidence, options):
    explanations = []
    if len(evidence) > 1:
        explanations.append(
            f"Step '{step_name}' retains {len(evidence)} qualified evidence"
            f" item(s) and {len(options)} evidence/domain option(s)."
        )

    for row in evidence:
        if len(row["affiliations"]) > 1:
            explanations.append(
                f"Step '{step_name}' signer '{row['keyid']}' has multiple"
                f" affiliations ({', '.join(row['affiliations'])});"
                f" assignments using it select one domain explicitly."
            )
        if row["note"]:
            explanations.append(
                f"Step '{step_name}' signer '{row['keyid']}' note retained:"
                f" {row['note']}"
            )
    return explanations


def _serialize_solution(solution, layout_steps, signers, options_by_step):
    record = {}
    for step in layout_steps:
        option = solution[step.name]
        record[step.name] = _serialize_assignment(
            step.name,
            option,
            signers,
            len(options_by_step[step.name]),
        )
    return record


def _serialize_assignment(step_name, option, signers, option_count):
    signer_records = [
        {
            "keyid": keyid,
            "identity": signers[keyid].identity,
            "affiliations": list(signers[keyid].affiliations),
            "note": signers[keyid].note,
        }
        for keyid in option.keyids
    ]
    basis = "; ".join(
        f"{record['keyid']} (identity '{record['identity']}') is affiliated"
        f" with {', '.join(record['affiliations'])}"
        for record in signer_records
    )
    rationale = (
        f"Step '{step_name}' is assigned control domain"
        f" '{option.control_domain}' using {len(option.keyids)} distinct"
        f" signer(s); basis: {basis}."
    )
    if len(option.common_affiliations) > 1:
        rationale += (
            " The evidence set is also compatible with domain(s) "
            + ", ".join(option.common_affiliations)
            + f"; this assignment selects '{option.control_domain}'."
        )
    notes = [record["note"] for record in signer_records if record["note"]]
    if notes:
        rationale += " Caller note(s): " + "; ".join(notes)
    if option_count > 1:
        rationale += (
            f" {option_count} evidence/domain option(s) were considered for"
            " this step."
        )

    return {
        "control_domain": option.control_domain,
        "keyids": list(option.keyids),
        "identities": list(option.identities),
        "signers": signer_records,
        "basis": basis,
        "rationale": rationale,
    }


def _serialize_option(option, signers):
    return {
        "control_domain": option.control_domain,
        "keyids": list(option.keyids),
        "identities": list(option.identities),
        "common_affiliations": list(option.common_affiliations),
        "signers": [
            {
                "keyid": keyid,
                "identity": signers[keyid].identity,
                "affiliations": list(signers[keyid].affiliations),
                "note": signers[keyid].note,
            }
            for keyid in option.keyids
        ],
    }


def _add_explanation(explanations, message):
    if message not in explanations:
        explanations.append(message)
