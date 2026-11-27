# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Evaluate alternative production flows against passed in-toto steps.

An audit sheet may permit more than one production flow.  Each flow names
the in-toto steps that must have passed and the supplier testimony that is
bound to those steps.  A product may only be released when at least one flow
is fully supported by the available attestations.  Attestations from
different flows must never be mixed to make up a single flow.

The evaluator is deliberately data-driven: it does not verify signatures or
artifact rules itself but consumes the set of steps that already passed
in-toto verification together with the recorded witnesses.  For every flow
it reports the complete set of supporting witnesses (positive case) or the
exact missing pieces and mutually exclusive attestations (negative case).
"""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Witness:
    """Supplier testimony recorded for an in-toto step.

    Attributes:
      witness_id: Unique identifier of the testimony, e.g. a link file name.
      step_name: The in-toto step the testimony was recorded for.
      flows: Flows this testimony may support.  A witness may be shared by
          multiple flows, in which case the binding to each flow is kept
          explicitly so the rationale can be reported back.
      supplier: Optional identifier of the supplier who provided testimony.

    """

    witness_id: str
    step_name: str
    flows: frozenset
    supplier: str = ""

    def __post_init__(self):
        if not self.witness_id:
            raise ValueError("'witness_id' must not be empty")
        if not self.step_name:
            raise ValueError("'step_name' must not be empty")
        if not self.flows:
            raise ValueError("'flows' must bind the witness to a flow")
        object.__setattr__(self, "flows", frozenset(self.flows))

    def supports(self, flow_name):
        """Return whether this witness is bound to the given flow."""
        return flow_name in self.flows


@dataclass(frozen=True)
class ProductionFlow:
    """One alternative production flow on the audit sheet.

    Attributes:
      name: Unique flow identifier.
      required_steps: in-toto steps that must have passed for this flow.
      required_witnesses: Mapping of step name to the witness ids that
          provide the supplier testimony required for that step.

    """

    name: str
    required_steps: frozenset
    required_witnesses: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.name:
            raise ValueError("flow 'name' must not be empty")
        object.__setattr__(
            self, "required_steps", frozenset(self.required_steps)
        )
        object.__setattr__(
            self,
            "required_witnesses",
            {
                step: frozenset(ids)
                for step, ids in self.required_witnesses.items()
            },
        )

        unknown = set(self.required_witnesses) - self.required_steps
        if unknown:
            raise ValueError(
                f"flow {self.name!r} requires witnesses for unknown steps: "
                f"{sorted(unknown)}"
            )

    @property
    def witness_requirements(self):
        """Yield ``(step_name, witness_id)`` pairs required by the flow."""
        for step_name in sorted(self.required_witnesses):
            for witness_id in sorted(self.required_witnesses[step_name]):
                yield step_name, witness_id


@dataclass(frozen=True)
class WitnessBinding:
    """A witness together with the reason it supports a flow.

    Attributes:
      witness: The reusable witness attestation.
      flow_name: The flow the witness is bound to in this evaluation.
      reason: Human-readable binding rationale.

    """

    witness: Witness
    flow_name: str
    reason: str


@dataclass(frozen=True)
class FlowEvaluation:
    """Result of evaluating one alternative production flow.

    Attributes:
      flow_name: Identifier of the evaluated flow.
      releasable: Whether the flow may be released on its own.
      supporting_witnesses: Complete witness set backing the flow when it
          is releasable, including the binding reason for shared witnesses.
      missing_steps: Passed steps required by the flow but not available.
      missing_witnesses: ``(step_name, witness_id)`` pairs for supplier
          testimony that is absent or not bound to this flow.
      conflicting_witnesses: Witnesses present for a required step but
          bound to a different, mutually exclusive flow.

    """

    flow_name: str
    releasable: bool
    supporting_witnesses: tuple = ()
    missing_steps: frozenset = frozenset()
    missing_witnesses: tuple = ()
    conflicting_witnesses: tuple = ()

    @property
    def deficiencies(self):
        """True if the flow reports any missing or conflicting evidence."""
        return bool(
            self.missing_steps
            or self.missing_witnesses
            or self.conflicting_witnesses
        )


@dataclass(frozen=True)
class ReleaseDecision:
    """Aggregated decision across all alternative production flows.

    Attributes:
      releasable: Whether at least one flow is fully supported.
      releasable_flows: Names of flows that may be released.
      flow_evaluations: Per-flow positive support sets or negative findings.

    """

    releasable: bool
    releasable_flows: frozenset
    flow_evaluations: tuple

    def get_evaluation(self, flow_name):
        """Return the evaluation for the named flow."""
        for evaluation in self.flow_evaluations:
            if evaluation.flow_name == flow_name:
                return evaluation
        raise KeyError(flow_name)


def _index_witnesses(witnesses):
    """Index witnesses by id and by step for conflict detection."""
    by_id = {}
    by_step = {}
    for witness in witnesses:
        if witness.witness_id in by_id:
            raise ValueError(f"duplicate witness id: {witness.witness_id!r}")
        by_id[witness.witness_id] = witness
        by_step.setdefault(witness.step_name, []).append(witness)
    return by_id, by_step


def _binding_reason(witness, flow_name):
    """Build the rationale for binding a witness to a flow."""
    shared = sorted(witness.flows)
    if len(shared) == 1:
        return (
            f"witness {witness.witness_id!r} is exclusively bound to flow "
            f"{flow_name!r} for step {witness.step_name!r}"
        )
    return (
        f"witness {witness.witness_id!r} is shared across flows {shared} and "
        f"bound to flow {flow_name!r} for step {witness.step_name!r}"
    )


def _find_conflicts(flow, missing_steps, witnesses_by_step):
    """Return witnesses bound to other flows for available required steps."""
    conflicts = []
    for step_name in flow.required_steps - missing_steps:
        step_witnesses = witnesses_by_step.get(step_name, [])
        conflicts.extend(
            (
                step_name,
                witness.witness_id,
                tuple(sorted(witness.flows)),
            )
            for witness in step_witnesses
            if not witness.supports(flow.name)
        )
    return tuple(sorted(set(conflicts)))


def _evaluate_flow(flow, passed_steps, witnesses_by_id, witnesses_by_step):
    """Evaluate a single flow against passed steps and witnesses."""
    missing_steps = frozenset(
        step_name
        for step_name in flow.required_steps
        if step_name not in passed_steps
    )

    supporting = []
    missing_witnesses = []
    for step_name, witness_id in flow.witness_requirements:
        witness = witnesses_by_id.get(witness_id)
        if witness is None:
            missing_witnesses.append((step_name, witness_id))
            continue

        if witness.step_name != step_name:
            raise ValueError(
                f"witness {witness_id!r} is recorded for step "
                f"{witness.step_name!r} but flow {flow.name!r} requires it "
                f"for step {step_name!r}"
            )

        if witness.supports(flow.name):
            supporting.append(
                WitnessBinding(
                    witness=witness,
                    flow_name=flow.name,
                    reason=_binding_reason(witness, flow.name),
                )
            )
        else:
            missing_witnesses.append((step_name, witness_id))

    if not missing_steps and not missing_witnesses:
        return FlowEvaluation(
            flow_name=flow.name,
            releasable=True,
            supporting_witnesses=tuple(supporting),
        )

    return FlowEvaluation(
        flow_name=flow.name,
        releasable=False,
        missing_steps=missing_steps,
        missing_witnesses=tuple(sorted(set(missing_witnesses))),
        conflicting_witnesses=_find_conflicts(
            flow, missing_steps, witnesses_by_step
        ),
    )


def evaluate_production_flows(flows, passed_steps, witnesses):
    """Determine which alternative production flows may be released.

    A flow is releasable only if every required in-toto step passed and
    every required supplier testimony is provided by a witness explicitly
    bound to that flow.  A witness may be bound to several flows, but a
    witness that is only bound to another flow can never be borrowed: it is
    reported as a mutually exclusive conflict rather than counted as
    support.

    Arguments:
      flows: Iterable of ``ProductionFlow`` alternatives.
      passed_steps: Iterable of names of in-toto steps that passed.
      witnesses: Iterable of available ``Witness`` attestations.

    Returns:
      A ``ReleaseDecision`` with a positive, complete support set for each
      releasable flow and missing steps, missing testimony or conflicts for
      each flow that cannot be signed off.

    Raises:
      ValueError: If flow names or witness ids are duplicated, or a known
          witness is required for a step it was not recorded for.

    """
    flows = tuple(flows)
    flow_names = [flow.name for flow in flows]
    if len(flow_names) != len(set(flow_names)):
        raise ValueError("production flow names must be unique")

    passed_steps = frozenset(passed_steps)
    witnesses_by_id, witnesses_by_step = _index_witnesses(witnesses)

    evaluations = [
        _evaluate_flow(flow, passed_steps, witnesses_by_id, witnesses_by_step)
        for flow in flows
    ]

    releasable_flows = frozenset(
        evaluation.flow_name
        for evaluation in evaluations
        if evaluation.releasable
    )
    return ReleaseDecision(
        releasable=bool(releasable_flows),
        releasable_flows=releasable_flows,
        flow_evaluations=tuple(evaluations),
    )
