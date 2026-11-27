# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for alternative production flow release evaluation."""

import unittest

from in_toto.attestation_policy import (
    FlowEvaluation,
    ProductionFlow,
    ReleaseDecision,
    Witness,
    WitnessBinding,
    evaluate_production_flows,
)


def make_flows():
    """Two alternative flows with partly overlapping step names."""
    flow_a = ProductionFlow(
        name="flow-a",
        required_steps={"source", "build-a", "attest-a"},
        required_witnesses={
            "source": {"source-shared"},
            "build-a": {"build-a-witness"},
            "attest-a": {"attest-a-witness"},
        },
    )
    flow_b = ProductionFlow(
        name="flow-b",
        required_steps={"source", "build-b", "attest-b"},
        required_witnesses={
            "source": {"source-shared"},
            "build-b": {"build-b-witness"},
            "attest-b": {"attest-b-witness"},
        },
    )
    return flow_a, flow_b


class TestModelValidation(unittest.TestCase):
    """Tests for witness and flow validation."""

    def test_witness_requires_binding(self):
        with self.assertRaises(ValueError):
            Witness(witness_id="w", step_name="step", flows=frozenset())

    def test_flow_rejects_witness_on_unknown_step(self):
        with self.assertRaises(ValueError):
            ProductionFlow(
                name="flow",
                required_steps={"step"},
                required_witnesses={"other": {"w"}},
            )

    def test_duplicate_flow_names_rejected(self):
        flow, _ = make_flows()
        with self.assertRaises(ValueError):
            evaluate_production_flows(
                [flow, ProductionFlow("flow-a", {"source"}, {})],
                passed_steps={"source"},
                witnesses=[],
            )

    def test_unknown_required_witness_is_reported_missing(self):
        flow_a, flow_b = make_flows()
        decision = evaluate_production_flows(
            [flow_a, flow_b],
            passed_steps=set(),
            witnesses=[],
        )
        self.assertFalse(decision.releasable)
        evaluation = decision.get_evaluation("flow-a")
        self.assertIn(("source", "source-shared"), evaluation.missing_witnesses)


class TestEvaluateProductionFlows(unittest.TestCase):
    """Tests for release decisions across alternative flows."""

    def test_both_local_samples_complete_are_releasable(self):
        flow_a, flow_b = make_flows()
        witnesses = [
            Witness("source-shared", "source", {"flow-a", "flow-b"}),
            Witness("build-a-witness", "build-a", {"flow-a"}),
            Witness("attest-a-witness", "attest-a", {"flow-a"}),
            Witness("build-b-witness", "build-b", {"flow-b"}),
            Witness("attest-b-witness", "attest-b", {"flow-b"}),
        ]
        decision = evaluate_production_flows(
            [flow_a, flow_b],
            passed_steps={
                "source",
                "build-a",
                "attest-a",
                "build-b",
                "attest-b",
            },
            witnesses=witnesses,
        )

        self.assertIsInstance(decision, ReleaseDecision)
        self.assertTrue(decision.releasable)
        self.assertEqual(decision.releasable_flows, {"flow-a", "flow-b"})

        for flow_name in ("flow-a", "flow-b"):
            evaluation = decision.get_evaluation(flow_name)
            self.assertTrue(evaluation.releasable)
            self.assertFalse(evaluation.deficiencies)
            self.assertEqual(
                {
                    binding.witness.witness_id
                    for binding in evaluation.supporting_witnesses
                },
                {
                    "source-shared",
                    f"build-{flow_name[-1]}-witness",
                    f"attest-{flow_name[-1]}-witness",
                },
            )

        source_bindings = [
            binding
            for evaluation in decision.flow_evaluations
            for binding in evaluation.supporting_witnesses
            if binding.witness.witness_id == "source-shared"
        ]
        self.assertEqual(len(source_bindings), 2)
        self.assertTrue(
            all(
                "shared across flows" in binding.reason
                for binding in source_bindings
            )
        )
        self.assertEqual(
            {binding.flow_name for binding in source_bindings},
            {"flow-a", "flow-b"},
        )

    def test_complete_flow_outputs_full_support_set(self):
        flow_a, flow_b = make_flows()
        witnesses = [
            Witness("source-shared", "source", {"flow-a", "flow-b"}),
            Witness("build-a-witness", "build-a", {"flow-a"}),
            Witness("attest-a-witness", "attest-a", {"flow-a"}, "supplier-a"),
            Witness("build-b-witness", "build-b", {"flow-b"}),
            Witness("attest-b-witness", "attest-b", {"flow-b"}),
        ]
        decision = evaluate_production_flows(
            [flow_a, flow_b],
            passed_steps={"source", "build-a", "attest-a"},
            witnesses=witnesses,
        )

        self.assertTrue(decision.releasable)
        self.assertEqual(decision.releasable_flows, {"flow-a"})

        evaluation_a = decision.get_evaluation("flow-a")
        self.assertIsInstance(evaluation_a, FlowEvaluation)
        self.assertTrue(
            all(
                isinstance(binding, WitnessBinding)
                and binding.flow_name == "flow-a"
                for binding in evaluation_a.supporting_witnesses
            )
        )
        supplier_binding = next(
            binding
            for binding in evaluation_a.supporting_witnesses
            if binding.witness.witness_id == "attest-a-witness"
        )
        self.assertEqual(supplier_binding.witness.supplier, "supplier-a")
        self.assertIn("exclusively bound", supplier_binding.reason)

    def test_missing_steps_and_witnesses_are_negative_findings(self):
        flow_a, flow_b = make_flows()
        witnesses = [
            Witness("source-shared", "source", {"flow-a", "flow-b"}),
            Witness("build-a-witness", "build-a", {"flow-a"}),
            Witness("attest-a-witness", "attest-a", {"flow-a"}),
            Witness("build-b-witness", "build-b", {"flow-b"}),
            Witness("attest-b-witness", "attest-b", {"flow-b"}),
        ]
        decision = evaluate_production_flows(
            [flow_a, flow_b],
            passed_steps={"source", "build-a", "attest-a", "build-b"},
            witnesses=witnesses,
        )

        self.assertTrue(decision.releasable)
        evaluation_b = decision.get_evaluation("flow-b")
        self.assertFalse(evaluation_b.releasable)
        self.assertTrue(evaluation_b.deficiencies)
        self.assertEqual(evaluation_b.missing_steps, {"attest-b"})
        self.assertEqual(evaluation_b.missing_witnesses, ())
        self.assertEqual(evaluation_b.conflicting_witnesses, ())

    def test_missing_step_and_missing_witness_both_reported(self):
        flow_a, flow_b = make_flows()
        witnesses = [
            Witness("source-shared", "source", {"flow-a", "flow-b"}),
            Witness("build-a-witness", "build-a", {"flow-a"}),
            Witness("attest-a-witness", "attest-a", {"flow-a"}),
            Witness("build-b-witness", "build-b", {"flow-b"}),
        ]
        decision = evaluate_production_flows(
            [flow_a, flow_b],
            passed_steps={"source", "build-a", "attest-a", "build-b"},
            witnesses=witnesses,
        )
        evaluation_b = decision.get_evaluation("flow-b")
        self.assertFalse(evaluation_b.releasable)
        self.assertEqual(evaluation_b.missing_steps, {"attest-b"})
        self.assertEqual(
            evaluation_b.missing_witnesses,
            (("attest-b", "attest-b-witness"),),
        )

    def test_mixing_flow_a_witness_cannot_sign_off_flow_b(self):
        flow_a, flow_b = make_flows()
        witnesses = [
            Witness("source-shared", "source", {"flow-a", "flow-b"}),
            Witness("build-a-witness", "build-a", {"flow-a"}),
            Witness("attest-a-witness", "attest-a", {"flow-a"}),
            # The flow-b build step is only backed by a flow-a-only witness.
            Witness("borrowed-a-witness", "build-b", {"flow-a"}),
            Witness("attest-b-witness", "attest-b", {"flow-b"}),
        ]
        decision = evaluate_production_flows(
            [flow_a, flow_b],
            passed_steps={
                "source",
                "build-a",
                "attest-a",
                "build-b",
                "attest-b",
            },
            witnesses=witnesses,
        )

        self.assertTrue(decision.releasable)
        self.assertEqual(decision.releasable_flows, {"flow-a"})

        evaluation_b = decision.get_evaluation("flow-b")
        self.assertFalse(evaluation_b.releasable)
        self.assertEqual(evaluation_b.missing_steps, frozenset())
        self.assertEqual(
            evaluation_b.missing_witnesses,
            (("build-b", "build-b-witness"),),
        )
        self.assertIn(
            ("build-b", "borrowed-a-witness", ("flow-a",)),
            evaluation_b.conflicting_witnesses,
        )

        evaluation_a = decision.get_evaluation("flow-a")
        self.assertTrue(evaluation_a.releasable)
        self.assertNotIn(
            "borrowed-a-witness",
            [
                binding.witness.witness_id
                for binding in evaluation_a.supporting_witnesses
            ],
        )

    def test_neither_flow_releasable_when_each_is_incomplete(self):
        flow_a, flow_b = make_flows()
        witnesses = [
            Witness("source-shared", "source", {"flow-a", "flow-b"}),
            Witness("build-a-witness", "build-a", {"flow-a"}),
            Witness("attest-a-witness", "attest-a", {"flow-a"}),
            Witness("build-b-witness", "build-b", {"flow-b"}),
            Witness("attest-b-witness", "attest-b", {"flow-b"}),
        ]
        decision = evaluate_production_flows(
            [flow_a, flow_b],
            passed_steps={"source", "build-a", "build-b"},
            witnesses=witnesses,
        )

        self.assertFalse(decision.releasable)
        self.assertEqual(decision.releasable_flows, frozenset())
        self.assertEqual(
            decision.get_evaluation("flow-a").missing_steps,
            {"attest-a"},
        )
        self.assertEqual(
            decision.get_evaluation("flow-b").missing_steps,
            {"attest-b"},
        )


if __name__ == "__main__":
    unittest.main()
