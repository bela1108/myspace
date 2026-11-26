import csv
import json
from pathlib import Path

from Evtx.order_review import (
    ACQUISITION_RELATION,
    PHYSICAL_ORDER,
    RECORD_CONTINUITY,
    TESTIMONY,
    WitnessStatement,
    find_minimal_witness_conflict,
    observations_from_evtx,
    review_local_order,
)
from evtx_scripts.evtx_order_review import main as order_review_main

DATA = Path(__file__).parent / "data"


def test_physical_and_continuity_relations_keep_separate_sources():
    review = review_local_order(
        observations=[
            {"node": "op-a", "acquisition": "ACQ-1", "physical_index": 0, "sequence_number": 100},
            {"node": "op-b", "acquisition": "ACQ-1", "physical_index": 1, "sequence_number": 101},
        ]
    )

    kinds = [relation.source.kind for relation in review.relations]
    assert PHYSICAL_ORDER in kinds
    assert RECORD_CONTINUITY in kinds
    assert all(relation.source.acquisition_id == "ACQ-1" for relation in review.relations)

    pair = next(pair for pair in review.ordered_pairs if pair.before == "op-a" and pair.after == "op-b")
    assert {source.kind for source in pair.sources} == {PHYSICAL_ORDER, RECORD_CONTINUITY}


def test_unknown_segments_keep_multiple_legal_orders():
    review = review_local_order(
        acquisition_relations=[
            ("start", "segment-u"),
            ("start", "segment-v"),
            ("segment-u", "end"),
            ("segment-v", "end"),
        ],
        max_legal_orders=10,
    )

    assert review.topological_generations == (
        ("start",),
        ("segment-u", "segment-v"),
        ("end",),
    )
    assert set(review.legal_orders) == {
        ("start", "segment-u", "segment-v", "end"),
        ("start", "segment-v", "segment-u", "end"),
    }
    assert ("segment-u", "segment-v") in review.incomparable_pairs


def test_reused_sequence_edge_does_not_override_explicit_acquisition_relation():
    review = review_local_order(
        acquisition_relations=[
            {
                "before": "reused-block",
                "after": "known-operation",
                "source": {"kind": ACQUISITION_RELATION, "source_id": "custody-manifest-row-7"},
            }
        ],
        evidence_relations=[
            {
                "before": "known-operation",
                "after": "reused-block",
                "source": {
                    "kind": RECORD_CONTINUITY,
                    "source_id": "seq-5-6",
                    "reused_sequence": True,
                },
            }
        ],
    )

    assert [(relation.before, relation.after) for relation in review.relations] == [("reused-block", "known-operation")]
    rejected = review.rejected_relations[0]
    assert rejected.reason == "reused_sequence_cannot_override_acquisition_relation"
    assert "custody-manifest-row-7" in json.dumps(rejected.as_dict(), ensure_ascii=False)


def test_consistent_reused_sequence_remains_provisional_not_hard_order():
    review = review_local_order(
        acquisition_relations=[("op-a", "op-b")],
        evidence_relations=[
            {
                "before": "op-a",
                "after": "op-b",
                "source": {"kind": RECORD_CONTINUITY, "reused_sequence": True},
            }
        ],
    )

    assert [(relation.before, relation.after) for relation in review.relations] == [("op-a", "op-b")]
    assert len(review.provisional_relations) == 1
    assert review.ordered_pairs[0].relation_ids == (review.relations[0].relation_id,)


def test_opposite_witness_claims_form_one_minimal_pair():
    review = review_local_order(
        witnesses=[
            WitnessStatement("op-1", "op-2", "W-1"),
            WitnessStatement("op-2", "op-1", "W-2"),
        ]
    )

    assert review.witness_conflict is not None
    assert review.witness_conflict.statement_ids == ("W-1", "W-2")
    source_kinds = {relation.source.kind for edge in review.witness_conflict.edges for relation in edge.relations}
    assert source_kinds == {TESTIMONY}


def test_hard_order_makes_one_witness_statement_minimal_conflict():
    review = review_local_order(
        observations=[
            {"node": "op-1", "acquisition": "ACQ-1", "physical_index": 0},
            {"node": "op-2", "acquisition": "ACQ-1", "physical_index": 1},
        ],
        witnesses=[{"statement_id": "W-BAD", "before": "op-2", "after": "op-1"}],
    )

    assert review.witness_conflict is not None
    assert review.witness_conflict.statement_ids == ("W-BAD",)
    kinds = [relation.source.kind for edge in review.witness_conflict.edges for relation in edge.relations]
    assert PHYSICAL_ORDER in kinds
    assert TESTIMONY in kinds


def test_witness_chain_conflict_requires_both_claims():
    hard = review_local_order(acquisition_relations=[("op-3", "op-1")])
    conflict = find_minimal_witness_conflict(
        hard.relations,
        [
            {"statement_id": "W-1", "before": "op-1", "after": "op-2"},
            {"statement_id": "W-2", "before": "op-2", "after": "op-3"},
        ],
    )

    assert conflict is not None
    assert conflict.statement_ids == ("W-1", "W-2")
    assert any(relation.source.kind == ACQUISITION_RELATION for edge in conflict.edges for relation in edge.relations)


def test_chinese_witness_table_headers_are_supported(tmp_path: Path):
    table = tmp_path / "witnesses.csv"
    with table.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["编号", "先发生", "后发生", "证人"])
        writer.writerow(["证言甲", "操作一", "操作二", "值班员"])

    from Evtx.order_review import load_witness_table

    rows = load_witness_table(table)
    review = review_local_order(witnesses=rows)
    statement = review.witness_conflict is None
    assert statement is True
    assert rows[0]["证人"] == "值班员"
    normalized = review_local_order(witnesses=rows).as_dict()["inconsistent_witness_statements"]
    assert normalized["statement_ids"] == []


def test_real_evtx_one_chunk_acquisitions_are_occurrence_scoped():
    fixture = DATA / "issue_38.evtx"
    observations = observations_from_evtx(fixture, "ACQ-A")
    assert len(observations) == 1
    assert observations[0].acquisition_id == "ACQ-A"
    assert observations[0].sequence_number == 1

    review = review_local_order(
        observations=[
            *observations_from_evtx(fixture, "ACQ-A", node_map={"ACQ-A:1": "op-1"}),
            *observations_from_evtx(fixture, "ACQ-B", node_map={"ACQ-B:1": "op-2"}),
            *observations_from_evtx(fixture, "ACQ-C", node_map={"ACQ-C:1": "op-3"}),
        ],
        witnesses=[("op-1", "op-2", "W-1"), ("op-2", "op-1", "W-2")],
    )
    assert review.nodes == ("op-1", "op-2", "op-3")
    assert review.witness_conflict.statement_ids == ("W-1", "W-2")


def test_dns_fixture_adapter_reads_physical_chain():
    observations = observations_from_evtx(DATA / "dns_log_malformed.evtx", "DNS")
    assert [item.sequence_number for item in observations] == [1, 2, 3, 4, 5]
    review = review_local_order(observations=observations)
    assert len([r for r in review.relations if r.source.kind == PHYSICAL_ORDER]) == 4
    assert len([r for r in review.relations if r.source.kind == RECORD_CONTINUITY]) == 4


def test_cli_outputs_investigator_json(tmp_path: Path):
    observations = tmp_path / "observations.json"
    observations.write_text(
        json.dumps(
            [
                {"node": "a", "acquisition": "A", "physical_index": 0},
                {"node": "b", "acquisition": "A", "physical_index": 1},
            ]
        ),
        encoding="utf-8",
    )
    witnesses = tmp_path / "witnesses.json"
    witnesses.write_text(
        json.dumps([{"statement_id": "bad", "before": "b", "after": "a"}]),
        encoding="utf-8",
    )
    output = tmp_path / "report.json"

    exit_code = order_review_main(
        [
            "--observations",
            str(observations),
            "--witnesses",
            str(witnesses),
            "--format",
            "json",
            "--output",
            str(output),
        ]
    )
    assert exit_code == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert set(report) == {"still_valid_partial_order", "inconsistent_witness_statements"}
    assert report["inconsistent_witness_statements"]["statement_ids"] == ["bad"]
