from stix2.markings.disclosure import (
    PUBLIC,
    RESTRICTED,
    UNKNOWN,
    propagate_disclosure,
)


def three_layer_graph_with_cycle():
    return {
        "root": "report",
        "nodes": [
            {"id": "report", "case_id": "case-a", "markers": ["TLP:AMBER"]},
            {"id": "middle", "case_id": "case-a"},
            {"id": "leaf", "case_id": "case-a"},
        ],
        "edges": [
            {"source": "report", "target": "middle", "ref": "object_refs"},
            {"source": "middle", "target": "leaf", "ref": "object_refs"},
            {"source": "leaf", "target": "middle", "ref": "related_ref"},
        ],
    }


def test_three_layers_reach_fixed_point_and_report_cycle_boundary():
    result = propagate_disclosure(three_layer_graph_with_cycle())

    assert result.stable is True
    assert result.limit_reached is None
    assert result.cycles == [["middle", "leaf", "middle"]]
    assert result.states["middle"].verdict == RESTRICTED
    assert result.states["leaf"].verdict == RESTRICTED
    assert "TLP:AMBER" in result.states["leaf"].markers
    assert result.first_over_limit_edge is None
    closing_edge = result.stable_boundary["edges"][-1]
    assert closing_edge["source"] == "leaf"
    assert closing_edge["target"] == "middle"
    assert closing_edge["cycle_closing"] is True


def test_depth_limit_reports_stable_boundary_and_first_over_limit_edge():
    result = propagate_disclosure(
        three_layer_graph_with_cycle(),
        max_depth=2,
    )

    assert result.stable is True
    assert result.iterations == 3
    assert result.cycles == [["middle", "leaf", "middle"]]

    overflow = result.first_over_limit_edge
    assert overflow is not None
    assert overflow["index"] == 2
    assert overflow["source"] == "leaf"
    assert overflow["target"] == "middle"
    assert overflow["limit_type"] == "depth"
    assert overflow["observed_depth"] == 3
    assert overflow["cycle_closing"] is True
    assert result.stable_boundary["cycle"] == ["middle", "leaf", "middle"]
    assert result.stable_boundary["frontier_nodes"] == ["leaf"]


def test_unknown_is_not_treated_as_public():
    result = propagate_disclosure(
        nodes=[{"id": "unlabeled"}, {"id": "referenced"}],
        edges=[("unlabeled", "referenced")],
        root="unlabeled",
    )

    assert result.states["unlabeled"].verdict == UNKNOWN
    assert result.states["referenced"].verdict == UNKNOWN
    assert result.public_node_ids == []

    tainted = propagate_disclosure(
        nodes=[
            {"id": "unknown_source", "unknown": True},
            {"id": "public_target", "public": True},
        ],
        edges=[("unknown_source", "public_target")],
        root="unknown_source",
    )
    assert tainted.states["public_target"].verdict == UNKNOWN
    assert tainted.public_node_ids == []

    public = propagate_disclosure(
        nodes=[{"id": "a", "public": True}, {"id": "b", "public": True}],
        edges=[("a", "b")],
        root="a",
    )
    assert public.states["b"].verdict == PUBLIC
    assert public.public_node_ids == ["a", "b"]


def test_cross_case_transfer_is_blocked_by_default():
    graph = {
        "root": "report",
        "nodes": [
            {"id": "report", "case_id": "case-a", "markers": ["CASE-A"]},
            {"id": "external", "case_id": "case-b"},
        ],
        "edges": [("report", "external", "object_refs")],
    }

    blocked = propagate_disclosure(graph)
    assert len(blocked.cross_case_edges) == 1
    assert blocked.first_over_limit_edge["limit_type"] == "cross_case"
    assert blocked.states["external"].depth is None
    assert "CASE-A" not in blocked.states["external"].markers
    assert blocked.states["external"].case_ids == {"case-b"}

    allowed = propagate_disclosure(graph, cross_case_policy="allow")
    assert allowed.states["external"].depth == 1
    assert "CASE-A" in allowed.states["external"].markers
    assert allowed.states["external"].case_ids == {"case-a", "case-b"}


def test_node_budget_reports_first_node_overflow_edge():
    result = propagate_disclosure(
        three_layer_graph_with_cycle(),
        max_nodes=2,
    )

    overflow = result.first_over_limit_edge
    assert overflow["limit_type"] == "nodes"
    assert overflow["index"] == 1
    assert overflow["source"] == "middle"
    assert overflow["target"] == "leaf"
    assert result.states["leaf"].depth is None
