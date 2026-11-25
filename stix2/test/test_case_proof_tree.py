from stix2.case_proof_tree import build_proof_tree


def test_corrected_observation_requires_review_for_dependent_testimony():
    case_file = {
        "versions": {
            "observation-1": {
                "v1": {"id": "observation-1", "version": "v1"},
                "v2": {"id": "observation-1", "version": "v2"},
            },
            "testimony-only": {
                "v1": {"id": "testimony-only", "version": "v1"},
            },
            "testimony-copied": {
                "v1": {"id": "testimony-copied", "version": "v1"},
            },
            "testimony-backed": {
                "v1": {"id": "testimony-backed", "version": "v1"},
            },
            "backup-exhibit": {
                "v1": {"id": "backup-exhibit", "version": "v1"},
            },
            "unattributed-testimony": {
                "v1": {"id": "unattributed-testimony", "version": "v1"},
            },
        },
        "edges": [
            {
                "source": "testimony-only",
                "source_version": "v1",
                "target": "observation-1",
                "target_version": "v1",
                "type": "supported_by",
            },
            {
                "source": "testimony-copied",
                "source_version": "v1",
                "target": "testimony-only",
                "target_version": "v1",
                "type": "copied_from",
            },
            {
                "source": "testimony-backed",
                "source_version": "v1",
                "target": "observation-1",
                "target_version": "v1",
                "type": "supported_by",
            },
            {
                "source": "testimony-backed",
                "source_version": "v1",
                "target": "backup-exhibit",
                "target_version": "v1",
                "type": "supported_by",
            },
        ],
        "revisions": [
            {
                "statement_id": "observation-1",
                "previous_version": "v1",
                "current_version": "v2",
                "reason": "early observation date corrected",
            },
        ],
    }

    tree = build_proof_tree(case_file)

    assert tree["nodes"]["testimony-only"]["review_status"] == "must_review"
    assert tree["nodes"]["testimony-copied"]["review_status"] == "must_review"
    assert tree["nodes"]["testimony-backed"]["review_status"] == "independently_supported"
    assert tree["nodes"]["unattributed-testimony"]["review_status"] == "unknown_source"

    copied_node = tree["nodes"]["testimony-copied"]
    assert copied_node["independent_support"] == []
    assert copied_node["paths"][0]["edge_types"] == ["copied_from", "supported_by"]

    backed_paths = tree["nodes"]["testimony-backed"]["paths"]
    assert len(backed_paths) == 2
    assert backed_paths[1]["status"] == "independent"
    assert backed_paths[1]["node_refs"] == [
        ("testimony-backed", "v1"),
        ("backup-exhibit", "v1"),
    ]

    revision = tree["revisions"][0]
    assert revision["paths"]["before_correction"][0]["node_refs"] == [
        ("testimony-only", "v1"),
        ("observation-1", "v1"),
    ]
    assert revision["paths"]["after_correction"][0]["node_refs"] == [
        ("testimony-only", "v1"),
        ("observation-1", "v2"),
    ]


def test_version_binding_rejects_missing_revision_target():
    case_file = {
        "versions": {
            "claim": {"v1": {"id": "claim", "version": "v1"}},
            "source": {"v1": {"id": "source", "version": "v1"}},
        },
        "edges": [
            {
                "source": "claim",
                "source_version": "v1",
                "target": "source",
                "target_version": "v1",
                "type": "supported_by",
            },
        ],
        "revisions": [
            {
                "statement_id": "source",
                "previous_version": "v1",
                "current_version": "v2",
            },
        ],
    }

    try:
        build_proof_tree(case_file)
    except ValueError as exc:
        assert "source:v2" in str(exc)
    else:
        raise AssertionError("missing revised version must be rejected")
