from datetime import datetime, timezone

from cpe.change_adjudication import (
    STATUS_DEFERRED,
    STATUS_MANUAL_REVIEW,
    STATUS_REMEDIATION,
    adjudicate_announcements,
    export_remediation_list,
)


def _t(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _overlapping_payload():
    old_web = "cpe:2.3:a:acme:web:1.0:*:*:*:*:*:*:*"
    new_web = "cpe:2.3:a:acme:web:2.0:*:*:*:*:*:*:*"
    old_db = "cpe:2.3:a:acme:db:1.0:*:*:*:*:*:*:*"
    new_db = "cpe:2.3:a:acme:db:2.0:*:*:*:*:*:*:*"
    return {
        "assets": [
            {
                "asset_id": "edge-1",
                "inventory_at": "2026-11-20T09:00:00Z",
                "components": {
                    "frontend": old_web,
                    "database": old_db,
                },
            }
        ],
        "tickets": [
            {
                "ticket_id": "CHG-UPGRADE",
                "asset_id": "edge-1",
                "starts_at": "2026-11-20T10:00:00Z",
                "ends_at": "2026-11-20T12:00:00Z",
                "planned_cpes": [
                    "cpe:2.3:a:acme:web:*:*:*:*:*:*:*:*",
                    "cpe:2.3:a:acme:db:*:*:*:*:*:*:*:*",
                ],
            },
            {
                "ticket_id": "CHG-ROLLBACK",
                "asset_id": "edge-1",
                "starts_at": "2026-11-20T10:30:00Z",
                "ends_at": "2026-11-20T12:30:00Z",
                "previous_ticket_id": "CHG-UPGRADE",
                "planned_cpes": [
                    "cpe:2.3:a:acme:web:*:*:*:*:*:*:*:*",
                    "cpe:2.3:a:acme:db:*:*:*:*:*:*:*:*",
                ],
            },
        ],
        "announcements": [
            {
                "announcement_id": "ADV-OLD",
                "expression": "cpe:2.3:a:acme:web:1.0:*:*:*:*:*:*:*",
            }
        ],
        "observations": [
            {
                "observation_id": "up-web",
                "asset_id": "edge-1",
                "component_id": "frontend",
                "ticket_id": "CHG-UPGRADE",
                "observed_at": "2026-11-20T10:10:00Z",
                "kind": "upgrade",
                "cpe": new_web,
            },
            {
                "observation_id": "up-db",
                "asset_id": "edge-1",
                "component_id": "database",
                "ticket_id": "CHG-UPGRADE",
                "observed_at": "2026-11-20T10:15:00Z",
                "kind": "upgrade",
                "cpe": new_db,
            },
            {
                "observation_id": "rb-web",
                "asset_id": "edge-1",
                "component_id": "frontend",
                "ticket_id": "CHG-ROLLBACK",
                "previous_observation_id": "up-web",
                "observed_at": "2026-11-20T11:10:00Z",
                "kind": "rollback",
                "cpe": old_web,
            },
        ],
    }


def test_partial_rollback_returns_only_the_rolled_back_component():
    payload = _overlapping_payload()
    result = adjudicate_announcements(
        payload,
        as_of="2026-11-20T13:00:00Z",
    )

    remediation = result.remediation_list()
    assert len(remediation) == 1
    entry = remediation[0]
    assert entry["asset_id"] == "edge-1"
    assert entry["component_id"] == "frontend"
    assert entry["announcement_id"] == "ADV-OLD"
    assert entry["status"] == STATUS_REMEDIATION
    assert entry["returned_after_deferral"] is True
    assert entry["matched_expression"] == (
        "cpe:2.3:a:acme:web:1.0:*:*:*:*:*:*:*"
    )
    assert entry["matched_fields"]
    assert set(entry["deferral_ticket_ids"]) == {
        "CHG-UPGRADE",
        "CHG-ROLLBACK",
    }
    assert all(chain["chained"] for chain in result.to_dict()["evidence_chains"])


def test_observation_order_does_not_change_the_exported_list():
    payload = _overlapping_payload()
    forward = list(payload["observations"])
    reversed_observations = list(reversed(forward))

    first = payload.copy()
    first["observations"] = forward
    second = payload.copy()
    second["observations"] = reversed_observations

    assert export_remediation_list(
        first, as_of="2026-11-20T13:00:00Z"
    ) == export_remediation_list(
        second, as_of="2026-11-20T13:00:00Z"
    )


def test_alias_recorded_after_the_window_does_not_backfill_a_deferral():
    payload = {
        "assets": [
            {
                "asset_id": "legacy-1",
                "inventory_at": "2026-11-20T09:00:00Z",
                "cpe": "cpe:2.3:a:acme:legacyweb:1.0:*:*:*:*:*:*:*",
            }
        ],
        "tickets": [
            {
                "ticket_id": "CHG-LEGACY",
                "asset_id": "legacy-1",
                "starts_at": "2026-11-20T10:00:00Z",
                "ends_at": "2026-11-20T11:00:00Z",
                "planned_cpes": [
                    "cpe:2.3:a:acme:web:*:*:*:*:*:*:*:*",
                ],
            }
        ],
        "observations": [],
        "announcements": [
            {
                "announcement_id": "ADV-ALIAS",
                "expression": "cpe:2.3:a:acme:web:1.0:*:*:*:*:*:*:*",
            }
        ],
        "aliases": [
            {
                "alias_cpe": "cpe:2.3:a:acme:legacyweb:1.0:*:*:*:*:*:*:*",
                "canonical_cpe": "cpe:2.3:a:acme:web:1.0:*:*:*:*:*:*:*",
                "effective_at": "2026-11-20T09:00:00Z",
                "recorded_at": "2026-11-20T12:30:00Z",
            }
        ],
    }
    result = adjudicate_announcements(
        payload,
        as_of="2026-11-20T13:00:00Z",
    )
    remediation = result.remediation_list()
    assert len(remediation) == 1
    assert remediation[0]["status"] == STATUS_REMEDIATION
    assert remediation[0]["returned_after_deferral"] is False
    assert result.deferral_events == ()


def test_overlap_without_chain_evidence_is_left_for_a_human():
    payload = {
        "assets": [
            {
                "asset_id": "edge-2",
                "inventory_at": "2026-11-20T09:00:00Z",
                "cpe": "cpe:2.3:a:acme:web:*:*:*:*:*:*:*:*",
            }
        ],
        "tickets": [
            {
                "ticket_id": "CHG-A",
                "asset_id": "edge-2",
                "starts_at": "2026-11-20T10:00:00Z",
                "ends_at": "2026-11-20T12:00:00Z",
                "planned_cpes": ["cpe:2.3:a:acme:web:*:*:*:*:*:*:*:*"],
            },
            {
                "ticket_id": "CHG-B",
                "asset_id": "edge-2",
                "starts_at": "2026-11-20T10:30:00Z",
                "ends_at": "2026-11-20T13:00:00Z",
                "planned_cpes": ["cpe:2.3:a:acme:web:*:*:*:*:*:*:*:*"],
            },
        ],
        "observations": [],
        "announcements": [
            {
                "announcement_id": "ADV-WEB",
                "expression": "cpe:2.3:a:acme:web:*:*:*:*:*:*:*:*",
            }
        ],
    }
    result = adjudicate_announcements(
        payload,
        as_of="2026-11-20T12:15:00Z",
    )
    assert result.evidence_chains[0].status == "manual_review"
    assert result.decisions[0].status == STATUS_MANUAL_REVIEW
    assert result.remediation == ()


def test_shared_evidence_marker_chains_consecutive_changes():
    old_cpe = "cpe:2.3:a:acme:web:1.0:*:*:*:*:*:*:*"
    new_cpe = "cpe:2.3:a:acme:web:2.0:*:*:*:*:*:*:*"
    payload = {
        "assets": [
            {
                "asset_id": "edge-chain",
                "inventory_at": "2026-11-20T09:00:00Z",
                "cpe": old_cpe,
            }
        ],
        "tickets": [
            {
                "ticket_id": "CHG-C1",
                "asset_id": "edge-chain",
                "starts_at": "2026-11-20T10:00:00Z",
                "ends_at": "2026-11-20T12:00:00Z",
                "planned_cpes": ["cpe:2.3:a:acme:web:*:*:*:*:*:*:*:*"],
            },
            {
                "ticket_id": "CHG-C2",
                "asset_id": "edge-chain",
                "starts_at": "2026-11-20T10:30:00Z",
                "ends_at": "2026-11-20T13:00:00Z",
                "planned_cpes": ["cpe:2.3:a:acme:web:*:*:*:*:*:*:*:*"],
            },
        ],
        "observations": [
            {
                "observation_id": "chain-up",
                "asset_id": "edge-chain",
                "observed_at": "2026-11-20T10:10:00Z",
                "ticket_id": "CHG-C1",
                "evidence_id": "chain-001",
                "cpe": new_cpe,
            },
            {
                "observation_id": "chain-back",
                "asset_id": "edge-chain",
                "observed_at": "2026-11-20T10:40:00Z",
                "ticket_id": "CHG-C2",
                "evidence_id": "chain-001",
                "cpe": old_cpe,
            },
        ],
        "announcements": [
            {"announcement_id": "ADV-CHAIN", "expression": old_cpe}
        ],
    }
    result = adjudicate_announcements(
        payload,
        as_of="2026-11-20T12:15:00Z",
    )
    assert result.evidence_chains[0].chained is True
    assert result.decisions[0].status == STATUS_DEFERRED


def test_inventory_gap_requires_human_review_instead_of_inference():
    payload = {
        "assets": [
            {
                "asset_id": "edge-3",
                "inventory_at": "2026-11-20T09:00:00Z",
                "inventory_gaps": [
                    {
                        "starts_at": "2026-11-20T09:30:00Z",
                        "ends_at": "2026-11-20T11:00:00Z",
                    }
                ],
                "cpe": "cpe:2.3:a:acme:web:1.0:*:*:*:*:*:*:*",
            }
        ],
        "tickets": [],
        "observations": [],
        "announcements": [
            {
                "announcement_id": "ADV-GAP",
                "expression": "cpe:2.3:a:acme:web:*:*:*:*:*:*:*:*",
            }
        ],
    }
    result = adjudicate_announcements(
        payload,
        as_of="2026-11-20T10:00:00Z",
    )
    assert result.remediation == ()
    assert result.decisions[0].status == STATUS_MANUAL_REVIEW
    assert result.decisions[0].metadata["manual_reason"] == "inventory_gap"


def test_deferral_is_only_while_ticket_is_active():
    payload = _overlapping_payload()
    result = adjudicate_announcements(
        payload,
        as_of="2026-11-20T10:05:00Z",
    )
    rollout = [item for item in result.decisions if item.component_id == "frontend"]
    assert len(rollout) == 1
    assert rollout[0].status == STATUS_DEFERRED


def test_deferral_does_not_cover_an_unplanned_component():
    payload = _overlapping_payload()
    payload["tickets"] = [payload["tickets"][0]]
    payload["tickets"][0]["planned_cpes"] = [
        "cpe:2.3:a:acme:web:*:*:*:*:*:*:*:*"
    ]
    payload["announcements"] = [
        {
            "announcement_id": "ADV-DB",
            "expression": "cpe:2.3:a:acme:db:*:*:*:*:*:*:*:*",
        }
    ]

    result = adjudicate_announcements(
        payload,
        as_of="2026-11-20T10:05:00Z",
    )
    database = [item for item in result.decisions if item.component_id == "database"]
    assert database[0].status == STATUS_REMEDIATION
    assert database[0].ticket_id is None


def test_late_alias_does_not_create_a_historical_deferral():
    payload = {
        "assets": [
            {
                "asset_id": "legacy-2",
                "inventory_at": "2026-11-20T09:00:00Z",
                "cpe": "cpe:2.3:a:acme:legacyweb:1.0:*:*:*:*:*:*:*",
            }
        ],
        "tickets": [
            {
                "ticket_id": "CHG-ANY-WEB",
                "asset_id": "legacy-2",
                "starts_at": "2026-11-20T10:00:00Z",
                "ends_at": "2026-11-20T11:00:00Z",
                "planned_cpes": [
                    "cpe:2.3:a:acme:*:*:*:*:*:*:*:*",
                ],
            }
        ],
        "observations": [],
        "announcements": [
            {
                "announcement_id": "ADV-LEGACY",
                "expression": "cpe:2.3:a:acme:legacyweb:*:*:*:*:*:*:*:*",
            },
            {
                "announcement_id": "ADV-CANONICAL",
                "expression": "cpe:2.3:a:acme:web:*:*:*:*:*:*:*:*",
            },
        ],
        "aliases": [
            {
                "alias_cpe": "cpe:2.3:a:acme:legacyweb:1.0:*:*:*:*:*:*:*",
                "canonical_cpe": "cpe:2.3:a:acme:web:1.0:*:*:*:*:*:*:*",
                "effective_at": "2026-11-20T09:00:00Z",
                "recorded_at": "2026-11-20T12:30:00Z",
            }
        ],
    }

    result = adjudicate_announcements(
        payload,
        as_of="2026-11-20T13:00:00Z",
    )
    assert [event.announcement_id for event in result.deferral_events] == [
        "ADV-LEGACY"
    ]
    canonical = [
        item
        for item in result.remediation
        if item.announcement_id == "ADV-CANONICAL"
    ][0]
    assert canonical.returned_after_deferral is False


def test_auto_generated_observation_ids_are_order_independent():
    observations = [
        {
            "asset_id": "edge-9",
            "observed_at": "2026-11-20T10:10:00Z",
            "kind": "upgrade",
            "cpe": "cpe:2.3:a:acme:web:2.0:*:*:*:*:*:*:*",
        }
    ]
    payload = {
        "assets": [
            {
                "asset_id": "edge-9",
                "inventory_at": "2026-11-20T09:00:00Z",
                "cpe": "cpe:2.3:a:acme:web:1.0:*:*:*:*:*:*:*",
            }
        ],
        "tickets": [],
        "announcements": [
            {
                "announcement_id": "ADV-NEW",
                "expression": "cpe:2.3:a:acme:web:2.0:*:*:*:*:*:*:*",
            }
        ],
        "observations": observations,
    }
    forward = adjudicate_announcements(payload, as_of="2026-11-20T11:00:00Z")
    payload["observations"] = list(reversed(observations))
    backward = adjudicate_announcements(payload, as_of="2026-11-20T11:00:00Z")
    assert forward.to_dict() == backward.to_dict()


def test_payload_field_aliases_and_separate_change_observations():
    old_cpe = "cpe:2.3:a:acme:web:1.0:*:*:*:*:*:*:*"
    new_cpe = "cpe:2.3:a:acme:web:2.0:*:*:*:*:*:*:*"
    payload = {
        "as_of": "2026-11-20T12:00:00Z",
        "original_assets": [
            {
                "device_id": "edge-10",
                "inventory_at": "2026-11-20T09:00:00Z",
                "cpe": old_cpe,
            }
        ],
        "change_tickets": [
            {
                "change_id": "CHG-10",
                "device_id": "edge-10",
                "start_time": "2026-11-20T10:00:00Z",
                "end_time": "2026-11-20T11:00:00Z",
                "planned_cpes": ["cpe:2.3:a:acme:web:*:*:*:*:*:*:*:*"],
            }
        ],
        "upgrade_observations": [
            {
                "device_id": "edge-10",
                "time": "2026-11-20T10:10:00Z",
                "cpe": new_cpe,
            }
        ],
        "rollback_observations": [
            {
                "device_id": "edge-10",
                "time": "2026-11-20T10:40:00Z",
                "cpe": old_cpe,
            }
        ],
        "announcement_expressions": {
            "ADV-10": "cpe:2.3:a:acme:web:1.0:*:*:*:*:*:*:*"
        },
    }
    result = adjudicate_announcements(payload)
    assert len(result.remediation) == 1
    entry = result.remediation[0]
    assert entry.announcement_id == "ADV-10"
    assert entry.returned_after_deferral is True


def test_datetime_helpers_accept_timezone_aware_values():
    assert _t("2026-11-20T10:00:00Z").tzinfo == timezone.utc
