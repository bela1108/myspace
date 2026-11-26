# -*- coding: utf-8 -*-
from cpe.adjudication_api import (
    export_remediation_list,
    run_adjudication,
    solve,
)

OLD_WEB = "cpe:2.3:a:acme:web:1.0:*:*:*:*:*:*:*"
NEW_WEB = "cpe:2.3:a:acme:web:2.0:*:*:*:*:*:*:*"
OLD_DB = "cpe:2.3:a:acme:db:1.0:*:*:*:*:*:*:*"
NEW_DB = "cpe:2.3:a:acme:db:2.0:*:*:*:*:*:*:*"


def _assets():
    return [
        {
            "asset_id": "edge-1",
            "inventory_at": "2026-11-20T09:00:00Z",
            "components": {"frontend": OLD_WEB, "database": OLD_DB},
        },
        {
            "asset_id": "edge-2",
            "inventory_at": "2026-11-20T09:00:00Z",
            "components": {"frontend": OLD_WEB},
        },
    ]


def _tickets():
    planned_web = ["cpe:2.3:a:acme:web:*:*:*:*:*:*:*:*"]
    return [
        {
            "ticket_id": "CHG-A",
            "asset_id": "edge-1",
            "starts_at": "2026-11-20T10:00:00Z",
            "ends_at": "2026-11-20T12:00:00Z",
            "planned_cpes": [
                "cpe:2.3:a:acme:web:*:*:*:*:*:*:*:*",
                "cpe:2.3:a:acme:db:*:*:*:*:*:*:*:*",
            ],
        },
        {
            "ticket_id": "CHG-B",
            "asset_id": "edge-2",
            "starts_at": "2026-11-20T10:30:00Z",
            "ends_at": "2026-11-20T12:30:00Z",
            "planned_cpes": planned_web,
        },
    ]


def _upgrades():
    return [
        {
            "observation_id": "up-web-1",
            "asset_id": "edge-1",
            "component_id": "frontend",
            "ticket_id": "CHG-A",
            "observed_at": "2026-11-20T10:10:00Z",
            "cpe": NEW_WEB,
        },
        {
            "observation_id": "up-db-1",
            "asset_id": "edge-1",
            "component_id": "database",
            "ticket_id": "CHG-A",
            "observed_at": "2026-11-20T10:15:00Z",
            "cpe": NEW_DB,
        },
        {
            "observation_id": "up-web-2",
            "asset_id": "edge-2",
            "component_id": "frontend",
            "ticket_id": "CHG-B",
            "observed_at": "2026-11-20T10:40:00Z",
            "cpe": NEW_WEB,
        },
    ]


def _rollbacks():
    return [
        {
            "observation_id": "rb-web-1",
            "asset_id": "edge-1",
            "component_id": "frontend",
            "ticket_id": "CHG-A",
            "previous_observation_id": "up-web-1",
            "observed_at": "2026-11-20T11:10:00Z",
            "cpe": OLD_WEB,
        }
    ]


def _expressions():
    return [
        {"announcement_id": "ADV-WEB", "expression": OLD_WEB},
        {"announcement_id": "ADV-DB", "expression": OLD_DB},
    ]


def test_split_observations_and_shuffled_export_match():
    forward = export_remediation_list(
        _assets(),
        _tickets(),
        upgrade_observations=_upgrades(),
        rollback_observations=_rollbacks(),
        announcement_expressions=_expressions(),
        as_of="2026-11-20T13:00:00Z",
    )

    shuffled_upgrades = list(reversed(_upgrades()))
    shuffled_rollbacks = list(reversed(_rollbacks()))
    backward = export_remediation_list(
        announcement_expressions=_expressions(),
        rollback_observations=shuffled_rollbacks,
        upgrade_observations=shuffled_upgrades,
        change_tickets=list(reversed(_tickets())),
        original_assets=list(reversed(_assets())),
        as_of="2026-11-20T13:00:00Z",
    )

    assert forward == backward
    assert len(forward) == 1
    entry = forward[0]
    assert entry["asset_id"] == "edge-1"
    assert entry["component_id"] == "frontend"
    assert entry["announcement_id"] == "ADV-WEB"
    assert entry["returned_after_deferral"] is True
    assert entry["matched_expression"] == OLD_WEB
    assert entry["matched_fields"]
    assert entry["triggered_match"]["matched_expression"] == OLD_WEB
    assert entry["trigger"]["observation_ids"]


def test_positional_split_call_and_solve_report():
    result = run_adjudication(
        _assets(),
        _tickets(),
        _upgrades(),
        _rollbacks(),
        {"ADV-WEB": OLD_WEB, "ADV-DB": OLD_DB},
        as_of="2026-11-20T13:00:00Z",
    )
    assert len(result.remediation) == 1

    report = solve(
        {
            "original_assets": _assets(),
            "change_tickets": _tickets(),
            "upgrade_observations": _upgrades(),
            "rollback_observations": _rollbacks(),
            "announcement_expressions": {"ADV-WEB": OLD_WEB},
            "as_of": "2026-11-20T13:00:00Z",
        }
    )
    assert isinstance(report, list)
    assert len(report) == 1
    assert report.result.remediation_list() == list(report)
    assert report[0]["triggered_match"]["announcement_id"] == "ADV-WEB"


def test_flat_device_time_keys_work():
    payload = {
        "as_of": "2026-11-20T12:00:00Z",
        "original_assets": [
            {"device_id": "edge-10", "inventory_at": "2026-11-20T09:00:00Z", "cpe": OLD_WEB}
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
            {"observation_id": "up-10", "device_id": "edge-10", "time": "2026-11-20T10:10:00Z", "cpe": NEW_WEB}
        ],
        "rollback_observations": [
            {"previous_observation_id": "up-10", "device_id": "edge-10", "time": "2026-11-20T10:40:00Z", "cpe": OLD_WEB}
        ],
        "announcement_expressions": {"ADV-10": OLD_WEB},
    }
    result = run_adjudication(payload)
    assert len(result.remediation) == 1
    assert result.remediation[0].returned_after_deferral is True
