"""Fictional control-cabinet payload used by the local query demo."""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Dict


def demo_payload() -> Dict[str, Any]:
    """Return one fictional cabinet and one snapshot for each control app slot."""
    return deepcopy(_PAYLOAD)


_PAYLOAD: Dict[str, Any] = {
    "query_id": "fictional-cabinet-CAB-047-two-snapshots",
    "cabinet": {
        "cabinet_id": "CAB-FICTION-047",
        "host_id": "HOST-CTRL-047",
        "host_owner": "platform-control-team",
        "common_snapshot_id": "HOST-INV-20261125",
        "common_components": [
            {
                "component_id": "inst-host-edge-bus",
                "cpe": "cpe:2.3:a:mockcontrols:edge_bus:1.8.2:*:*:*:*:*:*:*",
                "version": "1.8.2",
                "digest": "sha256:demo-common-bus-182",
                "path": "/opt/edge-bus",
                "owner": "platform-control-team",
            }
        ],
    },
    "advisories": [
        {
            "advisory_id": "ADV-CTRL-047",
            "title": "Fictional chained control-runtime exposure",
            "severity": "high",
            "operator": "all",
            "conditions": [
                {
                    "id": "common-bus-dependency",
                    "scope": "host_common",
                    "cpe": "cpe:2.3:a:mockcontrols:edge_bus:1.8.2:*:*:*:*:*:*:*",
                    "version_constraint": "<1.8.3",
                    "role": "shared_dependency",
                    "description_zh": "控制柜主机上的公共通信总线依赖。",
                },
                {
                    "id": "strict-slot-runtime",
                    "scope": "slot_strict",
                    "cpe": "cpe:2.3:a:mockcontrols:slot_runtime:4.0.7:*:*:*:*:*:*:*",
                    "version_constraint": "<4.1.0",
                    "role": "vulnerable_slot_component",
                    "description_zh": "严格属于当前控制应用槽的运行时部件。",
                },
            ],
        },
        {
            "advisory_id": "ADV-BUS-048",
            "title": "Fictional shared edge-bus exposure",
            "severity": "critical",
            "operator": "all",
            "conditions": [
                {
                    "id": "host-common-bus",
                    "scope": "host_common",
                    "cpe": "cpe:2.3:a:mockcontrols:edge_bus:1.8.2:*:*:*:*:*:*:*",
                    "version_constraint": "<1.8.3",
                    "description_zh": "仅指向主机公共组件的公告条件。",
                }
            ],
        },
    ],
    "snapshots": [
        {
            "snapshot_id": "SNAP-PLC-20261125-FIXED",
            "slot_id": "plc-control",
            "slot_owner": "plc-app-team",
            "application": "Fictional PLC Control",
            "host_id": "HOST-CTRL-047",
            "captured_at": "2026-11-25T01:30:00+08:00",
            "components": [
                {
                    "component_id": "inst-plc-runtime",
                    "cpe": "cpe:2.3:a:mockcontrols:slot_runtime:4.1.0:*:*:*:*:*:*:*",
                    "version": "4.1.0",
                    "digest": "sha256:demo-plc-runtime-410-fixed",
                    "path": "/opt/apps/plc/runtime",
                    "owner": "plc-app-team",
                }
            ],
        },
        {
            "snapshot_id": "SNAP-HMI-20261125-VULNERABLE",
            "slot_id": "hmi-control",
            "slot_owner": "hmi-app-team",
            "application": "Fictional HMI Control",
            "host_id": "HOST-CTRL-047",
            "captured_at": "2026-11-25T01:35:00+08:00",
            "components": [
                {
                    "component_id": "inst-hmi-runtime",
                    "cpe": "cpe:2.3:a:mockcontrols:slot_runtime:4.0.7:*:*:*:*:*:*:*",
                    "version": "4.0.7",
                    "digest": "sha256:demo-hmi-runtime-407-vulnerable",
                    "path": "/opt/apps/hmi/runtime",
                    "owner": "hmi-app-team",
                }
            ],
        },
    ],
    "closure_requests": [
        {
            "advisory_id": "ADV-CTRL-047",
            "slot_id": "plc-control",
            "closed_by": "plc-app-team",
            "closed_at": "2026-11-25T02:00:00+08:00",
            "disposition": "patched",
            "reason_zh": "PLC 槽已升级到 4.1.0；严格本槽条件不再满足。",
        }
    ],
    "evidence_supplements": [
        {
            "advisory_id": "ADV-CTRL-047",
            "scope": "slot_strict",
            "slot_id": "hmi-control",
            "submitted_by": "hmi-engineer-on-site",
            "closed_by": "hmi-app-team",
            "closed_at": "2026-11-25T03:10:00+08:00",
            "reason_zh": "HMI 单槽补证：已替换为 4.1.0 并留存新摘要。",
            "component": {
                "component_id": "inst-hmi-runtime",
                "cpe": "cpe:2.3:a:mockcontrols:slot_runtime:4.1.0:*:*:*:*:*:*:*",
                "version": "4.1.0",
                "digest": "sha256:demo-hmi-runtime-410-supplemented",
                "path": "/opt/apps/hmi/runtime",
                "owner": "hmi-app-team",
            },
        },
        {
            "advisory_id": "ADV-BUS-048",
            "scope": "host_common",
            "submitted_by": "plc-engineer-shared-evidence",
            "closed_by": "platform-control-team",
            "closed_at": "2026-11-25T03:20:00+08:00",
            "reason_zh": "一个槽提交的公共总线升级证据经主机平台方确认。",
            "component": {
                "component_id": "inst-host-edge-bus",
                "cpe": "cpe:2.3:a:mockcontrols:edge_bus:1.8.3:*:*:*:*:*:*:*",
                "version": "1.8.3",
                "digest": "sha256:demo-common-bus-183-fixed",
                "path": "/opt/edge-bus",
                "owner": "platform-control-team",
            },
        },
    ],
    "migrations": [
        {
            "migration_id": "MIG-PLC-R2",
            "from_slot_id": "plc-control",
            "to_slot_id": "plc-control-r2",
            "advisory_id": "ADV-CTRL-047",
            "new_snapshot": {
                "snapshot_id": "SNAP-PLC-R2-20261125",
                "slot_id": "plc-control-r2",
                "slot_owner": "plc-r2-app-team",
                "application": "Fictional PLC Control R2",
                "host_id": "HOST-CTRL-047",
                "captured_at": "2026-11-25T04:00:00+08:00",
                "components": [
                    {
                        "component_id": "inst-plc-r2-runtime",
                        "cpe": "cpe:2.3:a:mockcontrols:slot_runtime:4.1.0:*:*:*:*:*:*:*",
                        "version": "4.1.0",
                        "digest": "sha256:demo-plc-r2-runtime-410-new-slot",
                        "path": "/opt/apps/plc-r2/runtime",
                        "owner": "plc-r2-app-team",
                    }
                ],
            },
            "closure_request": {
                "advisory_id": "ADV-CTRL-047",
                "closed_by": "plc-r2-app-team",
                "closed_at": "2026-11-25T04:10:00+08:00",
                "disposition": "migrated-and-reverified",
                "reason_zh": "新槽已重新扫描并见证 4.1.0 部件身份。",
            },
        }
    ],
}
