# -*- coding: utf-8 -*-

from cpe.orchestration import (
    Device,
    MaintenanceWindow,
    PlatformExpression,
    PlatformStatus,
    Reason,
    build_schedule,
)

import json
import unittest


EXPRESSION = json.dumps([
    {
        "operator": "OR",
        "children": [],
        "cpe_match": [
            {"cpe23Uri": "cpe:2.3:a:acme:nodegrid:*:*:*:*:*:*:*:*"},
        ],
    },
])


def make_device(device_id, version, group=None,
                status=PlatformStatus.CONFIRMED, product="nodegrid"):
    cpe = "cpe:2.3:a:acme:{0}:{1}:*:*:*:*:*:*:*".format(product, version)
    return Device(device_id, cpe, redundancy_group=group,
                  platform_status=status)


class PlatformExpressionTest(unittest.TestCase):
    """
    Check offline evaluation of the platform expression.
    """

    def test_matches_product_family(self):
        expr = PlatformExpression(EXPRESSION)
        assert expr.matches("cpe:2.3:a:acme:nodegrid:1.2.1:*:*:*:*:*:*:*")
        assert expr.matches("cpe:2.3:a:acme:nodegrid:9.9.9:*:*:*:*:*:*:*")

    def test_rejects_other_products(self):
        expr = PlatformExpression(EXPRESSION)
        assert not expr.matches(
            "cpe:2.3:a:acme:other:1.2.1:*:*:*:*:*:*:*")
        assert not expr.matches(
            "cpe:2.3:o:acme:nodegrid:1.2.1:*:*:*:*:*:*:*")
class OrchestrationTest(unittest.TestCase):
    """
    Check grouping, separation of buckets and gap analysis.
    """

    def setUp(self):
        self.devices = [
            make_device("dev-core-1", "1.2.1", group="rg-core"),
            make_device("dev-core-2", "1.2.2", group="rg-core"),
            make_device("dev-core-3", "1.2.3", group="rg-core"),
            make_device("dev-edge-1", "1.2.4", group="rg-edge",
                        status=PlatformStatus.UNDETERMINED),
        ]
        self.windows = [MaintenanceWindow("mw-1", 2),
                        MaintenanceWindow("mw-2", 2)]

    def test_confirmed_matches_are_grouped_into_windows(self):
        result = build_schedule(self.devices, EXPRESSION, self.windows)
        assert result.assignments == {"mw-1": ["dev-core-1"],
                                      "mw-2": ["dev-core-2"]}

    def test_undetermined_items_are_kept_apart(self):
        result = build_schedule(self.devices, EXPRESSION, self.windows)
        assert result.undetermined == ["dev-edge-1"]
        placed = sum(result.assignments.values(), [])
        assert "dev-edge-1" not in placed

    def test_window_conflict_items_are_kept_apart(self):
        result = build_schedule(self.devices, EXPRESSION, self.windows)
        assert len(result.unscheduled) == 1
        item = result.unscheduled[0]
        assert item.device_id == "dev-core-3"
        assert item.redundancy_group == "rg-core"
        assert item.reason == Reason.REDUNDANCY_CONFLICT

    def test_redundancy_peers_never_share_a_window(self):
        devices = [
            make_device("dev-a1", "1.0.1", group="rg-a"),
            make_device("dev-a2", "1.0.2", group="rg-a"),
            make_device("dev-b1", "1.0.3", group="rg-b"),
            make_device("dev-b2", "1.0.4", group="rg-b"),
        ]
        result = build_schedule(devices, EXPRESSION, self.windows)
        group_of = dict((d.device_id, d.redundancy_group) for d in devices)
        for members in result.assignments.values():
            groups = [group_of[d] for d in members]
            assert len(groups) == len(set(groups))
        assert result.unscheduled == []

    def test_quota_exhaustion_is_reported(self):
        windows = [MaintenanceWindow("mw-1", 1),
                   MaintenanceWindow("mw-2", 1)]
        devices = [
            make_device("dev-1", "1.0.1"),
            make_device("dev-2", "1.0.2"),
            make_device("dev-3", "1.0.3"),
        ]
        result = build_schedule(devices, EXPRESSION, windows)
        assert len(result.unscheduled) == 1
        assert result.unscheduled[0].reason == Reason.QUOTA_EXHAUSTED

    def test_non_matching_confirmed_devices_are_excluded(self):
        devices = self.devices + [
            make_device("dev-other-1", "1.0.0", product="other"),
        ]
        result = build_schedule(devices, EXPRESSION, self.windows)
        assert result.excluded == ["dev-other-1"]

    def test_group_one_alternative_window_short_is_found(self):
        result = build_schedule(self.devices, EXPRESSION, self.windows)
        near = result.near_complete_groups
        assert len(near) == 1
        gap = near[0]
        assert gap.redundancy_group == "rg-core"
        assert gap.extra_windows_needed == 1
        assert gap.scheduled == ["dev-core-1", "dev-core-2"]
        assert gap.pending == ["dev-core-3"]

    def test_group_needing_more_windows_is_not_near_complete(self):
        devices = self.devices + [
            make_device("dev-core-4", "1.2.5", group="rg-core"),
        ]
        result = build_schedule(devices, EXPRESSION, self.windows)
        assert result.near_complete_groups == []
        gap = result.group_gaps[0]
        assert gap.redundancy_group == "rg-core"
        assert gap.extra_windows_needed == 2

    def test_report_mentions_every_bucket(self):
        result = build_schedule(self.devices, EXPRESSION, self.windows)
        report = result.render_text(self.windows)
        assert "dev-core-1" in report
        assert "dev-edge-1" in report
        assert "dev-core-3" in report
        assert "rg-core" in report
