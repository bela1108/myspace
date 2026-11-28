#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Acceptance run for the offline orchestration: four synthetic devices,
two maintenance windows and fixed quotas.

Scenario:

* dev-core-1/2/3 share redundancy group rg-core and are confirmed
  matches of the platform expression, so they must not go down in the
  same window; with only two windows one of them cannot be placed.
* dev-edge-1 matches the expression offline but the platform has not
  confirmed it yet, so it stays out of the schedule.

Expected outcome: dev-core-1 and dev-core-2 are placed, dev-core-3 is
left out by the window conflict, dev-edge-1 is reported as undetermined,
and rg-core is flagged as the group that is only one alternative window
away from completion.
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cpe.orchestration import (  # noqa: E402
    Device,
    MaintenanceWindow,
    PlatformStatus,
    Reason,
    build_schedule,
)


EXPRESSION = json.dumps([
    {
        "operator": "OR",
        "children": [],
        "cpe_match": [
            {"cpe23Uri": "cpe:2.3:a:acme:nodegrid:*:*:*:*:*:*:*:*"},
        ],
    },
])

DEVICES = [
    Device("dev-core-1", "cpe:2.3:a:acme:nodegrid:1.2.1:*:*:*:*:*:*:*",
           redundancy_group="rg-core",
           platform_status=PlatformStatus.CONFIRMED),
    Device("dev-core-2", "cpe:2.3:a:acme:nodegrid:1.2.2:*:*:*:*:*:*:*",
           redundancy_group="rg-core",
           platform_status=PlatformStatus.CONFIRMED),
    Device("dev-core-3", "cpe:2.3:a:acme:nodegrid:1.2.3:*:*:*:*:*:*:*",
           redundancy_group="rg-core",
           platform_status=PlatformStatus.CONFIRMED),
    Device("dev-edge-1", "cpe:2.3:a:acme:nodegrid:1.2.4:*:*:*:*:*:*:*",
           redundancy_group="rg-edge",
           platform_status=PlatformStatus.UNDETERMINED),
]

WINDOWS = [MaintenanceWindow("mw-1", 2), MaintenanceWindow("mw-2", 2)]


def check(condition, message):
    if not condition:
        raise AssertionError(message)
    print("  ok - {0}".format(message))


def main():
    result = build_schedule(DEVICES, EXPRESSION, WINDOWS)

    print(result.render_text(WINDOWS))
    print("")
    print("验收断言:")  # acceptance assertions

    check(result.assignments == {"mw-1": ["dev-core-1"],
                                 "mw-2": ["dev-core-2"]},
          "已确认匹配按冗余约束落入两个窗口")

    check(result.undetermined == ["dev-edge-1"],
          "平台未确定项单独列出且不纳入编排")

    check(len(result.unscheduled) == 1
          and result.unscheduled[0].device_id == "dev-core-3"
          and result.unscheduled[0].reason == Reason.REDUNDANCY_CONFLICT,
          "窗口冲突未排上项单独列出并注明原因")

    near = result.near_complete_groups
    check(len(near) == 1
          and near[0].redundancy_group == "rg-core"
          and near[0].extra_windows_needed == 1,
          "报告找出只差一个替代窗口即可完成的冗余组 rg-core")

    print("验收通过 (ACCEPTANCE PASSED)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
