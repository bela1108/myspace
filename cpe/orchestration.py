# -*- coding: utf-8 -*-

"""
Offline maintenance-window orchestration on top of CPE language matching.

This module schedules the assets matched by a platform expression (CPE
Applicability Language) into a fixed set of maintenance windows. Assets
that belong to the same redundancy group must not be taken down in the
same window, and every window has a fixed quota of devices it can update.

The result keeps three buckets apart:

* confirmed matches that fit into a window (actionable groups),
* assets whose platform match is still undetermined,
* confirmed matches left out because of window conflicts.

For every redundancy group that could not be placed completely, the
report computes how many extra (alternative) windows would be needed,
so the group that is only one alternative window short can be spotted.
"""

from .cpe2_3_fs import CPE2_3_FS
from .cpeset2_3 import CPESet2_3
from .cpelang2_3 import CPELanguage2_3


class PlatformStatus(object):
    """
    Platform confirmation states for an asset matched by an expression.
    """

    #: The platform confirmed the asset matches the expression
    CONFIRMED = "confirmed"

    #: The platform has not decided yet whether the asset matches
    UNDETERMINED = "undetermined"


class Reason(object):
    """
    Causes for a confirmed device not fitting into any window.
    """

    #: Every window with free quota already holds a redundancy peer
    REDUNDANCY_CONFLICT = "redundancy-conflict"

    #: All windows ran out of quota
    QUOTA_EXHAUSTED = "quota-exhausted"


class Device(object):
    """
    An asset candidate for offline remediation.

    :param string device_id: unique asset identifier
    :param string cpe: CPE 2.3 formatted string of the asset
    :param string redundancy_group: name of the redundancy group the
        asset belongs to, or None if it can be stopped alone
    :param string platform_status: one of PlatformStatus values
    """

    def __init__(self, device_id, cpe, redundancy_group=None,
                 platform_status=PlatformStatus.CONFIRMED):
        self.device_id = device_id
        self.cpe = cpe
        self.redundancy_group = redundancy_group
        self.platform_status = platform_status

    def __repr__(self):
        return "Device({0!r}, group={1!r}, status={2!r})".format(
            self.device_id, self.redundancy_group, self.platform_status)


class MaintenanceWindow(object):
    """
    A maintenance window able to update a fixed number of devices.

    :param string window_id: unique window identifier
    :param int quota: maximum number of devices the window can update
    """

    def __init__(self, window_id, quota):
        if quota < 1:
            raise ValueError("window quota must be a positive integer")
        self.window_id = window_id
        self.quota = quota

    def __repr__(self):
        return "MaintenanceWindow({0!r}, quota={1!r})".format(
            self.window_id, self.quota)


class PlatformExpression(object):
    """
    A platform expression in CPE Applicability Language 2.3 (JSON),
    evaluated offline against asset CPE names.

    :param string expression: JSON document with the expression, or a
        path to a file containing it when is_file is True
    :param boolean is_file: whether expression is a file path
    """

    def __init__(self, expression, is_file=False):
        if is_file:
            with open(expression) as f:
                self.raw = f.read()
        else:
            self.raw = expression
        self._language = CPELanguage2_3(self.raw, isJSON=True)

    def matches(self, cpe_name):
        """
        Returns True if the platform expression matches the given CPE
        2.3 formatted string, evaluated offline with the cpe library.

        :param string cpe_name: CPE 2.3 formatted string of an asset
        :returns: True if the expression matches the asset
        :rtype: boolean
        """

        cpeset = CPESet2_3()
        cpeset.append(CPE2_3_FS(cpe_name))
        return bool(self._language.language_match(cpeset))


class UnscheduledItem(object):
    """
    A confirmed device that did not fit into any window.
    """

    def __init__(self, device_id, redundancy_group, reason):
        self.device_id = device_id
        self.redundancy_group = redundancy_group
        self.reason = reason


class GroupGap(object):
    """
    Placement gap of a redundancy group that could not be completed.

    :param string redundancy_group: name of the redundancy group
    :param list members: all confirmed group members
    :param list scheduled: members placed into a window
    :param list pending: members left out because of window conflicts
    :param int extra_windows_needed: alternative windows (with the same
        quota) required to place every member, or None if the group
        cannot be completed even with one window per member
    """

    def __init__(self, redundancy_group, members, scheduled, pending,
                 extra_windows_needed):
        self.redundancy_group = redundancy_group
        self.members = members
        self.scheduled = scheduled
        self.pending = pending
        self.extra_windows_needed = extra_windows_needed

    @property
    def is_near_complete(self):
        """
        Returns True if a single alternative window completes the group.
        """

        return self.extra_windows_needed == 1


class OrchestrationResult(object):
    """
    Outcome of an offline orchestration run.
    """

    def __init__(self, assignments, unscheduled, undetermined, excluded,
                 group_gaps, device_groups):
        #: Mapping of window id to the list of device ids placed in it
        self.assignments = assignments
        #: Confirmed devices left out because of window conflicts
        self.unscheduled = unscheduled
        #: Devices whose platform match is still undetermined
        self.undetermined = undetermined
        #: Confirmed devices the expression does not match
        self.excluded = excluded
        #: Placement gaps of incomplete redundancy groups
        self.group_gaps = group_gaps
        self._device_groups = device_groups

    @property
    def near_complete_groups(self):
        """
        Returns the redundancy groups that are only one alternative
        window away from being fully scheduled.
        """

        return [gap for gap in self.group_gaps if gap.is_near_complete]

    def render_text(self, windows):
        """
        Renders a human-readable report of the orchestration result.

        :param list windows: maintenance windows used in the run
        :returns: report text
        :rtype: string
        """

        reason_labels = {
            Reason.REDUNDANCY_CONFLICT:
                "冗余组冲突（同组设备不可同期停机）",
            Reason.QUOTA_EXHAUSTED: "窗口配额耗尽",
        }

        lines = ["离线处置编排报告"]
        lines.append("维护窗口: " + ", ".join(
            "{0}(配额{1})".format(w.window_id, w.quota) for w in windows))
        lines.append("")

        lines.append("[已落实分组]")
        for window in windows:
            members = self.assignments.get(window.window_id, [])
            if not members:
                lines.append("  {0}: (空)".format(window.window_id))
                continue
            lines.append("  {0}:".format(window.window_id))
            for device_id in members:
                group = self._device_groups.get(device_id)
                suffix = "  (冗余组 {0})".format(group) if group else ""
                lines.append("    - {0}{1}".format(device_id, suffix))
        lines.append("")

        lines.append("[平台未确定]（不纳入编排）")
        if self.undetermined:
            lines.extend("  - {0}".format(d) for d in self.undetermined)
        else:
            lines.append("  (无)")
        lines.append("")

        lines.append("[窗口冲突未排上]")
        if self.unscheduled:
            for item in self.unscheduled:
                group = "冗余组 {0}, ".format(item.redundancy_group) \
                    if item.redundancy_group else ""
                lines.append("  - {0} ({1}{2})".format(
                    item.device_id, group, reason_labels[item.reason]))
        else:
            lines.append("  (无)")

        if self.excluded:
            lines.append("")
            lines.append("[已确认但不匹配表达式]")
            lines.extend("  - {0}".format(d) for d in self.excluded)
        lines.append("")

        lines.append("[替代窗口分析]")
        if not self.group_gaps:
            lines.append("  (无缺口冗余组)")
        for gap in self.group_gaps:
            if gap.extra_windows_needed == 1:
                verdict = "只差 1 个替代窗口即可完成"
            elif gap.extra_windows_needed is None:
                verdict = "每台一个窗口也无法补齐"
            else:
                verdict = "还需 {0} 个替代窗口".format(
                    gap.extra_windows_needed)
            lines.append(
                "  冗余组 {0}: 成员 {1} 台, 已落实 {2} 台, 待排 {3} 台 -> {4}"
                .format(gap.redundancy_group, len(gap.members),
                        len(gap.scheduled), len(gap.pending), verdict))
        return "\n".join(lines)


def _ordered_devices(devices):
    """
    Returns devices in deterministic scheduling order: redundancy groups
    first (largest group, then name), ungrouped devices last.
    """

    grouped = {}
    loose = []
    for device in devices:
        if device.redundancy_group is None:
            loose.append(device)
        else:
            grouped.setdefault(device.redundancy_group, []).append(device)

    ordered = []
    for name in sorted(grouped, key=lambda n: (-len(grouped[n]), n)):
        ordered.extend(sorted(grouped[name], key=lambda d: d.device_id))
    ordered.extend(sorted(loose, key=lambda d: d.device_id))
    return ordered


def _assign(devices, windows):
    """
    Greedily places devices into windows, honoring per-window quotas and
    keeping redundancy peers out of the same window.
    """

    window_ids = [w.window_id for w in windows]
    remaining = dict((w.window_id, w.quota) for w in windows)
    groups_in = dict((w.window_id, set()) for w in windows)
    assignments = dict((w.window_id, []) for w in windows)
    unscheduled = []

    for device in _ordered_devices(devices):
        candidates = [
            wid for wid in window_ids
            if remaining[wid] > 0
            and device.redundancy_group not in groups_in[wid]
        ]
        if candidates:
            chosen = max(
                candidates,
                key=lambda wid: (remaining[wid], -window_ids.index(wid)))
            assignments[chosen].append(device.device_id)
            remaining[chosen] -= 1
            if device.redundancy_group is not None:
                groups_in[chosen].add(device.redundancy_group)
        else:
            if all(remaining[wid] == 0 for wid in window_ids):
                reason = Reason.QUOTA_EXHAUSTED
            else:
                reason = Reason.REDUNDANCY_CONFLICT
            unscheduled.append(UnscheduledItem(
                device.device_id, device.redundancy_group, reason))

    return assignments, unscheduled


def _analyze_gaps(schedulable, windows, unscheduled):
    """
    For every redundancy group with unscheduled members, computes how
    many alternative windows (same quota) would complete the group.
    """

    pending_by_group = {}
    for item in unscheduled:
        if item.redundancy_group is not None:
            pending_by_group.setdefault(
                item.redundancy_group, []).append(item.device_id)

    gaps = []
    quota = max([w.quota for w in windows] or [1])
    for name in sorted(pending_by_group):
        members = sorted(d.device_id for d in schedulable
                         if d.redundancy_group == name)
        pending = sorted(pending_by_group[name])
        scheduled = sorted(set(members) - set(pending))

        extra = None
        for k in range(1, len(members) + 1):
            trial = list(windows) + [
                MaintenanceWindow("alt-{0}".format(i), quota)
                for i in range(1, k + 1)
            ]
            _, still_out = _assign(schedulable, trial)
            if not any(u.device_id in members for u in still_out):
                extra = k
                break
        gaps.append(GroupGap(name, members, scheduled, pending, extra))
    return gaps


def build_schedule(devices, expression, windows):
    """
    Runs the offline orchestration.

    :param list devices: Device objects to orchestrate
    :param expression: PlatformExpression or its JSON document
    :param list windows: MaintenanceWindow objects available
    :returns: the orchestration outcome
    :rtype: OrchestrationResult
    """

    if not isinstance(expression, PlatformExpression):
        expression = PlatformExpression(expression)

    schedulable = []
    undetermined = []
    excluded = []
    for device in devices:
        if device.platform_status == PlatformStatus.UNDETERMINED:
            undetermined.append(device.device_id)
        elif expression.matches(device.cpe):
            schedulable.append(device)
        else:
            excluded.append(device.device_id)

    assignments, unscheduled = _assign(schedulable, windows)
    group_gaps = _analyze_gaps(schedulable, windows, unscheduled)
    device_groups = dict((d.device_id, d.redundancy_group)
                         for d in devices)

    return OrchestrationResult(
        assignments,
        sorted(unscheduled, key=lambda u: u.device_id),
        sorted(undetermined),
        sorted(excluded),
        group_gaps,
        device_groups)
