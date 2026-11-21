#
# SPDX-License-Identifier: Apache-2.0
r"""Batch re-review of historical approvals against new scan reports.

This module provides the backend entry point used when the security rule
package is upgraded.  A caller supplies:

* an old JSON baseline report whose findings carry historical approval
  records,
* one or more new JSON reports produced with the upgraded rule set, and
* an audited rule-version migration declaration describing how rules
  changed between the two versions (rule splits and severity changes).

Each finding in the new reports is dispositioned individually:

* ``carried_over`` -- the finding is verifiably unchanged (same rule,
  location, severity and code) and its historical approval is complete
  and unexpired, so the approval continues to apply.
* ``needs_review`` -- a human must look at the finding.  The ``reason``
  field explains why:

  * ``rule_split`` -- the old rule was split into new rules by the
    migration, so the old approval does not automatically cover them.
  * ``severity_changed`` -- the same rule now reports a different
    severity (declared in the migration or observed in the report).
  * ``approval_expired`` -- the historical approval has expired.
  * ``incomplete_approval`` -- the historical approval record is
    missing required fields and cannot be verified.
  * ``new_finding`` -- no matching baseline finding exists.
  * ``finding_changed`` -- the location matches but the code snippet
    differs, so the finding cannot be verified as unchanged.
"""
import datetime
import json
import logging
import os

LOG = logging.getLogger(__name__)

DISPOSITION_CARRIED_OVER = "carried_over"
DISPOSITION_NEEDS_REVIEW = "needs_review"

REASON_RULE_SPLIT = "rule_split"
REASON_SEVERITY_CHANGED = "severity_changed"
REASON_APPROVAL_EXPIRED = "approval_expired"
REASON_INCOMPLETE_APPROVAL = "incomplete_approval"
REASON_NEW_FINDING = "new_finding"
REASON_FINDING_CHANGED = "finding_changed"

REQUIRED_APPROVAL_FIELDS = ("approved_by", "approved_at", "expires_at")


def _load_json(source):
    """Accept a parsed dict or a path to a JSON file."""
    if isinstance(source, dict):
        return source
    with open(source) as fdata:
        return json.load(fdata)


def _parse_timestamp(value):
    """Parse an ISO 8601 timestamp into an aware datetime."""
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    parsed = datetime.datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=datetime.timezone.utc)
    return parsed


def _finding_key(finding):
    return (
        finding.get("filename"),
        finding.get("test_id"),
        finding.get("line_number"),
    )


def _location_key(finding):
    return (finding.get("filename"), finding.get("line_number"))


def _report_name(report, report_data, index):
    if report_data.get("report_name"):
        return report_data["report_name"]
    if isinstance(report, dict):
        return "report[%d]" % index
    return os.path.basename(report)


def _baseline_index(baseline):
    """Index baseline findings by identity and by location."""
    by_key = {}
    by_location = {}
    for finding in baseline.get("results", []):
        by_key[_finding_key(finding)] = finding
        by_location.setdefault(_location_key(finding), []).append(finding)
    return by_key, by_location


def _missing_approval_fields(approval):
    return [field for field in REQUIRED_APPROVAL_FIELDS
            if not approval.get(field)]


def _split_source(migration, new_finding, by_location):
    """Find the baseline rule a new finding was split from, if any."""
    splits = migration.get("rule_splits", {})
    for old_test_id, new_test_ids in splits.items():
        if new_finding.get("test_id") not in new_test_ids:
            continue
        for candidate in by_location.get(_location_key(new_finding), []):
            if candidate.get("test_id") == old_test_id:
                return old_test_id
    return None


def _severity_changed(migration, baseline_finding, new_finding):
    old_severity = baseline_finding.get("issue_severity")
    new_severity = new_finding.get("issue_severity")
    if old_severity != new_severity:
        return old_severity, new_severity
    declared = migration.get("severity_changes", {}).get(
        new_finding.get("test_id"))
    if declared and declared.get("to") == new_severity:
        return declared.get("from"), new_severity
    return None


def _review_finding(finding, report_name, migration, by_key, by_location,
                    review_time, migration_label):
    """Disposition a single new finding against the baseline."""
    entry = {
        "report": report_name,
        "filename": finding.get("filename"),
        "line_number": finding.get("line_number"),
        "test_id": finding.get("test_id"),
        "test_name": finding.get("test_name"),
        "issue_severity": finding.get("issue_severity"),
    }

    baseline_finding = by_key.get(_finding_key(finding))

    if baseline_finding is None:
        old_test_id = _split_source(migration, finding, by_location)
        if old_test_id is not None:
            entry.update(
                disposition=DISPOSITION_NEEDS_REVIEW,
                reason=REASON_RULE_SPLIT,
                detail=(
                    "Rule %s was split by migration %s and this finding "
                    "now uses %s; the historical approval for %s does not "
                    "automatically cover the new rule." % (
                        old_test_id, migration_label,
                        finding.get("test_id"), old_test_id)),
            )
        else:
            entry.update(
                disposition=DISPOSITION_NEEDS_REVIEW,
                reason=REASON_NEW_FINDING,
                detail="No matching baseline finding; requires a fresh "
                       "review.",
            )
        return entry

    approval = baseline_finding.get("approval") or {}
    missing = _missing_approval_fields(approval)
    if missing:
        entry.update(
            disposition=DISPOSITION_NEEDS_REVIEW,
            reason=REASON_INCOMPLETE_APPROVAL,
            detail="Historical approval record is missing required "
                   "fields: %s." % ", ".join(missing),
        )
        return entry

    expires_at = _parse_timestamp(approval["expires_at"])
    if expires_at <= review_time:
        entry.update(
            disposition=DISPOSITION_NEEDS_REVIEW,
            reason=REASON_APPROVAL_EXPIRED,
            detail="Approval by %s expired at %s (review time %s)." % (
                approval["approved_by"], approval["expires_at"],
                review_time.isoformat()),
        )
        return entry

    severity_change = _severity_changed(migration, baseline_finding, finding)
    if severity_change:
        entry.update(
            disposition=DISPOSITION_NEEDS_REVIEW,
            reason=REASON_SEVERITY_CHANGED,
            detail="Severity for %s changed from %s to %s; the approval "
                   "must be re-evaluated." % (
                       finding.get("test_id"), severity_change[0],
                       severity_change[1]),
        )
        return entry

    if baseline_finding.get("code") != finding.get("code"):
        entry.update(
            disposition=DISPOSITION_NEEDS_REVIEW,
            reason=REASON_FINDING_CHANGED,
            detail="Code at the approved location changed; the finding "
                   "cannot be verified as unchanged.",
        )
        return entry

    entry.update(
        disposition=DISPOSITION_CARRIED_OVER,
        reason=None,
        detail="Finding verified unchanged (same rule, location, "
               "severity and code); approval by %s carries over until "
               "%s." % (approval["approved_by"], approval["expires_at"]),
        approval=approval,
    )
    return entry


def review_approvals(baseline, new_reports, migration, review_time=None):
    """Batch re-review entry point for historical approvals.

    :param baseline: old JSON baseline report (parsed dict or path) whose
        findings may carry an ``approval`` record.
    :param new_reports: iterable of new JSON reports (parsed dicts or
        paths) produced with the upgraded rule set.
    :param migration: audited rule-version migration declaration (parsed
        dict or path) with ``rule_splits`` and ``severity_changes``.
    :param review_time: datetime used as "now" for expiry checks;
        defaults to the current UTC time.
    :return: a review report dict with per-finding dispositions and a
        summary.
    """
    baseline = _load_json(baseline)
    migration = _load_json(migration)
    if review_time is None:
        review_time = datetime.datetime.now(datetime.timezone.utc)

    by_key, by_location = _baseline_index(baseline)
    migration_label = "%s -> %s" % (
        migration.get("from_version", "?"), migration.get("to_version", "?"))

    findings = []
    for index, report in enumerate(new_reports):
        report_data = _load_json(report)
        report_name = _report_name(report, report_data, index)
        for finding in report_data.get("results", []):
            findings.append(_review_finding(
                finding, report_name, migration, by_key, by_location,
                review_time, migration_label))

    reasons = {}
    for entry in findings:
        if entry["reason"]:
            reasons[entry["reason"]] = reasons.get(entry["reason"], 0) + 1

    carried_over = sum(
        1 for entry in findings
        if entry["disposition"] == DISPOSITION_CARRIED_OVER)

    return {
        "generated_at": review_time.isoformat(),
        "rule_set_migration": {
            "from_version": migration.get("from_version"),
            "to_version": migration.get("to_version"),
        },
        "summary": {
            "total": len(findings),
            "carried_over": carried_over,
            "needs_review": len(findings) - carried_over,
            "reasons": reasons,
        },
        "findings": findings,
    }
