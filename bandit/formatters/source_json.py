#
# SPDX-License-Identifier: Apache-2.0
r"""
====================
Source JSON formatter
====================

The ``source-json`` formatter behaves like the regular JSON formatter but is
designed for reports consumed outside the build step that generated the
scanned code.

Each finding keeps its original scan evidence (``filename``,
``line_number``, ``line_range`` and column offsets) and gains a
``source_refs`` list projected through the source map supplied with
``--source-map``.  Findings are additionally grouped by their original
source locations so a template author can see every generated finding that
points at one of their lines.

The grouping never invents line numbers: a candidate that can only be
expressed as a range is keyed on that range with ``source_line`` set to
``None``, and findings that could not be projected appear under explicit
``unmapped`` / ``invalid`` groups carrying the failure reason.
"""
import collections
import datetime
import json
import logging
import sys

from bandit.core import docs_utils
from bandit.core import source_map as b_source_map

LOG = logging.getLogger(__name__)

UNMAPPED_GROUP = "unmapped"
INVALID_GROUP = "invalid"


def _issue_key(issue_data):
    """Stable identity for a finding within a source group."""
    return (
        issue_data["filename"],
        issue_data["line_number"],
        tuple(issue_data.get("line_range") or []),
        issue_data["test_id"],
        issue_data["issue_text"],
    )


def _group_for_reference(ref):
    """Return the group key (source file, line or range marker) for a ref."""
    if not ref.get("status") == "mapped":
        return (INVALID_GROUP, ref.get("reason"), ref.get("source_file"))

    source_file = ref["source_file"]
    if ref.get("source_line") is not None:
        return (source_file, "line", ref["source_line"])
    return (source_file, "range", ref["source_start"], ref["source_end"])


def _build_source_groups(results):
    """Group already-serialised findings by their projected source locations.

    A finding with several mapped candidates appears in several groups
    (one-to-many).  Groups are ordered, and each finding only occurs once
    within a group even when two of its references resolve to the same key.
    """
    groups = collections.OrderedDict()

    for issue_data in results:
        refs = issue_data.get("source_refs")
        if not refs:
            key = (UNMAPPED_GROUP, b_source_map.REASON_NO_MAPPING, None)
            groups.setdefault(key, [])
            if all(_issue_key(issue_data) != _issue_key(existing)
                   for existing in groups[key]):
                groups[key].append(issue_data)
            continue

        for ref in refs:
            group_key = _group_for_reference(ref)
            bucket = groups.setdefault(group_key, [])
            identity = _issue_key(issue_data)
            # de-duplicate within this group only: one finding with several
            # references to the same source line still appears once, while a
            # one-to-many finding appears once in *each* target group
            if all(identity != _issue_key(existing) for existing in bucket):
                bucket.append(issue_data)

    serialized_groups = []
    for group_key, findings in groups.items():
        entry = {"findings": findings}
        if group_key[0] in (UNMAPPED_GROUP, INVALID_GROUP):
            entry["status"] = "invalid"
            entry["reason"] = group_key[1]
            entry["source_file"] = group_key[2]
        else:
            entry["status"] = "mapped"
            entry["source_file"] = group_key[0]
            if group_key[1] == "line":
                entry["source_line"] = group_key[2]
                entry["source_start"] = group_key[2]
                entry["source_end"] = group_key[2]
            else:
                entry["source_line"] = None
                entry["source_start"] = group_key[2]
                entry["source_end"] = group_key[3]
        serialized_groups.append(entry)
    return serialized_groups


def report(manager, fileobj, sev_level, conf_level, lines=-1):
    """Output findings grouped by their projected source locations.

    :param manager: the bandit manager object
    :param fileobj: the output file object, which may be sys.stdout
    :param sev_level: filtering severity level
    :param conf_level: filtering confidence level
    :param lines: number of code lines to report, -1 for all
    """
    machine_output = {"results": [], "errors": []}
    for fname, reason in manager.get_skipped():
        machine_output["errors"].append(
            {"filename": fname, "reason": reason}
        )

    results = manager.get_issue_list(
        sev_level=sev_level, conf_level=conf_level
    )

    # Baseline mode returns an OrderedDict of issue -> candidates; it relies
    # on the original scan evidence and is intentionally not regrouped here.
    if not isinstance(results, list):
        raise RuntimeError(
            "source-json output cannot be combined with a baseline; use the "
            "json formatter for baseline comparisons"
        )

    collector = []
    for result in results:
        data = result.as_dict(max_lines=lines)
        data["more_info"] = docs_utils.get_url(data["test_id"])
        collector.append(data)

    machine_output["results"] = collector
    machine_output["source_groups"] = _build_source_groups(collector)
    machine_output["metrics"] = manager.metrics.data

    if manager.source_map is not None:
        machine_output["source_map"] = manager.source_map.as_dict()

    time_string = datetime.datetime.now(
        datetime.timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    machine_output["generated_at"] = time_string

    rendered = json.dumps(
        machine_output, sort_keys=True, indent=2, separators=(",", ": ")
    )

    with fileobj:
        fileobj.write(rendered)

    if fileobj.name != sys.stdout.name:
        LOG.info("source-json output written to file: %s", fileobj.name)
