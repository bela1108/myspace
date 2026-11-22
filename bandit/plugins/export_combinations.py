#
# SPDX-License-Identifier: Apache-2.0
r"""
==========================================================
B616: export_combinations - protected export label overlap
==========================================================

Some reports are allowed to expose individual labels, but exposing a set of
labels to the same outbound recipient can identify a person.  This plugin
collects labels from finite same-module expressions and reports when two
export points can send a caller-protected pair to the same recipient.

The protected combinations must be supplied by the caller.  For example::

    export_combinations:
      protected:
        - [A, B]

Export functions and argument names can also be configured::

    export_combinations:
      export_functions: [export, send_report]
      recipient_arguments: [recipient, destination]
      field_arguments: [fields, columns]

The plugin is conservative: an unresolved runtime value is reported as
``unprovable`` with the reason retained rather than being treated as a
confirmed combination.  Exports guarded by opposite branches of the same
condition are not combined, and exports to disjoint recipients are not
aggregated.
"""

import bandit
from bandit.core import export_combinations as export_analysis
from bandit.core import issue
from bandit.core import test_properties as test


def gen_config(name):
    """Return default configuration for the export-combination review."""
    return {
        "protected": [],
        "export_functions": sorted(
            export_analysis.DEFAULT_EXPORT_FUNCTIONS
        ),
        "recipient_arguments": sorted(
            export_analysis.DEFAULT_RECIPIENT_ARGUMENTS
        ),
        "field_arguments": sorted(
            export_analysis.DEFAULT_FIELD_ARGUMENTS
        ),
        "max_return_depth": 4,
        "max_return_values": 32,
    }


def _read_source(file_data):
    if hasattr(file_data, "seek"):
        file_data.seek(0)
        data = file_data.read()
    else:
        data = file_data
    if isinstance(data, bytes):
        return data.decode("utf-8", "replace")
    return data


def _finding_text(finding):
    labels = " + ".join(finding.protected)
    if finding.status is export_analysis.CombinationStatus.CO_EXECUTABLE:
        if finding.left is finding.right or (
            finding.left is not None
            and finding.right is not None
            and finding.left.identifier == finding.right.identifier
        ):
            return (
                f"Protected export labels {labels} are co-executable at "
                f"{finding.left.identifier}; both leave through the same "
                "export point"
            )
        if finding.left is not None and finding.right is not None:
            return (
                f"Protected export labels {labels} are co-executable at "
                f"{finding.left.identifier} and {finding.right.identifier}; "
                f"recipient: {finding.recipient}"
            )
    if finding.status is export_analysis.CombinationStatus.UNPROVABLE:
        return (
            f"Protected export labels {labels} are unprovable: "
            f"{finding.reason}"
        )
    return f"Protected export labels {labels}: {finding.reason}"


@test.takes_config
@test.checks("File")
@test.test_id("B616")
def export_combinations(context, config):
    """Check caller-protected label combinations across export API calls."""
    config = config or {}
    protected = (
        config.get("protected")
        or config.get("protect")
        or config.get("protected_combinations")
        or config.get("label_combinations")
        or config.get("combinations")
    )
    if not protected:
        return

    source = _read_source(context.file_data)
    report = export_analysis.analyze_source(
        source,
        protected=protected,
        filename=context.filename or "<unknown>",
        config=config,
    )

    actionable = [
        finding
        for finding in report.findings
        if finding.status
        in {
            export_analysis.CombinationStatus.CO_EXECUTABLE,
            export_analysis.CombinationStatus.UNPROVABLE,
        }
    ]
    if not actionable:
        return

    primary = next(
        (
            finding
            for finding in actionable
            if finding.status
            is export_analysis.CombinationStatus.CO_EXECUTABLE
        ),
        actionable[0],
    )
    text = _finding_text(primary)
    if len(actionable) > 1:
        text += " | " + " | ".join(
            _finding_text(finding) for finding in actionable[1:]
        )

    if (
        primary.status
        is export_analysis.CombinationStatus.CO_EXECUTABLE
    ):
        severity = bandit.MEDIUM
        confidence = bandit.HIGH
    else:
        severity = bandit.LOW
        confidence = bandit.LOW

    lineno = primary.left.lineno if primary.left is not None else 1
    col_offset = (
        primary.left.col_offset if primary.left is not None else 0
    )
    result = bandit.Issue(
        severity=severity,
        confidence=confidence,
        cwe=issue.Cwe.IMPROPER_ACCESS_CONTROL,
        text=text,
        lineno=lineno,
        col_offset=col_offset,
    )
    if primary.left is not None:
        result.linerange = [primary.left.lineno, primary.left.lineno]
    return result
