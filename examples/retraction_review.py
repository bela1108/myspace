#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Review an advisory retraction against a small before/after inventory.

The fixture intentionally ends with exactly three asset outcomes:

* ``wls-01`` is confirmed closed by a verified component replacement;
* ``wls-02`` is still affected because its latest observation still matches;
* ``wls-03`` has insufficient evidence because its installation manifest is
  incomplete.

It also asks for two family exclusions.  ``apache_log4j`` is excluded only
because its family inventory is explicitly complete.  ``openssl`` is not
excluded because its coverage evidence covers only two of three collectors.
No exclusion is inferred from a CPE non-match.
"""

from __future__ import absolute_import, print_function, unicode_literals

import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from cpe.impact import (  # noqa: E402
    Advisory,
    Asset,
    ComponentObservation,
    FamilyCoverage,
    InventoryScope,
    ReplacementEvidence,
    assess_retraction,
)


AFFECTED_WLS = (
    "cpe:2.3:a:oracle:weblogic_server:12.2.1.3:*:*:*:*:*:*:*"
)
PATCHED_WLS = (
    "cpe:2.3:a:oracle:weblogic_server:12.2.1.4:*:*:*:*:*:*:*"
)


def build_review():
    advisory = Advisory.from_cpe_names(
        "CVE-2026-0001",
        [AFFECTED_WLS],
        applies_from="2026-09-01T00:00:00Z",
        applies_until="2026-10-01T00:00:00Z",
        retracted_at="2026-10-03T00:00:00Z",
        description="Withdrawn WebLogic 12.2.1.3 advisory under re-review.",
    )

    scope = InventoryScope(
        approved_families=("oracle_weblogic", "apache_log4j", "openssl"),
        coverage={
            "oracle_weblogic": FamilyCoverage(
                family="oracle_weblogic",
                complete=True,
                evidence="CMDB export 2026-10-21 covers all WebLogic hosts",
            ),
            "apache_log4j": FamilyCoverage(
                family="apache_log4j",
                complete=True,
                evidence="signed software inventory export 2026-10-21",
            ),
            "openssl": FamilyCoverage(
                family="openssl",
                complete=False,
                evidence="2 of 3 collectors reported; one host missing",
            ),
        },
        requested_exclusions=("apache_log4j", "openssl"),
    )

    assets = (
        Asset(
            asset_id="wls-01",
            family="oracle_weblogic",
            observations=(
                ComponentObservation(
                    cpe=AFFECTED_WLS,
                    observed_at="2026-09-15T00:00:00Z",
                    source="pre-retraction CMDB snapshot",
                ),
                ComponentObservation(
                    cpe=PATCHED_WLS,
                    observed_at="2026-10-20T00:00:00Z",
                    source="post-retraction CMDB snapshot",
                ),
            ),
            manifest_complete=True,
            manifest_evidence="full package manifest 2026-10-20",
        ),
        Asset(
            asset_id="wls-02",
            family="oracle_weblogic",
            observations=(
                ComponentObservation(
                    cpe=AFFECTED_WLS,
                    observed_at="2026-09-15T00:00:00Z",
                    source="pre-retraction CMDB snapshot",
                ),
                ComponentObservation(
                    cpe=AFFECTED_WLS,
                    observed_at="2026-10-20T00:00:00Z",
                    source="post-retraction CMDB snapshot",
                ),
            ),
            manifest_complete=True,
            manifest_evidence="full package manifest 2026-10-20",
        ),
        Asset(
            asset_id="wls-03",
            family="oracle_weblogic",
            observations=(
                ComponentObservation(
                    cpe="cpe:2.3:o:redhat:enterprise_linux:8:*:*:*:*:*:*:*",
                    observed_at="2026-10-20T00:00:00Z",
                    source="partial package inventory",
                ),
            ),
            manifest_complete=False,
            manifest_evidence="only 1 of 3 package sources submitted",
        ),
    )

    replacements = (
        ReplacementEvidence(
            asset_id="wls-01",
            removed_cpe=AFFECTED_WLS,
            installed_cpe=PATCHED_WLS,
            replaced_at="2026-10-18T00:00:00Z",
            evidence_ref="CHG-4711 / signed install receipt",
            verified=True,
        ),
    )

    return assess_retraction(
        assets=assets,
        advisory=advisory,
        scope=scope,
        replacement_evidence=replacements,
        as_of="2026-11-01T00:00:00Z",
    )


def main():
    report = build_review()
    reports_dir = os.path.join(ROOT, "reports")
    if not os.path.isdir(reports_dir):
        os.makedirs(reports_dir)

    with open(os.path.join(reports_dir, "retraction-impact.json"), "w",
              encoding="utf-8") as handle:
        handle.write(report.to_json())
        handle.write("\n")
    with open(os.path.join(reports_dir, "retraction-impact.md"), "w",
              encoding="utf-8") as handle:
        handle.write(report.to_markdown())
        handle.write("\n")

    print(report.to_markdown())


if __name__ == "__main__":
    main()
