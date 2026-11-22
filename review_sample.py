# -*- coding: utf-8 -*-
"""
评审样张 (review sample) for the CVSS review backend in cvss/review.py.

Scenario: a risk register (风险台账) holds incident pairs whose CVSS ratings
are identical. In each pair one row was scored with reviewer-confirmed
metrics while the other borrowed a metric value from the upstream default.
The review backend decides, driven by an explicit policy, which row can be
published directly and which metric still needs evidence.

Run with: python review_sample.py
"""

from __future__ import print_function

from cvss import ReviewPolicy, review_vector

# Explicit review configuration: base and temporal/threat metrics must be
# confirmed by a reviewer before direct publication; environmental metrics
# may rely on an upstream default; anything without provenance counts as
# unverified.
POLICY = ReviewPolicy(
    required_trust={
        "base": "confirmed",
        "temporal": "confirmed",
        "threat": "confirmed",
        "environmental": "upstream_default",
    },
    fallback_required_trust="confirmed",
    default_trust="unverified",
)

CONFIRMED = "confirmed"
UPSTREAM_DEFAULT = "upstream_default"

# Two register rows with identical CVSS 3.1 ratings (9.8 Critical). The
# second row borrowed Attack Complexity from the upstream default.
VECTOR_31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
BASE_31 = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]

INCIDENT_A = {
    "id": "INC-2026-0042",
    "vector": VECTOR_31,
    "provenance": dict((metric, CONFIRMED) for metric in BASE_31),
}

INCIDENT_B = {
    "id": "INC-2026-0043",
    "vector": VECTOR_31,
    "provenance": dict(
        (metric, UPSTREAM_DEFAULT if metric == "AC" else CONFIRMED) for metric in BASE_31
    ),
}

# Two register rows with identical CVSS 4.0 ratings (10.0 Critical). The
# second row borrowed Attack Requirements from the upstream default.
VECTOR_40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
BASE_40 = ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"]

INCIDENT_C = {
    "id": "INC-2026-0107",
    "vector": VECTOR_40,
    "provenance": dict((metric, CONFIRMED) for metric in BASE_40),
}

INCIDENT_D = {
    "id": "INC-2026-0108",
    "vector": VECTOR_40,
    "provenance": dict(
        (metric, UPSTREAM_DEFAULT if metric == "AT" else CONFIRMED) for metric in BASE_40
    ),
}


def review(incident):
    report = review_vector(incident["vector"], incident["provenance"], POLICY)
    print("=" * 78)
    print("评审样张 / Review sheet: {0}".format(incident["id"]))
    print("=" * 78)
    print(report.explain())
    print()
    return report


def main():
    print("Review policy: {0}".format(POLICY.required_trust))
    print()

    print("Pair 1: two CVSS 3.1 rows with identical ratings")
    report_a = review(INCIDENT_A)
    report_b = review(INCIDENT_B)

    print("Pair 2: two CVSS 4.0 rows with identical ratings")
    report_c = review(INCIDENT_C)
    report_d = review(INCIDENT_D)

    print("=" * 78)
    print("Summary: same score, different decisions")
    print("=" * 78)
    for incident, report in (
        (INCIDENT_A, report_a),
        (INCIDENT_B, report_b),
        (INCIDENT_C, report_c),
        (INCIDENT_D, report_d),
    ):
        missing = ", ".join(m.abbreviation for m in report.missing_evidence) or "-"
        print(
            "{0}: score {1} ({2}) -> {3}, missing evidence: {4}".format(
                incident["id"],
                report.scores()[0],
                report.severities()[0],
                report.decision.upper(),
                missing,
            )
        )
    print()
    print(
        "INC-2026-0043 and INC-2026-0108 stay on HOLD until a reviewer "
        "confirms the borrowed metric; confirming it flips the decision:"
    )
    for incident, borrowed in ((INCIDENT_B, "AC"), (INCIDENT_D, "AT")):
        provenance = dict(incident["provenance"])
        provenance[borrowed] = CONFIRMED
        report = review_vector(incident["vector"], provenance, POLICY)
        print(
            "  {0}: {1} confirmed -> {2}".format(incident["id"], borrowed, report.decision.upper())
        )


if __name__ == "__main__":
    main()
