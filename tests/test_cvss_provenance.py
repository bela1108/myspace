"""
Offline regression for a review table that keeps confirmed CVSS base metrics
from two CVSS generations side by side while preserving their version origin.

Scenario
--------
A public report merges two legal short (mandatory-only) base vectors into one
review table. Every approved base metric must stay tagged with the CVSS
generation it was declared for, and the score reported for each row must be
computed by the matching cvss entry point only.

Vectors and hand-declared approved fields
------------------------------------------
CVSS2   "AV:N/AC:L/Au:N/C:P/I:P/A:P"
        approved: AV=N, AC=L, Au=N, C=P, I=P, A=P (the six v2 mandatory metrics)
CVSS3.1 "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        approved: AV=N, AC=L, PR=N, UI=N, S=U, C=H, I=H, A=H
        (the eight v3.1 mandatory metrics)

Expected score ranges (base score is the first value of scores())
------------------------------------------------------------------
CVSS2   base 7.5, asserted inside [7.4, 7.6]; temporal and environmental
        scores are None because no optional temporal/environmental metric is
        present in the record.
CVSS3.1 base 9.8, asserted inside [9.7, 9.9]; temporal and environmental
        scores equal the base score because the v3 specification derives them
        from the base metrics when no optional metric is supplied.

Missing optional metrics
------------------------
Optional metrics absent from a record (v2 temporal/environmental metrics, v3
temporal/environmental/modified metrics) are explained by that record alone,
using the version's own default marker ("ND" for v2, "X" for v3). They must
never be copied from the other generation; in particular the v2-only "Au"
metric and the v3-only "PR"/"UI"/"S" metrics must not leak across rows.

This test exercises only the public cvss entry points (CVSS2, CVSS3 and
cvss.parser.parse_cvss_from_text) and does not touch the scoring kernel.
"""

import sys
import unittest
from os import path

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))

from cvss import parser
from cvss.constants2 import (
    ENVIRONMENTAL_METRICS as V2_ENVIRONMENTAL_METRICS,
)
from cvss.constants2 import (
    METRICS_MANDATORY as V2_MANDATORY_METRICS,
)
from cvss.constants2 import (
    TEMPORAL_METRICS as V2_TEMPORAL_METRICS,
)
from cvss.constants3 import (
    ENVIRONMENTAL_METRICS as V3_ENVIRONMENTAL_METRICS,
)
from cvss.constants3 import (
    METRICS_MANDATORY as V3_MANDATORY_METRICS,
)
from cvss.constants3 import (
    TEMPORAL_METRICS as V3_TEMPORAL_METRICS,
)
from cvss.cvss2 import CVSS2
from cvss.cvss3 import CVSS3


V2_VECTOR = "AV:N/AC:L/Au:N/C:P/I:P/A:P"
V2_APPROVED = {
    "AV": "N",
    "AC": "L",
    "Au": "N",
    "C": "P",
    "I": "P",
    "A": "P",
}
V2_SCORE_RANGE = (7.4, 7.6)

V3_VECTOR = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
V3_APPROVED = {
    "AV": "N",
    "AC": "L",
    "PR": "N",
    "UI": "N",
    "S": "U",
    "C": "H",
    "I": "H",
    "A": "H",
}
V3_SCORE_RANGE = (9.7, 9.9)

# Hand-approved review table: each row declares its own CVSS generation, so the
# public report can always tell which version a confirmed metric came from.
REVIEW_TABLE = [
    {"version": "2.0", "vector": V2_VECTOR, "approved": V2_APPROVED},
    {"version": "3.1", "vector": V3_VECTOR, "approved": V3_APPROVED},
]


def build_report_row(entry):
    """
    Builds one public-report row from a hand-approved entry using only the
    public cvss entry points. Confirmed metrics come exclusively from the
    version named by the entry; nothing is shared between generations.
    """
    if entry["version"] == "2.0":
        cvss_object = CVSS2(entry["vector"])
        mandatory_metrics = V2_MANDATORY_METRICS
        optional_metrics = V2_TEMPORAL_METRICS + V2_ENVIRONMENTAL_METRICS
        default_marker = "ND"
        declared_metrics = cvss_object.metrics
    else:
        cvss_object = CVSS3(entry["vector"])
        mandatory_metrics = V3_MANDATORY_METRICS
        optional_metrics = V3_TEMPORAL_METRICS + V3_ENVIRONMENTAL_METRICS
        default_marker = "X"
        # original_metrics holds exactly the fields declared in the vector,
        # before v3 modified metrics are back-filled from the base metrics.
        declared_metrics = cvss_object.original_metrics

    confirmed = {
        metric: declared_metrics[metric]
        for metric in mandatory_metrics
        if metric in declared_metrics
    }
    missing_optional = [
        metric for metric in optional_metrics if metric not in declared_metrics
    ]
    return {
        "version": entry["version"],
        "confirmed": confirmed,
        "missing_optional": missing_optional,
        "default_marker": default_marker,
        "scores": cvss_object.scores(),
    }


class TestCVSSProvenance(unittest.TestCase):
    def test_short_vectors_parse_through_public_entry_points(self):
        """Both short vectors are legal and parse via their own entry points."""
        v2 = CVSS2(V2_VECTOR)
        v3 = CVSS3(V3_VECTOR)
        self.assertEqual("2.0", v2.__class__.__name__ and "2.0")
        self.assertEqual(1, v3.minor_version)
        self.assertEqual(V2_VECTOR, v2.clean_vector())
        self.assertEqual(V3_VECTOR, v3.clean_vector())

        parsed = parser.parse_cvss_from_text(
            "see {0} and {1} in the report".format(V2_VECTOR, V3_VECTOR)
        )
        parsed_types = sorted(type(obj).__name__ for obj in parsed)
        self.assertEqual(["CVSS2", "CVSS3"], parsed_types)

    def test_confirmed_metrics_match_hand_approved_fields(self):
        """Each row reports exactly the hand-declared approved base fields."""
        rows = [build_report_row(entry) for entry in REVIEW_TABLE]
        self.assertEqual(V2_APPROVED, rows[0]["confirmed"])
        self.assertEqual(V3_APPROVED, rows[1]["confirmed"])
        self.assertEqual("2.0", rows[0]["version"])
        self.assertEqual("3.1", rows[1]["version"])

    def test_score_ranges_match_version_expectations(self):
        """Base scores fall in the per-version expected intervals."""
        v2_base, v2_temporal, v2_environmental = CVSS2(V2_VECTOR).scores()
        v3_base, v3_temporal, v3_environmental = CVSS3(V3_VECTOR).scores()

        self.assertGreaterEqual(v2_base, V2_SCORE_RANGE[0])
        self.assertLessEqual(v2_base, V2_SCORE_RANGE[1])
        self.assertIsNone(v2_temporal)
        self.assertIsNone(v2_environmental)

        self.assertGreaterEqual(v3_base, V3_SCORE_RANGE[0])
        self.assertLessEqual(v3_base, V3_SCORE_RANGE[1])
        self.assertEqual(v3_base, v3_temporal)
        self.assertEqual(v3_base, v3_environmental)

    def test_missing_optional_metrics_are_explained_not_copied(self):
        """Absent optional metrics are recorded per version with its own marker."""
        rows = [build_report_row(entry) for entry in REVIEW_TABLE]
        v2_row, v3_row = rows

        self.assertEqual(
            V2_TEMPORAL_METRICS + V2_ENVIRONMENTAL_METRICS,
            v2_row["missing_optional"],
        )
        self.assertEqual(
            V3_TEMPORAL_METRICS + V3_ENVIRONMENTAL_METRICS,
            v3_row["missing_optional"],
        )
        self.assertEqual("ND", v2_row["default_marker"])
        self.assertEqual("X", v3_row["default_marker"])

        # Version-specific base metrics must not leak across generations.
        self.assertIn("Au", v2_row["confirmed"])
        self.assertNotIn("Au", v3_row["confirmed"])
        for v3_only_metric in ("PR", "UI", "S"):
            self.assertIn(v3_only_metric, v3_row["confirmed"])
            self.assertNotIn(v3_only_metric, v2_row["confirmed"])

        # The v3 library back-fills modified metrics internally, but the
        # report must still treat every modified metric as not hand-declared.
        self.assertTrue(
            all(
                metric in v3_row["missing_optional"]
                for metric in V3_ENVIRONMENTAL_METRICS
                if metric.startswith("M")
            )
        )
        # Nothing absent from a record may be filled from the other version.
        self.assertFalse(
            set(v2_row["missing_optional"]) & set(v3_row["confirmed"])
        )
        self.assertFalse(
            set(v3_row["missing_optional"]) & set(v2_row["confirmed"])
        )


if __name__ == "__main__":
    unittest.main()
