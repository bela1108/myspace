"""Tests for reproducibility adjudication."""

import unittest
from pathlib import Path

import tests.common
from in_toto.exceptions import ReproducibilityVerificationError
from in_toto.models.layout import Layout, Step
from in_toto.models.link import Link
from in_toto.models.metadata import Metadata
from in_toto.verifylib import in_toto_verify, verify_reproducibility

DEMO = Path(__file__).parent / "demo_files_reproducibility"
A = {"sha256": "a" * 64}
B = {"sha256": "b" * 64}
S = {"sha256": "c" * 64}


class TestReproducibility(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.layout_meta = Metadata.load(
            str(DEMO / "reproducible.layout")
        )
        cls.layout = cls.layout_meta.signed
        cls.left = Metadata.load(
            str(DEMO / "build-a" / "build.2f685fa7.link")
        )
        cls.right = Metadata.load(
            str(DEMO / "build-b" / "build.50d7e110.link")
        )

    def test_allowed_timestamp_differences_pass(self):
        result = verify_reproducibility(
            self.layout, self.left, self.right
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.verdict, "reproducible")
        self.assertEqual(result.checked, 4)

        # The full outer digest dictionaries are retained, not reduced.
        self.assertEqual(
            self.left.signed.products["build/build.log"]["sha256"], "a" * 64
        )
        self.assertEqual(
            self.right.signed.products["build/build.log"]["sha256"],
            "b" * 64,
        )

        # Adjudication must not rewrite signed metadata.
        self.left.verify_signature(tests.common.SignerStore.rsa_pub)
        self.right.verify_signature(tests.common.SignerStore.ecdsa_pub)

    def test_disallowed_difference_reports_artifact_side_rule(self):
        layout = Layout(
            steps=[
                Step(
                    name="build",
                    expected_products=[["CREATE", "build/app"]],
                )
            ]
        )
        left = Link(name="build", products={"build/app": A})
        right = Link(name="build", products={"build/app": B})

        with self.assertRaises(ReproducibilityVerificationError) as ctx:
            verify_reproducibility(layout, left, right)

        failure = ctx.exception.failures[0]
        self.assertEqual(failure.artifact, "build/app")
        self.assertEqual(failure.side, "right")
        self.assertEqual(failure.rule, ["CREATE", "build/app"])
        self.assertEqual(failure.rule, "CREATE build/app")
        self.assertEqual(failure.source_type, "products")
        self.assertEqual(failure.left_hash, A)
        self.assertEqual(failure.right_hash, B)
        self.assertIn("build/app", str(failure))
        self.assertIn("right", str(failure))
        self.assertIn("CREATE build/app", str(failure))

    def test_required_intermediate_not_swallowed_by_allow_glob(self):
        layout = Layout(
            steps=[
                Step(
                    name="build",
                    expected_products=[
                        ["REQUIRE", "build/manifest.json"],
                        ["ALLOW", "build/*"],
                    ],
                )
            ]
        )
        left = Link(
            name="build",
            products={"build/build.log": A, "build/manifest.json": A},
        )
        right = Link(
            name="build",
            products={"build/build.log": B, "build/manifest.json": B},
        )

        with self.assertRaises(ReproducibilityVerificationError) as ctx:
            verify_reproducibility(
                layout,
                left,
                right,
                allow_differences=["build/*"],
            )

        self.assertEqual(len(ctx.exception.failures), 1)
        failure = ctx.exception.failures[0]
        self.assertEqual(failure.artifact, "build/manifest.json")
        self.assertEqual(
            failure.rule, ["REQUIRE", "build/manifest.json"]
        )
        self.assertEqual(failure.reason, "required-identical")

    def test_missing_artifact_reports_missing_side(self):
        layout = Layout(
            steps=[
                Step(
                    name="build",
                    expected_products=[["ALLOW", "build/*"]],
                )
            ]
        )
        left = Link(name="build", products={"build/app": A})
        right = Link(name="build", products={})

        with self.assertRaises(ReproducibilityVerificationError) as ctx:
            verify_reproducibility(layout, left, right)

        failure = ctx.exception.failures[0]
        self.assertEqual(failure.side, "right")
        self.assertIsNone(failure.right_hash)
        self.assertEqual(failure.left_hash, A)

    def test_explicit_allow_list_restricts_layout_allow(self):
        # The layout allows both log and timing files to differ, but the
        # release list only names logs. The timing difference is unexplained.
        with self.assertRaises(ReproducibilityVerificationError) as ctx:
            verify_reproducibility(
                self.layout,
                self.left,
                self.right,
                allow_differences=["build/*.log"],
            )

        self.assertEqual(len(ctx.exception.failures), 1)
        failure = ctx.exception.failures[0]
        self.assertEqual(failure.artifact, "build/timings.txt")
        self.assertEqual(failure.side, "right")
        self.assertEqual(failure.rule, ["ALLOW", "build/*.txt"])

    def test_high_level_two_build_directories(self):
        key_dict = {
            tests.common.SignerStore.rsa_pub["keyid"]: (
                tests.common.SignerStore.rsa_pub
            ),
        }
        summary = in_toto_verify(
            self.layout_meta,
            key_dict,
            link_dir_path=str(DEMO / "build-a"),
            reproducibility_link_dir=str(DEMO / "build-b"),
            persist_inspection_links=False,
        )
        self.assertIn("build/build.log", summary.products)


if __name__ == "__main__":
    unittest.main()
