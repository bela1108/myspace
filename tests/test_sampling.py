# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for deterministic release sampling acceptance."""

import hashlib
import json
import unittest
from pathlib import Path

from in_toto.exceptions import (
    SamplingCutoffError,
    SamplingFullSetChangedError,
    SamplingVerificationError,
    SignatureVerificationError,
)
from in_toto.models.layout import Layout, Step
from in_toto.models.link import FILENAME_FORMAT, Link
from in_toto.models.metadata import Metablock, Metadata
from in_toto.sampling import (
    SAMPLING_VERSION,
    SamplingDraw,
    SamplingPolicy,
    collect_full_set,
    compute_draw_sheet,
    create_review_evidence,
    verify_draw_sheet,
    verify_sampling_acceptance,
)
from in_toto.verifylib import in_toto_verify
from tests.common import SignerStore, TmpDirMixin

ARTIFACT_NAMES = ("alpha", "beta", "gamma", "delta")


def hash_bytes(data):
    return {"sha256": hashlib.sha256(data).hexdigest()}


class TestReleaseSampling(unittest.TestCase, TmpDirMixin):
    """Exercise pass, full-set replacement and cutoff scenarios in order."""

    @classmethod
    def setUpClass(cls):
        cls.set_up_test_dir()
        Path("materials").mkdir()

        cls.full_set = {}
        for name in ARTIFACT_NAMES:
            path = f"materials/{name}.txt"
            with open(path, "wb") as file_object:
                file_object.write(f"ordinary text: {name}\n".encode())
            with open(path, "rb") as file_object:
                cls.full_set[path] = hash_bytes(file_object.read())

        cls.cutoff = "2026-11-23T12:00:00Z"
        cls.policy = SamplingPolicy(
            seed="batch-2026-11-23",
            sample_size=2,
            cutoff=cls.cutoff,
            reviewers=[SignerStore.rsa_pub["keyid"]],
            steps=["package"],
            artifact_type="materials",
        )
        cls.review_keys = {SignerStore.rsa_pub["keyid"]: SignerStore.rsa_pub}
        cls.draw = compute_draw_sheet(cls.policy, cls.full_set)
        cls.reviews = [
            create_review_evidence(
                artifact_id,
                cls.full_set[artifact_id],
                cls.draw,
                "2026-11-23T10:00:00Z",
                SignerStore.rsa,
            )
            for artifact_id in cls.draw.selected
        ]

    @classmethod
    def tearDownClass(cls):
        cls.tear_down_test_dir()

    def test_01_passing_sample_is_recomputable(self):
        """Two of four text materials pass with on-time signed reviews."""
        self.assertEqual(len(self.full_set), 4)
        self.assertEqual(len(self.draw.selected), 2)
        self.assertTrue(set(self.draw.selected) <= set(self.full_set))

        reversed_full_set = dict(reversed(list(self.full_set.items())))
        recomputed = compute_draw_sheet(self.policy, reversed_full_set)
        self.assertEqual(recomputed.selected, self.draw.selected)
        self.assertEqual(recomputed.sample_digest, self.draw.sample_digest)

        self.draw.dump("draw-sheet.json")
        loaded = SamplingDraw.load("draw-sheet.json")
        with open("draw-sheet.json", encoding="utf8") as file_object:
            serialized = json.load(file_object)
        self.assertEqual(serialized["version"], SAMPLING_VERSION)
        self.assertEqual(serialized["selected"], self.draw.selected)
        self.assertEqual(
            verify_draw_sheet(loaded, self.policy, self.full_set).sample_digest,
            self.draw.sample_digest,
        )

        result = verify_sampling_acceptance(
            self.policy,
            self.full_set,
            self.reviews,
            review_keys=self.review_keys,
            draw_sheet=loaded,
            write_draw_sheet="draw-sheet-verified.json",
        )
        self.assertTrue(result.passed)
        self.assertSetEqual(set(result.accepted), set(self.draw.selected))
        self.assertFalse(result.missing)
        self.assertFalse(result.invalid)
        self.assertFalse(result.late)

    def test_02_replacing_an_unsampled_material_rechecks_full_set(self):
        """A change to any material invalidates the old draw and evidence."""
        unsampled = sorted(set(self.full_set) - set(self.draw.selected))[0]
        replaced_full_set = dict(self.full_set)
        replaced_full_set[unsampled] = hash_bytes(b"replacement material\n")

        with self.assertRaises(SamplingFullSetChangedError) as context:
            verify_draw_sheet(self.draw, self.policy, replaced_full_set)

        error = context.exception
        self.assertIn(unsampled, error.changed)
        self.assertEqual(error.expected_digest, self.draw.full_set_digest)
        self.assertNotEqual(error.actual_digest, self.draw.full_set_digest)

        with self.assertRaises(SamplingFullSetChangedError) as context:
            verify_sampling_acceptance(
                self.policy,
                replaced_full_set,
                self.reviews,
                review_keys=self.review_keys,
                draw_sheet=self.draw,
            )
        self.assertIn(unsampled, context.exception.changed)

        replacement_draw = compute_draw_sheet(self.policy, replaced_full_set)
        self.assertNotEqual(
            replacement_draw.full_set_digest, self.draw.full_set_digest
        )
        self.assertEqual(len(replacement_draw.selected), 2)

        with self.assertRaises(SamplingVerificationError) as context:
            verify_sampling_acceptance(
                self.policy,
                replaced_full_set,
                self.reviews,
                review_keys=self.review_keys,
                draw_sheet=replacement_draw,
            )
        self.assertFalse(context.exception.result.passed)
        self.assertTrue(context.exception.result.invalid)
        self.assertEqual(
            len(context.exception.result.missing),
            len(replacement_draw.selected),
        )

        replacement_reviews = [
            create_review_evidence(
                artifact_id,
                replaced_full_set[artifact_id],
                replacement_draw,
                "2026-11-23T10:00:00Z",
                SignerStore.rsa,
            )
            for artifact_id in replacement_draw.selected
        ]
        result = verify_sampling_acceptance(
            self.policy,
            replaced_full_set,
            replacement_reviews,
            review_keys=self.review_keys,
            draw_sheet=replacement_draw,
        )
        self.assertTrue(result.passed)
        self.assertSetEqual(
            set(result.accepted), set(replacement_draw.selected)
        )

    def test_03_review_after_cutoff_is_retained_for_rereview(self):
        """A late signature does not pass, but remains available for re-review."""
        late_artifact = self.draw.selected[0]
        on_time_artifact = self.draw.selected[1]
        late_time = "2026-11-23T12:00:01Z"

        late_review = create_review_evidence(
            late_artifact,
            self.full_set[late_artifact],
            self.draw,
            late_time,
            SignerStore.rsa,
        )
        on_time_review = create_review_evidence(
            on_time_artifact,
            self.full_set[on_time_artifact],
            self.draw,
            "2026-11-23T11:59:59Z",
            SignerStore.rsa,
        )

        with self.assertRaises(SamplingCutoffError) as context:
            verify_sampling_acceptance(
                self.policy,
                self.full_set,
                [late_review, on_time_review],
                review_keys=self.review_keys,
                draw_sheet=self.draw,
                write_result="late-result.json",
            )

        result = context.exception.result
        self.assertIn(late_artifact, result.late)
        self.assertIn(late_artifact, result.missing)
        self.assertIn(on_time_artifact, result.accepted)
        self.assertEqual(result.late[late_artifact][0].reviewed_at, late_time)

        with open("late-result.json", encoding="utf8") as file_object:
            serialized = json.load(file_object)
        self.assertIn(late_artifact, serialized["late"])
        self.assertEqual(
            serialized["late"][late_artifact][0]["reviewed_at"], late_time
        )

        re_review = create_review_evidence(
            late_artifact,
            self.full_set[late_artifact],
            self.draw,
            "2026-11-23T12:00:00Z",
            SignerStore.rsa,
        )
        result = verify_sampling_acceptance(
            self.policy,
            self.full_set,
            [late_review, on_time_review, re_review],
            review_keys=self.review_keys,
            draw_sheet=self.draw,
        )
        self.assertTrue(result.passed)
        self.assertIn(late_artifact, result.late)
        self.assertIn(late_artifact, result.accepted)

    def test_04_layout_signature_binds_sampling_policy(self):
        """A sampling policy is covered by the owner-signed layout."""
        owner = SignerStore.ed25519
        owner_pub = SignerStore.ed25519_pub
        functionary = SignerStore.ecdsa
        functionary_pub = SignerStore.ecdsa_pub

        step = Step(
            name="package",
            pubkeys=[functionary_pub["keyid"]],
            expected_materials=[["ALLOW", "*"]],
            expected_products=[["ALLOW", "*"]],
        )
        layout = Layout(
            steps=[step],
            keys={
                functionary_pub["keyid"]: functionary_pub,
                SignerStore.rsa_pub["keyid"]: SignerStore.rsa_pub,
            },
            sampling=self.policy,
            expires="2099-01-01T00:00:00Z",
        )
        layout_metadata = Metablock(signed=layout)
        layout_metadata.create_signature(owner)

        link_metadata = Metablock(
            signed=Link(
                name="package",
                materials=self.full_set,
                products={},
            )
        )
        link_metadata.create_signature(functionary)
        link_path = FILENAME_FORMAT.format(
            step_name="package", keyid=functionary_pub["keyid"]
        )
        link_metadata.dump(link_path)
        layout_metadata.dump("sampling.layout")
        layout_metadata = Metadata.load("sampling.layout")

        reviews = [
            create_review_evidence(
                artifact_id,
                self.full_set[artifact_id],
                self.draw,
                "2026-11-23T10:00:00Z",
                SignerStore.rsa,
            )
            for artifact_id in self.draw.selected
        ]

        summary = in_toto_verify(
            layout_metadata,
            {owner_pub["keyid"]: owner_pub},
            sampling_review_metadata=reviews,
            sampling_draw_sheet_path="integrated-draw.json",
            sampling_result_path="integrated-result.json",
        )
        self.assertEqual(summary.name, "")
        self.assertTrue(Path("integrated-draw.json").exists())
        self.assertTrue(Path("integrated-result.json").exists())

        # A changed policy breaks the layout signature, not just the sampling
        # check, because the policy is part of the signed layout.
        layout_metadata.signed.sampling = SamplingPolicy.read(
            {
                **self.policy.to_dict(),
                "seed": "different-batch",
            }
        )
        with self.assertRaises(SignatureVerificationError):
            in_toto_verify(
                layout_metadata,
                {owner_pub["keyid"]: owner_pub},
                sampling_review_metadata=reviews,
            )


class TestSamplingFullSet(unittest.TestCase):
    """Small unit tests for full-set collection from verified links."""

    def test_collect_full_set_from_verified_metadata(self):
        materials = {
            "notes/a.txt": hash_bytes(b"a"),
            "notes/b.txt": hash_bytes(b"b"),
            "notes/c.txt": hash_bytes(b"c"),
            "notes/d.txt": hash_bytes(b"d"),
        }
        metadata = Metablock(
            signed=Link(name="package", materials=materials, products={})
        )
        verified = {"package": {SignerStore.rsa_pub["keyid"]: metadata}}
        self.assertEqual(
            collect_full_set(verified, artifact_type="materials"),
            materials,
        )
