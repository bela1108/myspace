# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for fixed-seed batch sampling and review timing checks."""

import tempfile
import unittest
from pathlib import Path

from in_toto import verifylib
from in_toto.exceptions import (
    MaterialSetMismatchError,
    ReviewCutoffError,
)
from in_toto.models.link import Link


class SamplingReviewTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)

        for index in range(1, 5):
            (self.root / f"material-{index}.txt").write_text(
                f"ordinary text material {index}\n", encoding="utf-8"
            )

        self.seed = "unit-test-fixed-batch-seed"
        self.cutoff = "2026-11-25T12:00:00Z"
        self.on_time = "2026-11-25T11:30:00Z"
        self.late = "2026-11-25T12:30:00Z"
        self.materials = verifylib.normalize_material_set(str(self.root))
        self.draw = verifylib.compute_sample_draw(
            seed=self.seed,
            materials=self.materials,
            sample_size=2,
            cutoff=self.cutoff,
        )
        self.selected = list(self.draw.selected)
        self.unselected = next(
            name for name in self.materials if name not in self.selected
        )

    def _reviews(self, timestamp, *, draw=None):
        draw = draw or self.draw
        return {
            name: {
                "reviewed_at": timestamp,
                "reviewer": f"reviewer-{index}",
                "draw_digest": draw.draw_digest,
                "full_set_digest": draw.full_set_digest,
                "cutoff": self.cutoff,
            }
            for index, name in enumerate(draw.selected)
        }

    def test_01_fixed_seed_draw_and_on_time_reviews_pass(self):
        repeated_draw = verifylib.compute_sample_draw(
            seed=self.seed,
            materials=self.materials,
            sample_size=2,
            cutoff=self.cutoff,
        )

        self.assertEqual(repeated_draw.selected, self.draw.selected)
        self.assertEqual(repeated_draw.draw_digest, self.draw.draw_digest)
        self.assertTrue(verifylib.verify_draw_sheet(self.draw, self.materials))

        result = verifylib.verify_sampling_review(
            self.materials,
            self._reviews(self.on_time),
            self.cutoff,
            seed=self.seed,
            sample_size=2,
            raise_on_failure=False,
        )

        self.assertTrue(result.passed)
        self.assertEqual(result.missing, [])
        self.assertEqual(result.late_reviews, [])

    def test_02_replacing_unsampled_material_invalidates_full_set(self):
        replaced_path = self.root / self.unselected
        replaced_path.write_text(
            "replaced ordinary text material\n", encoding="utf-8"
        )
        replaced_set = verifylib.normalize_material_set(str(self.root))

        with self.assertRaises(MaterialSetMismatchError):
            verifylib.verify_full_material_set(
                replaced_set,
                expected_digest=self.draw.full_set_digest,
            )

        stale_result = verifylib.verify_sampling_review(
            replaced_set,
            self._reviews(self.on_time),
            self.cutoff,
            seed=self.seed,
            sample_size=2,
            draw_sheet=self.draw,
            raise_on_failure=False,
        )

        self.assertFalse(stale_result.passed)
        self.assertTrue(stale_result.full_set_changed)
        self.assertTrue(stale_result.requires_full_set_review)
        self.assertIn(self.unselected, stale_result.replaced_materials)

        new_draw = verifylib.compute_sample_draw(
            seed=self.seed,
            materials=replaced_set,
            sample_size=2,
            cutoff=self.cutoff,
        )
        rechecked_result = verifylib.verify_sampling_review(
            replaced_set,
            self._reviews(self.on_time, draw=new_draw),
            self.cutoff,
            seed=self.seed,
            sample_size=2,
            expected_draw_digest=new_draw.draw_digest,
            expected_full_set_digest=new_draw.full_set_digest,
            raise_on_failure=False,
        )

        self.assertTrue(rechecked_result.passed)
        self.assertEqual(rechecked_result.replaced_materials, [])

    def test_03_late_confirmation_is_retained_but_does_not_pass(self):
        late_reviews = self._reviews(self.late)

        self.assertTrue(verifylib.is_review_on_time(self.on_time, self.cutoff))
        self.assertFalse(verifylib.is_review_on_time(self.late, self.cutoff))
        with self.assertRaises(ReviewCutoffError):
            verifylib.verify_review_time(self.late, self.cutoff)

        result = verifylib.verify_sampling_review(
            self.materials,
            late_reviews,
            self.cutoff,
            seed=self.seed,
            sample_size=2,
            raise_on_failure=False,
        )

        self.assertFalse(result.passed)
        self.assertEqual(set(result.missing), set(self.selected))
        self.assertEqual(len(result.late_reviews), 2)
        self.assertIs(result.recheck_queue, result.late_reviews)

        with self.assertRaises(ReviewCutoffError):
            verifylib.verify_sampling_review(
                self.materials,
                late_reviews,
                self.cutoff,
                seed=self.seed,
                sample_size=2,
                raise_on_failure=True,
            )

    def test_04_signed_link_materials_form_the_full_set(self):
        link = Link(name="build", materials=self.materials)

        collected = verifylib.collect_signed_material_set(link)

        self.assertEqual(collected, self.materials)
        self.assertEqual(
            verifylib.material_set_digest(collected),
            self.draw.full_set_digest,
        )


if __name__ == "__main__":
    unittest.main()
