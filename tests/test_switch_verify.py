# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for offline fallback-to-normal switch verification."""

import json
import os
import tempfile
import unittest

import securesystemslib.exceptions
from securesystemslib.signer import CryptoSigner

import in_toto.exceptions
from in_toto.models.layout import Layout, Step
from in_toto.models.link import FILENAME_FORMAT, Link
from in_toto.models.metadata import Metablock
from in_toto.switch_verify import (
    FALLBACK,
    NORMAL,
    QUARANTINE,
    RELEASE,
    assess_junction,
    verify_switch_release,
)


def _digest(char):
    """Return a valid SHA-256 hash dictionary for test artifacts."""
    return {"sha256": char * 64}


def _public_key(signer):
    """Return a key dictionary suitable for layouts and verification."""
    key = signer.public_key.to_dict()
    key["keyid"] = signer.public_key.keyid
    return key


def _sign(signable, signer):
    """Sign a Layout or Link and return a Metablock."""
    metadata = Metablock(signed=signable)
    metadata.create_signature(signer)
    return metadata


def _layout(step_name, functionary_signer, readme):
    """Create a one-step layout with the given functionary."""
    key = _public_key(functionary_signer)
    return Layout(
        steps=[Step(name=step_name, pubkeys=[key["keyid"]])],
        keys={key["keyid"]: key},
        readme=readme,
    )


def _link(step_name, materials, products, signer, mode=None):
    """Create and sign a Link, optionally carrying a mode claim."""
    kwargs = {
        "name": step_name,
        "materials": materials,
        "products": products,
    }
    if mode is not None:
        kwargs["byproducts"] = {"switch-mode": mode}

    return _sign(Link(**kwargs), signer)


def _bom(name, materials, signer):
    """Create and sign a material manifest Link."""
    return _sign(Link(name=name, materials=materials), signer)


class TestSwitchVerify(unittest.TestCase):
    """Offline switch verification behaviour."""

    @classmethod
    def setUpClass(cls):
        """Create independent owner, functionary and review keys."""
        cls.fallback_owner = CryptoSigner.generate_ed25519()
        cls.normal_owner = CryptoSigner.generate_ed25519()
        cls.fallback_functionary = CryptoSigner.generate_ed25519()
        cls.normal_functionary = CryptoSigner.generate_ed25519()
        cls.other_normal_functionary = CryptoSigner.generate_ed25519()
        cls.cache_owner = CryptoSigner.generate_ed25519()
        cls.reviewer = CryptoSigner.generate_ed25519()
        cls.intruder = CryptoSigner.generate_ed25519()

        cls.fallback_layout = _sign(
            _layout(
                "fallback-build",
                cls.fallback_functionary,
                "incident fallback layout",
            ),
            cls.fallback_owner,
        )
        cls.normal_layout = _sign(
            _layout(
                "normal-build",
                cls.normal_functionary,
                "post-recovery normal layout",
            ),
            cls.normal_owner,
        )

        cls.fallback_link = _link(
            "fallback-build",
            {"src/base.tar": _digest("a")},
            {"cache/vendor.tar": _digest("b")},
            cls.fallback_functionary,
            mode="fallback",
        )

        cls.clean_normal_link = _link(
            "normal-build",
            {"src/normal.tar": _digest("d")},
            {"app.tar.gz": _digest("c")},
            cls.normal_functionary,
            mode="normal",
        )

        cls.dirty_normal_link = _link(
            "normal-build",
            {"cache/vendor.tar": _digest("b")},
            {"app.tar.gz": _digest("c")},
            cls.normal_functionary,
            mode="normal",
        )

        cls.dirty_cache_bom = _bom(
            "cache-bom", {"cache/vendor.tar": _digest("b")}, cls.cache_owner
        )
        cls.clean_cache_bom = _bom("cache-bom", {}, cls.cache_owner)
        cls.review_bom = _bom(
            "review-bom", {"cache/vendor.tar": _digest("b")}, cls.reviewer
        )
        cls.wrong_digest_review_bom = _bom(
            "review-bom", {"cache/vendor.tar": _digest("f")}, cls.reviewer
        )

        cls.layout_keys = {
            FALLBACK: {
                cls.fallback_owner.public_key.keyid: _public_key(
                    cls.fallback_owner
                )
            },
            NORMAL: {
                cls.normal_owner.public_key.keyid: _public_key(cls.normal_owner)
            },
        }
        cls.review_keys = {
            cls.reviewer.public_key.keyid: _public_key(cls.reviewer)
        }
        cls.cache_keys = {
            cls.cache_owner.public_key.keyid: _public_key(cls.cache_owner)
        }
        cls.intruder_keys = {
            cls.intruder.public_key.keyid: _public_key(cls.intruder)
        }

    def _verify(self, **overrides):
        """Verify a normal switch with sensible test defaults."""
        arguments = {
            "fallback_layout": self.fallback_layout,
            "fallback_layout_keys": self.layout_keys[FALLBACK],
            "fallback_links": {
                "fallback-build": {
                    self.fallback_functionary.public_key.keyid: self.fallback_link
                }
            },
            "normal_layout": self.normal_layout,
            "normal_layout_keys": self.layout_keys[NORMAL],
            "normal_links": {
                "normal-build": {
                    self.normal_functionary.public_key.keyid: self.clean_normal_link
                }
            },
            "cache_bom": self.clean_cache_bom,
            "cache_keys": self.cache_keys,
            "review_keys": self.review_keys,
        }
        arguments.update(overrides)
        return verify_switch_release(**arguments)

    def test_fallback_release_is_legal(self):
        """A signed fallback release is legal on its own."""
        verdict = verify_switch_release(
            self.fallback_layout,
            self.layout_keys[FALLBACK],
            {
                "fallback-build": {
                    self.fallback_functionary.public_key.keyid: self.fallback_link
                }
            },
        )

        self.assertEqual(verdict.status, RELEASE)
        self.assertEqual(verdict.phase, FALLBACK)
        self.assertEqual(
            verdict.layout_signoffs[FALLBACK],
            [self.fallback_owner.public_key.keyid],
        )
        self.assertEqual(verdict.violations, [])

    def test_first_normal_release_with_clean_cache_is_legal(self):
        """A normal release whose cache holds no fallback residue is legal."""
        verdict = self._verify()

        self.assertEqual(verdict.status, RELEASE)
        self.assertEqual(verdict.phase, NORMAL)
        self.assertEqual(
            verdict.layout_signoffs[FALLBACK],
            [self.fallback_owner.public_key.keyid],
        )
        self.assertEqual(
            verdict.layout_signoffs[NORMAL],
            [self.normal_owner.public_key.keyid],
        )
        self.assertEqual(verdict.junction["residue"], {})

    def test_unreviewed_cache_residue_is_quarantined(self):
        """Fallback output consumed by the normal build stays quarantined."""
        verdict = self._verify(
            normal_links={
                "normal-build": {
                    self.normal_functionary.public_key.keyid: self.dirty_normal_link
                }
            },
            cache_bom=self.dirty_cache_bom,
        )

        self.assertEqual(verdict.status, QUARANTINE)
        self.assertEqual(
            [violation["type"] for violation in verdict.violations],
            ["unreviewed_cache_residue"],
        )
        self.assertIn("cache/vendor.tar", verdict.junction["unreviewed"])
        self.assertIn("cache/vendor.tar", verdict.junction["consumed"])

    def test_reviewed_cache_residue_is_released(self):
        """A signed review of the exact path and digest unblocks release."""
        verdict = self._verify(
            normal_links={
                "normal-build": {
                    self.normal_functionary.public_key.keyid: self.dirty_normal_link
                }
            },
            cache_bom=self.dirty_cache_bom,
            review_bom=self.review_bom,
        )

        self.assertEqual(verdict.status, RELEASE)
        self.assertEqual(verdict.violations, [])
        self.assertIn("cache/vendor.tar", verdict.junction["reviewed"])
        self.assertEqual(verdict.junction["unreviewed"], {})

    def test_review_with_wrong_digest_does_not_release(self):
        """A review cannot approve a different artifact digest."""
        verdict = self._verify(
            normal_links={
                "normal-build": {
                    self.normal_functionary.public_key.keyid: self.dirty_normal_link
                }
            },
            cache_bom=self.dirty_cache_bom,
            review_bom=self.wrong_digest_review_bom,
        )

        self.assertEqual(verdict.status, QUARANTINE)
        self.assertIn("cache/vendor.tar", verdict.junction["unreviewed"])

    def test_layout_signoffs_are_attributed_per_layout(self):
        """A foreign signature on one layout is rejected."""
        fallback_layout = _sign(
            _layout(
                "fallback-build",
                self.fallback_functionary,
                "incident fallback layout",
            ),
            self.fallback_owner,
        )
        fallback_layout.create_signature(self.intruder)

        with self.assertRaises(in_toto.exceptions.SwitchVerificationError):
            self._verify(fallback_layout=fallback_layout)

    def test_shared_layout_signers_can_be_rejected(self):
        """Two layouts cannot share a manual sign-off when policy forbids it."""
        normal_layout = _sign(
            _layout(
                "normal-build",
                self.normal_functionary,
                "post-recovery normal layout",
            ),
            self.fallback_owner,
        )

        with self.assertRaises(in_toto.exceptions.SwitchVerificationError):
            self._verify(
                normal_layout=normal_layout,
                normal_layout_keys=self.layout_keys[FALLBACK],
                require_distinct_layout_signers=True,
            )

    def test_lingering_fallback_link_is_not_hidden_by_mode_marker(self):
        """A last-written 'normal' marker cannot hide concurrent fallback work."""
        with tempfile.TemporaryDirectory() as temp_dir:
            marker_path = os.path.join(temp_dir, "mode.json")
            with open(marker_path, "w", encoding="utf8") as file_object:
                json.dump({"mode": "normal"}, file_object)

            verdict = self._verify(
                normal_links={
                    "normal-build": {
                        self.normal_functionary.public_key.keyid: self.clean_normal_link
                    },
                    # The fallback job briefly coexisted in the normal dir.
                    "fallback-build": {
                        self.fallback_functionary.public_key.keyid: self.fallback_link
                    },
                },
                cache_bom=self.dirty_cache_bom,
                mode_marker=marker_path,
            )

        self.assertEqual(verdict.untrusted_mode_hint, "normal")
        self.assertEqual(verdict.status, QUARANTINE)
        self.assertIn("cache/vendor.tar", verdict.junction["residue"])

    def test_mode_marker_does_not_change_replay_result(self):
        """Replay depends on signed evidence, not the marker value."""
        first = self._verify(mode_marker={"mode": "normal"})
        second = self._verify(mode_marker={"mode": "fallback"})

        self.assertEqual(first.status, second.status)
        self.assertEqual(first.replay_digest, second.replay_digest)
        self.assertNotEqual(
            first.untrusted_mode_hint, second.untrusted_mode_hint
        )

    def test_coexisting_step_links_are_reported(self):
        """Links from both sides of the switch are visible per step."""
        fallback_signed_normal_link = _link(
            "normal-build",
            {"src/normal.tar": _digest("d")},
            {"app.tar.gz": _digest("c")},
            self.fallback_functionary,
            mode="fallback",
        )
        verdict = self._verify(
            normal_links={
                "normal-build": {
                    self.normal_functionary.public_key.keyid: self.clean_normal_link,
                    self.fallback_functionary.public_key.keyid: fallback_signed_normal_link,
                }
            }
        )

        self.assertEqual(
            verdict.concurrent_modes["normal-build"],
            [FALLBACK, NORMAL],
        )

    def test_conflicting_links_with_same_signer_fail_closed(self):
        """Duplicate links for one signer are not resolved by write order."""
        other_link = _link(
            "normal-build",
            {"src/normal.tar": _digest("d")},
            {"app.tar.gz": _digest("e")},
            self.normal_functionary,
            mode="normal",
        )

        with self.assertRaises(in_toto.exceptions.ConcurrentModeError):
            self._verify(normal_links=[self.clean_normal_link, other_link])

    def test_conflicting_links_with_different_signers_fail_closed(self):
        """Authorized concurrent links must agree even with threshold one."""
        key_one = _public_key(self.normal_functionary)
        key_two = _public_key(self.other_normal_functionary)
        layout = Layout(
            steps=[
                Step(
                    name="normal-build",
                    pubkeys=[key_one["keyid"], key_two["keyid"]],
                    threshold=1,
                )
            ],
            keys={
                key_one["keyid"]: key_one,
                key_two["keyid"]: key_two,
            },
            readme="concurrent normal layout",
        )
        normal_layout = _sign(layout, self.normal_owner)
        other_link = _link(
            "normal-build",
            {"src/normal.tar": _digest("d")},
            {"app.tar.gz": _digest("e")},
            self.other_normal_functionary,
            mode="normal",
        )

        with self.assertRaises(in_toto.exceptions.ConcurrentModeError):
            self._verify(
                normal_layout=normal_layout,
                normal_links={
                    "normal-build": {
                        key_one["keyid"]: self.clean_normal_link,
                        key_two["keyid"]: other_link,
                    }
                },
            )

    def test_links_can_be_loaded_from_directories(self):
        """Verification supports link dirs and ignores unfinished files."""
        with (
            tempfile.TemporaryDirectory() as fallback_dir,
            tempfile.TemporaryDirectory() as normal_dir,
        ):
            fallback_path = os.path.join(
                fallback_dir,
                FILENAME_FORMAT.format(
                    step_name="fallback-build",
                    keyid=self.fallback_functionary.public_key.keyid,
                ),
            )
            self.fallback_link.dump(fallback_path)

            normal_path = os.path.join(
                normal_dir,
                FILENAME_FORMAT.format(
                    step_name="normal-build",
                    keyid=self.normal_functionary.public_key.keyid,
                ),
            )
            self.clean_normal_link.dump(normal_path)

            unfinished = os.path.join(
                normal_dir, ".normal-build.abc.link-unfinished"
            )
            with open(unfinished, "w", encoding="utf8") as file_object:
                file_object.write("not json")

            verdict = self._verify(
                fallback_links=fallback_dir,
                normal_links=normal_dir,
            )

        self.assertEqual(verdict.status, RELEASE)

    def test_unsigned_manifest_is_rejected_by_default(self):
        """A bare Link cannot act as a signed review manifest."""
        review_link = Link(
            name="review-bom",
            materials={"cache/vendor.tar": _digest("b")},
        )

        with self.assertRaises(in_toto.exceptions.SwitchVerificationError):
            self._verify(review_bom=review_link)

    def test_unsigned_manifest_can_be_explicitly_allowed(self):
        """Local experiments can opt in to an unsigned manifest."""
        review_link = Link(
            name="review-bom",
            materials={"cache/vendor.tar": _digest("b")},
        )

        verdict = self._verify(
            normal_links={
                "normal-build": {
                    self.normal_functionary.public_key.keyid: self.dirty_normal_link
                }
            },
            cache_bom=self.dirty_cache_bom,
            review_bom=review_link,
            allow_unsigned_bom=True,
        )

        self.assertEqual(verdict.status, RELEASE)

    def test_manifest_signed_by_wrong_key_is_rejected(self):
        """A manifest must be signed by the designated manifest keys."""
        forged_cache_bom = _bom(
            "cache-bom", {"cache/vendor.tar": _digest("b")}, self.intruder
        )

        with self.assertRaises(in_toto.exceptions.SwitchVerificationError):
            self._verify(cache_bom=forged_cache_bom)

    def test_junction_detects_divergent_cache_hashes(self):
        """A cache path with a conflicting digest is a junction violation."""
        junction = assess_junction(
            {"cache/vendor.tar": _digest("b")},
            {"cache/vendor.tar": _digest("b")},
            cache_entries={"cache/vendor.tar": _digest("e")},
        )

        self.assertTrue(junction["unreviewed"])
        self.assertTrue(junction["divergences"])

    def test_junction_detects_relocated_fallback_content(self):
        """Renaming fallback output in the cache does not hide its content."""
        junction = assess_junction(
            {"cache/vendor.tar": _digest("b")},
            {"cache/renamed-vendor.tar": _digest("b")},
            cache_entries={"cache/renamed-vendor.tar": _digest("b")},
        )

        self.assertIn("cache/renamed-vendor.tar", junction["residue"])
        self.assertIn("cache/renamed-vendor.tar", junction["unreviewed"])
        self.assertEqual(
            junction["relocated"][0]["original_paths"],
            ["cache/vendor.tar"],
        )

    def test_review_of_relocated_content_unblocks_release(self):
        """A reviewer can approve relocated content by its new path and hash."""
        verdict = self._verify(
            normal_links={
                "normal-build": {
                    self.normal_functionary.public_key.keyid: _link(
                        "normal-build",
                        {"cache/renamed-vendor.tar": _digest("b")},
                        {"app.tar.gz": _digest("c")},
                        self.normal_functionary,
                    )
                }
            },
            cache_bom=_bom(
                "cache-bom",
                {"cache/renamed-vendor.tar": _digest("b")},
                self.cache_owner,
            ),
            review_bom=_bom(
                "review-bom",
                {"cache/renamed-vendor.tar": _digest("b")},
                self.reviewer,
            ),
        )

        self.assertEqual(verdict.status, RELEASE)
        self.assertEqual(verdict.junction["unreviewed"], {})

    def test_invalid_manifest_threshold_is_rejected(self):
        """A zero signature threshold cannot bypass manifest verification."""
        with self.assertRaises(securesystemslib.exceptions.FormatError):
            self._verify(review_threshold=0)

    def test_multi_signed_link_does_not_inflate_threshold(self):
        """One link with two signatures counts as one functionary only."""
        key_one = _public_key(self.normal_functionary)
        key_two = _public_key(self.other_normal_functionary)
        layout = Layout(
            steps=[
                Step(
                    name="normal-build",
                    pubkeys=[key_one["keyid"], key_two["keyid"]],
                    threshold=2,
                )
            ],
            keys={
                key_one["keyid"]: key_one,
                key_two["keyid"]: key_two,
            },
            readme="two-functionary normal layout",
        )
        normal_layout = _sign(layout, self.normal_owner)
        multi_signed_link = _link(
            "normal-build",
            {"src/normal.tar": _digest("d")},
            {"app.tar.gz": _digest("c")},
            self.normal_functionary,
        )
        multi_signed_link.create_signature(self.other_normal_functionary)

        with self.assertRaises(in_toto.exceptions.ThresholdVerificationError):
            self._verify(
                normal_layout=normal_layout,
                normal_links={
                    "normal-build": {
                        key_one["keyid"]: multi_signed_link,
                        key_two["keyid"]: multi_signed_link,
                    }
                },
            )

    def test_divergent_cache_hash_is_quarantined(self):
        """A cache snapshot with a conflicting digest fails closed."""
        divergent_cache_bom = _bom(
            "cache-bom", {"cache/vendor.tar": _digest("e")}, self.cache_owner
        )
        verdict = self._verify(
            normal_links={
                "normal-build": {
                    self.normal_functionary.public_key.keyid: self.dirty_normal_link
                }
            },
            cache_bom=divergent_cache_bom,
        )

        self.assertEqual(verdict.status, QUARANTINE)
        self.assertIn(
            "divergent_cache_entry",
            [violation["type"] for violation in verdict.violations],
        )

    def test_missing_cache_manifest_assumes_residue(self):
        """Without a cache snapshot, all fallback output stays suspicious."""
        verdict = self._verify(
            normal_links={
                "normal-build": {
                    self.normal_functionary.public_key.keyid: self.dirty_normal_link
                }
            },
            cache_bom=None,
        )

        self.assertEqual(verdict.status, QUARANTINE)
        self.assertIn("cache/vendor.tar", verdict.junction["residue"])

    def test_plain_mode_marker_is_reported_but_ignored(self):
        """A non-JSON marker value is diagnostic only."""
        verdict = self._verify(mode_marker="normal")

        self.assertEqual(verdict.status, RELEASE)
        self.assertEqual(verdict.untrusted_mode_hint, "normal")

    def test_verdict_supports_dictionary_access(self):
        """The verdict exposes dictionary-style fields for integrations."""
        verdict = self._verify()

        self.assertEqual(verdict["status"], RELEASE)
        self.assertEqual(verdict.get("phase"), NORMAL)
        self.assertIn("layout_signoffs", verdict.keys())

    def test_missing_link_directory_is_rejected(self):
        """A non-existent link directory is an explicit failure."""
        with self.assertRaises(in_toto.exceptions.SwitchVerificationError):
            self._verify(fallback_links="/does/not/exist")

    def test_cache_threshold_must_be_positive(self):
        """A zero cache threshold cannot bypass manifest verification."""
        with self.assertRaises(securesystemslib.exceptions.FormatError):
            self._verify(cache_threshold=0)

    def test_quarantined_verdict_can_raise(self):
        """Callers can turn a quarantine verdict into an exception."""
        verdict = self._verify(
            normal_links={
                "normal-build": {
                    self.normal_functionary.public_key.keyid: self.dirty_normal_link
                }
            },
            cache_bom=self.dirty_cache_bom,
        )

        self.assertTrue(verdict.is_quarantined)
        with self.assertRaises(in_toto.exceptions.SwitchVerificationError):
            verdict.raise_for_status()

        self._verify().raise_for_status()

    def test_signed_artifact_rules_are_replayed(self):
        """A layout DISALLOW rule stops a normal release offline."""
        key = _public_key(self.normal_functionary)
        step = Step(name="normal-build", pubkeys=[key["keyid"]])
        step.add_material_rule_from_string("DISALLOW *")
        normal_layout = _sign(
            Layout(
                steps=[step],
                keys={key["keyid"]: key},
                readme="rules normal layout",
            ),
            self.normal_owner,
        )

        with self.assertRaises(in_toto.exceptions.RuleVerificationError):
            self._verify(
                normal_layout=normal_layout,
                normal_links={
                    "normal-build": {key["keyid"]: self.clean_normal_link}
                },
            )

    def test_verdict_is_json_serializable(self):
        """The audit verdict can be persisted and replayed."""
        verdict = self._verify()
        dumped = json.loads(json.dumps(verdict.to_dict(), sort_keys=True))

        self.assertTrue(dumped["release"])
        self.assertEqual(dumped["replay_digest"], verdict.replay_digest)


if __name__ == "__main__":
    unittest.main()
