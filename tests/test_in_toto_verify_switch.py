# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

"""Tests for the in-toto-verify-switch command line tool."""

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from in_toto.in_toto_verify_switch import main as verify_switch_main
from in_toto.models.layout import Layout, Step
from in_toto.models.link import Link
from in_toto.models.metadata import Metablock
from tests.common import PEMS, CliTestCase, SignerStore, TmpDirMixin


def _digest(char):
    """Return a valid sha256 hash dictionary."""
    return {"sha256": char * 64}


def _sign(signable, signer):
    """Sign a Layout or Link."""
    metadata = Metablock(signed=signable)
    metadata.create_signature(signer)
    return metadata


class TestInTotoVerifySwitchTool(CliTestCase, TmpDirMixin):
    """CLI exit codes and JSON output."""

    cli_main_func = staticmethod(verify_switch_main)

    @classmethod
    def setUpClass(cls):
        cls.set_up_test_dir()

        fallback_key = SignerStore.rsa_pub
        normal_key = SignerStore.ecdsa_pub
        fallback_layout = _sign(
            Layout(
                steps=[
                    Step(
                        name="fallback-build",
                        pubkeys=[fallback_key["keyid"]],
                    )
                ],
                keys={fallback_key["keyid"]: fallback_key},
                readme="fallback",
            ),
            SignerStore.rsa,
        )
        normal_layout = _sign(
            Layout(
                steps=[
                    Step(name="normal-build", pubkeys=[normal_key["keyid"]])
                ],
                keys={normal_key["keyid"]: normal_key},
                readme="normal",
            ),
            SignerStore.ecdsa,
        )
        fallback_link = _sign(
            Link(
                name="fallback-build",
                materials={"src/base.tar": _digest("1")},
                products={"cache/vendor.tar": _digest("2")},
            ),
            SignerStore.rsa,
        )
        clean_normal_link = _sign(
            Link(
                name="normal-build",
                materials={"src/normal.tar": _digest("3")},
                products={"app.tar.gz": _digest("4")},
            ),
            SignerStore.ecdsa,
        )
        dirty_normal_link = _sign(
            Link(
                name="normal-build",
                materials={"cache/vendor.tar": _digest("2")},
                products={"app.tar.gz": _digest("4")},
            ),
            SignerStore.ecdsa,
        )
        clean_cache = _sign(
            Link(name="cache-bom", materials={}), SignerStore.ed25519
        )
        dirty_cache = _sign(
            Link(
                name="cache-bom",
                materials={"cache/vendor.tar": _digest("2")},
            ),
            SignerStore.ed25519,
        )

        fallback_layout.dump("fallback.layout")
        normal_layout.dump("normal.layout")
        clean_cache.dump("clean-cache.link")
        dirty_cache.dump("dirty-cache.link")

        for directory in ("fallback-links", "clean-normal", "dirty-normal"):
            os.mkdir(directory)

        fallback_link.dump(
            os.path.join(
                "fallback-links",
                f"fallback-build.{fallback_key['keyid'][:8]}.link",
            )
        )
        clean_normal_link.dump(
            os.path.join(
                "clean-normal",
                f"normal-build.{normal_key['keyid'][:8]}.link",
            )
        )
        dirty_normal_link.dump(
            os.path.join(
                "dirty-normal",
                f"normal-build.{normal_key['keyid'][:8]}.link",
            )
        )

    @classmethod
    def tearDownClass(cls):
        cls.tear_down_test_dir()

    def _common_args(self):
        return [
            "--fallback-layout",
            "fallback.layout",
            "--fallback-keys",
            str(PEMS / "rsa_public.pem"),
            "--fallback-link-dir",
            "fallback-links",
            "--normal-layout",
            "normal.layout",
            "--normal-keys",
            str(PEMS / "ecdsa_public.pem"),
            "--cache-keys",
            str(PEMS / "ed25519_public.pem"),
        ]

    def test_clean_normal_release_exits_zero(self):
        """A clean normal release is accepted."""
        self.assert_cli_sys_exit(
            self._common_args()
            + [
                "--normal-link-dir",
                "clean-normal",
                "--cache-bom",
                "clean-cache.link",
            ],
            0,
        )

    def test_dirty_normal_release_exits_one(self):
        """Unreviewed residue yields a quarantine exit code."""
        self.assert_cli_sys_exit(
            self._common_args()
            + [
                "--normal-link-dir",
                "dirty-normal",
                "--cache-bom",
                "dirty-cache.link",
            ],
            1,
        )

    def test_json_output_is_replayable(self):
        """The JSON verdict is stable for identical offline inputs."""
        args = self._common_args() + [
            "--normal-link-dir",
            "clean-normal",
            "--cache-bom",
            "clean-cache.link",
            "--json",
        ]
        payloads = []

        for _ in range(2):
            stdout = io.StringIO()
            with (
                patch.object(sys, "argv", ["in-toto-verify-switch"] + args),
                redirect_stdout(stdout),
                self.assertRaises(SystemExit) as raise_ctx,
            ):
                verify_switch_main()

            self.assertEqual(raise_ctx.exception.code, 0)
            payloads.append(json.loads(stdout.getvalue()))

        self.assertTrue(payloads[0]["release"])
        self.assertEqual(
            payloads[0]["replay_digest"], payloads[1]["replay_digest"]
        )


if __name__ == "__main__":
    unittest.main()
