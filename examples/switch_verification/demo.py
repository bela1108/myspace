"""Replay three small fallback-to-normal release scenarios.

The example creates signed layouts, links, and cache manifests in a temporary
directory, then verifies them offline:

1. the fallback release during the incident is legal,
2. the first normal release after recovery with a clean cache is legal,
3. the first normal release with unreviewed fallback cache residue is
   quarantined, even though a legacy mode marker says ``normal``.
"""

import json
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from securesystemslib.signer import CryptoSigner  # noqa: E402

from in_toto.models.layout import Layout, Step  # noqa: E402
from in_toto.models.link import Link  # noqa: E402
from in_toto.models.metadata import Metablock  # noqa: E402
from in_toto.switch_verify import (  # noqa: E402
    QUARANTINE,
    RELEASE,
    verify_switch_release,
)


def digest(char):
    """Return a valid sha256 hash dictionary."""
    return {"sha256": char * 64}


def public_key(signer):
    """Return a key dictionary with its keyid."""
    key = signer.public_key.to_dict()
    key["keyid"] = signer.public_key.keyid
    return key


def sign(signable, signer):
    """Sign a Layout or Link."""
    metadata = Metablock(signed=signable)
    metadata.create_signature(signer)
    return metadata


def write(metadata, directory, filename):
    """Write signed metadata and return its path."""
    path = Path(directory) / filename
    metadata.dump(str(path))
    return path


def main():  # noqa: PLR0915
    """Run the three scenarios and assert their expected verdicts."""
    fallback_owner = CryptoSigner.generate_ed25519()
    normal_owner = CryptoSigner.generate_ed25519()
    fallback_functionary = CryptoSigner.generate_ed25519()
    normal_functionary = CryptoSigner.generate_ed25519()
    cache_owner = CryptoSigner.generate_ed25519()

    fallback_key = public_key(fallback_functionary)
    normal_key = public_key(normal_functionary)

    fallback_layout = sign(
        Layout(
            steps=[
                Step(name="fallback-build", pubkeys=[fallback_key["keyid"]])
            ],
            keys={fallback_key["keyid"]: fallback_key},
            readme="incident fallback layout",
        ),
        fallback_owner,
    )
    normal_layout = sign(
        Layout(
            steps=[Step(name="normal-build", pubkeys=[normal_key["keyid"]])],
            keys={normal_key["keyid"]: normal_key},
            readme="post-recovery normal layout",
        ),
        normal_owner,
    )

    fallback_link = sign(
        Link(
            name="fallback-build",
            materials={"src/base.tar": digest("1")},
            products={"cache/vendor.tar": digest("2")},
            byproducts={"switch-mode": "fallback"},
        ),
        fallback_functionary,
    )
    clean_normal_link = sign(
        Link(
            name="normal-build",
            materials={"src/normal.tar": digest("3")},
            products={"app.tar.gz": digest("4")},
            byproducts={"switch-mode": "normal"},
        ),
        normal_functionary,
    )
    dirty_normal_link = sign(
        Link(
            name="normal-build",
            materials={"cache/vendor.tar": digest("2")},
            products={"app.tar.gz": digest("4")},
            byproducts={"switch-mode": "normal"},
        ),
        normal_functionary,
    )
    concurrent_fallback_link = sign(
        Link(
            name="normal-build",
            materials={"cache/vendor.tar": digest("2")},
            products={"app.tar.gz": digest("4")},
            byproducts={"switch-mode": "fallback"},
        ),
        fallback_functionary,
    )
    clean_cache_bom = sign(Link(name="cache-bom", materials={}), cache_owner)
    dirty_cache_bom = sign(
        Link(
            name="cache-bom",
            materials={"cache/vendor.tar": digest("2")},
        ),
        cache_owner,
    )

    fallback_keys = {
        fallback_owner.public_key.keyid: public_key(fallback_owner)
    }
    normal_keys = {normal_owner.public_key.keyid: public_key(normal_owner)}
    cache_keys = {cache_owner.public_key.keyid: public_key(cache_owner)}

    with tempfile.TemporaryDirectory() as temp_dir:
        temp = Path(temp_dir)
        fallback_dir = temp / "fallback-links"
        clean_normal_dir = temp / "normal-links-clean"
        dirty_normal_dir = temp / "normal-links-dirty"
        for directory in (fallback_dir, clean_normal_dir, dirty_normal_dir):
            directory.mkdir()

        write(
            fallback_layout,
            temp,
            "fallback.layout",
        )
        write(normal_layout, temp, "normal.layout")
        write(clean_cache_bom, temp, "cache-clean.link")
        write(dirty_cache_bom, temp, "cache-dirty.link")
        write(
            fallback_link,
            fallback_dir,
            f"fallback-build.{fallback_key['keyid'][:8]}.link",
        )
        write(
            clean_normal_link,
            clean_normal_dir,
            f"normal-build.{normal_key['keyid'][:8]}.link",
        )
        write(
            dirty_normal_link,
            dirty_normal_dir,
            f"normal-build.{normal_key['keyid'][:8]}.link",
        )
        # The fallback job briefly coexisted with the normal job.
        write(
            fallback_link,
            dirty_normal_dir,
            f"fallback-build.{fallback_key['keyid'][:8]}.link",
        )
        # The fallback job also recorded the same step name briefly.
        write(
            concurrent_fallback_link,
            dirty_normal_dir,
            f"normal-build.{fallback_key['keyid'][:8]}.link",
        )

        # A legacy last-writer marker claims everything is normal now.
        mode_marker = temp / "mode.json"
        mode_marker.write_text(json.dumps({"mode": "normal"}), encoding="utf8")

        scenarios = [
            (
                "incident fallback release",
                verify_switch_release(
                    fallback_layout,
                    fallback_keys,
                    str(fallback_dir),
                ),
                RELEASE,
            ),
            (
                "first normal release, clean cache",
                verify_switch_release(
                    fallback_layout,
                    fallback_keys,
                    str(fallback_dir),
                    normal_layout,
                    normal_keys,
                    str(clean_normal_dir),
                    cache_bom=clean_cache_bom,
                    cache_keys=cache_keys,
                ),
                RELEASE,
            ),
            (
                "first normal release, unreviewed residue",
                verify_switch_release(
                    fallback_layout,
                    fallback_keys,
                    str(fallback_dir),
                    normal_layout,
                    normal_keys,
                    str(dirty_normal_dir),
                    cache_bom=dirty_cache_bom,
                    cache_keys=cache_keys,
                    mode_marker=str(mode_marker),
                ),
                QUARANTINE,
            ),
        ]

        failed = False
        for title, verdict, expected in scenarios:
            print(f"{title}: {verdict.status}")
            print(f"  phase={verdict.phase} signoffs={verdict.layout_signoffs}")
            print(
                f"  residue={sorted(verdict.junction['residue'])}"
                f" unreviewed={sorted(verdict.junction['unreviewed'])}"
            )
            if verdict.untrusted_mode_hint:
                print(f"  mode marker (ignored): {verdict.untrusted_mode_hint}")
            if verdict.concurrent_modes:
                print(f"  concurrent modes: {verdict.concurrent_modes}")
            print(f"  replay digest: {verdict.replay_digest}")
            print()
            failed = failed or verdict.status != expected

        if failed:
            raise SystemExit("unexpected switch verdict")

        print("all scenarios matched their expected verdicts")


if __name__ == "__main__":
    main()
