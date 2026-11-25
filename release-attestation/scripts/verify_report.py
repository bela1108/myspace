#!/usr/bin/env python3
"""Independently re-verify a public in-toto attestation bundle.

The verifier is self-contained: it only reads the public bundle directory and
the functionary public keys shipped inside that bundle. It never reads the
internal layout or any internal working path. Exit code 0 means every check in
the report was re-derived successfully; exit code 1 means the chain is broken
and the printed verdict names the exact missing link or failed check.
"""

import hashlib
import json
import sys
from pathlib import Path

from in_toto.models.metadata import Metadata
from in_toto.rulelib import unpack_rule
from in_toto.verifylib import verify_match_rule

HERE = Path(__file__).resolve().parents[1]
DEFAULT_BUNDLE = HERE / "public"


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fail(check, detail):
    return {"check": check, "ok": False, "detail": detail}


def ok(check, detail):
    return {"check": check, "ok": True, "detail": detail}


def main():
    if len(sys.argv) > 1:
        bundle = Path(sys.argv[1]).resolve()
    else:
        bundle = DEFAULT_BUNDLE
    evidence = bundle / "evidence"
    results = []
    report = json.loads((bundle / "attestation-report.json").read_text())
    keys = json.loads((bundle / "disclosed-keys.json").read_text())
    manifest = json.loads((bundle / "bundle-manifest.json").read_text())

    # 1. Bundle tamper-evidence: every shipped file matches the manifest.
    for name, expected in manifest["files"]:
        path = bundle / name
        if not path.exists():
            path = evidence / name
        if not path.exists():
            results.append(fail(f"manifest:{name}", "file missing from bundle"))
        elif sha256_file(path) != expected:
            results.append(fail(f"manifest:{name}", "sha256 mismatch"))
        else:
            results.append(ok(f"manifest:{name}", "sha256 matches manifest"))

    # 2. Each cited link is present on disk and signed by a disclosed key.
    links_by_name = {}
    for material in report["signed_materials"]:
        name = material["material_file"]
        link_path = evidence / name
        if not link_path.exists():
            results.append(
                fail(f"link-present:{material['step']}", f"{name} missing")
            )
            continue
        metadata = Metadata.load(str(link_path))
        keyid = metadata.signatures[0]["keyid"]
        if keyid not in keys:
            results.append(
                fail(
                    f"link-key:{material['step']}",
                    "signing key not in disclosed-keys.json",
                )
            )
            continue
        try:
            metadata.verify_signature(keys[keyid])
        except Exception as error:  # noqa: BLE001
            results.append(
                fail(f"link-signature:{material['step']}", str(error))
            )
            continue
        results.append(
            ok(
                f"link-signature:{material['step']}",
                f"verified with key {keyid[:12]}...",
            )
        )
        links_by_name[material["step"]] = metadata.get_payload()

        if sha256_file(link_path) != material["file_sha256"]:
            results.append(
                fail(
                    f"link-digest:{material['step']}",
                    "file sha256 differs from report",
                )
            )
        else:
            results.append(
                ok(
                    f"link-digest:{material['step']}",
                    "file sha256 matches report",
                )
            )

    # 3. Re-derive every MATCH edge with the reference engine.
    for edge in report["match_edges"]:
        upstream = links_by_name.get(edge["upstream_step"])
        downstream = links_by_name.get(edge["downstream_step"])
        if upstream is None or downstream is None:
            results.append(
                fail(
                    f"match-edge:{edge['edge_id']}",
                    "a link required by this edge is absent",
                )
            )
            continue
        rule_data = unpack_rule(edge["rule"])
        consumed = verify_match_rule(
            rule_data,
            set(upstream.products),
            dict(upstream.products),
            links_by_name,
        )
        if edge["artifact"] not in consumed:
            results.append(
                fail(
                    f"match-edge:{edge['edge_id']}",
                    "MATCH engine did not consume the artifact",
                )
            )
        elif (
            edge["upstream_product_sha256"]
            != edge["downstream_material_sha256"]
        ):
            results.append(
                fail(f"match-edge:{edge['edge_id']}", "hashes are not equal")
            )
        else:
            results.append(
                ok(
                    f"match-edge:{edge['edge_id']}",
                    "MATCH re-derived, hashes equal",
                )
            )

    # 4. Shipped package matches the package-step product record.
    package_step = next(
        link for name, link in links_by_name.items() if name == "package"
    )
    package_name = report["scope"]["release_package"]
    recorded = package_step.products.get(package_name, {}).get("sha256")
    actual = sha256_file(bundle / package_name)
    if recorded == actual:
        results.append(
            ok(
                f"release-package:{package_name}",
                "sha256 matches package link product",
            )
        )
    else:
        results.append(
            fail(
                f"release-package:{package_name}",
                f"recorded {recorded} != bundle {actual}",
            )
        )

    broken = [result for result in results if not result["ok"]]
    verdict = {
        "bundle_id": manifest["bundle_id"],
        "overall": "PASS" if not broken else "FAIL",
        "checks": results,
        "boundary_note": (
            "inspection items listed in report.boundaries are intentionally "
            "not asserted: no signed link exists for them in this bundle"
        ),
    }
    print(json.dumps(verdict, indent=2, sort_keys=True))
    return 0 if not broken else 1


if __name__ == "__main__":
    sys.exit(main())
