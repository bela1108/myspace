#!/usr/bin/env python3
"""Derive a customer-facing attestation report from verified in-toto evidence.

The generator only ever emits claims that can be re-derived from the signed
materials listed in the disclosure policy (``policy.json``). Everything outside
the allowed product / step / artifact scope is redacted, and relationships that
cannot be proven from those materials are recorded as explicit boundaries
instead of being asserted.
"""

import hashlib
import json
import shutil
import sys
from pathlib import Path

from in_toto.models.metadata import Metadata
from in_toto.rulelib import unpack_rule
from in_toto.verifylib import verify_match_rule

REPO_ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parents[1]
POLICY_PATH = HERE / "policy.json"


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def load_policy():
    with open(POLICY_PATH, encoding="utf-8") as handle:
        return json.load(handle)


def find_link(policy, step_name):
    pattern = f"{step_name}.*.link"
    matches = []
    for source_dir in policy["evidence_source_dirs"]:
        matches.extend(sorted((REPO_ROOT / source_dir).glob(pattern)))
    if len(matches) != 1:
        raise SystemExit(
            f"expected exactly one link for step {step_name!r}, found "
            f"{[str(m) for m in matches]}"
        )
    return matches[0]


def filter_artifacts(artifacts, allowed):
    """Return only in-scope artifacts; fail closed on out-of-scope entries."""
    filtered = {}
    for name, hashes in sorted(artifacts.items()):
        if name not in allowed:
            raise SystemExit(
                f"artifact {name!r} is not on the disclosure allow-list; "
                "refusing to emit it"
            )
        filtered[name] = hashes
    return filtered


def summarize_material(metadata, bundle_name, link, keyid):
    payload = metadata.get_payload()
    return {
        "material_file": bundle_name,
        "step": payload.name,
        "signing_keyid": keyid,
        "file_sha256": sha256_bytes(
            (HERE / "public" / "evidence" / bundle_name).read_bytes()
        ),
        "canonical_payload_sha256": sha256_bytes(payload.signable_bytes),
        "signature_hex": metadata.signatures[0]["sig"],
        "signature_verified_against_layout_key": True,
        "recorded_command": link.command,
        "return_value": link.byproducts.get("return-value"),
    }


def rederive_match(rule, links_by_name):
    """Re-run the reference implementation's MATCH engine on the rule."""
    rule_data = unpack_rule(rule)
    source_name = rule_data["dest_name"]
    source_link = links_by_name[source_name]
    queue = set(source_link.products)
    consumed = verify_match_rule(
        rule_data, queue, dict(source_link.products), links_by_name
    )
    return rule_data, sorted(consumed)


def main():
    policy = load_policy()
    allowed_steps = set(policy["allowed_steps"])
    allowed_artifacts = set(policy["allowed_artifact_names"])

    layout_path = REPO_ROOT / policy["layout_template"]
    layout_metadata = Metadata.load(str(layout_path))
    layout = layout_metadata.get_payload()
    layout_step_names = {step.name for step in layout.steps}
    layout_inspection_names = {item.name for item in layout.inspect}

    if not allowed_steps.issubset(layout_step_names):
        raise SystemExit("policy lists steps that the layout does not define")

    public_evidence_dir = HERE / "public" / "evidence"
    public_evidence_dir.mkdir(parents=True, exist_ok=True)
    for stale in public_evidence_dir.glob("*.link"):
        stale.unlink()

    materials = []
    links_by_name = {}
    for step_name in sorted(allowed_steps):
        link_path = find_link(policy, step_name)
        bundle_name = link_path.name
        metadata = Metadata.load(str(link_path))
        keyid = metadata.signatures[0]["keyid"]
        if keyid not in layout.keys:
            raise SystemExit(
                f"signing key {keyid} for step {step_name!r} is not a key in "
                "the layout; cannot verify authenticity"
            )
        metadata.verify_signature(layout.keys[keyid])

        shutil.copyfile(link_path, public_evidence_dir / bundle_name)
        link = metadata.get_payload()
        links_by_name[step_name] = link
        summary = summarize_material(metadata, bundle_name, link, keyid)
        summary["materials"] = filter_artifacts(
            link.materials, allowed_artifacts
        )
        summary["products"] = filter_artifacts(link.products, allowed_artifacts)
        materials.append(summary)

    claims = []
    match_edges = []
    for step in layout.steps:
        if step.name not in allowed_steps:
            continue
        link = links_by_name[step.name]
        for rule in step.expected_products:
            if rule[0] == "CREATE":
                artifact = rule[1]
                if artifact not in link.products:
                    raise SystemExit(
                        f"CREATE rule for {artifact!r} not satisfied "
                        "by evidence"
                    )
                claims.append(
                    {
                        "claim_id": f"create:{step.name}:{artifact}",
                        "statement": (
                            f"step {step.name!r} created product {artifact!r}; "
                            "no input materials were recorded for this step"
                            if not link.materials
                            else (
                                f"step {step.name!r} created product "
                                f"{artifact!r}"
                            )
                        ),
                        "evidence": [
                            material["material_file"]
                            for material in materials
                            if material["step"] == step.name
                        ],
                        "artifact_sha256": link.products[artifact]["sha256"],
                    }
                )
        for rule in step.expected_materials:
            if rule[0] != "MATCH":
                continue
            rule_data, consumed = rederive_match(rule, links_by_name)
            if not consumed:
                raise SystemExit(f"MATCH rule {rule!r} could not be re-derived")
            source_artifact = links_by_name[rule_data["dest_name"]].products[
                rule_data["pattern"]
            ]["sha256"]
            target_artifact = link.materials[rule_data["pattern"]]["sha256"]
            match_edges.append(
                {
                    "edge_id": f"match:{rule_data['dest_name']}->{step.name}:"
                    f"{rule_data['pattern']}",
                    "rule": rule,
                    "engine": "in_toto.verifylib.verify_match_rule",
                    "artifact": rule_data["pattern"],
                    "upstream_step": rule_data["dest_name"],
                    "downstream_step": step.name,
                    "upstream_product_sha256": source_artifact,
                    "downstream_material_sha256": target_artifact,
                    "hashes_equal": source_artifact == target_artifact,
                    "consumed_by_engine": consumed,
                    "evidence": sorted(
                        {
                            material["material_file"]
                            for material in materials
                            if material["step"]
                            in (step.name, rule_data["dest_name"])
                        }
                    ),
                }
            )
            claims.append(
                {
                    "claim_id": f"match:{step.name}:{rule_data['pattern']}",
                    "statement": (
                        f"material {rule_data['pattern']!r} consumed by step "
                        f"{step.name!r} is byte-identical (sha256) to the "
                        f"product of step {rule_data['dest_name']!r}"
                    ),
                    "evidence": match_edges[-1]["evidence"],
                    "artifact_sha256": target_artifact,
                }
            )

    exclusions = [
        {"item": item, "reason": policy["exclusion_reason"]}
        for item in policy["excluded_evidence_variants"]
    ]

    boundary = []
    for inspection in layout.inspect:
        if inspection.name not in layout_inspection_names:
            continue
        boundary.append(
            {
                "layout_item": inspection.name,
                "item_type": "inspection",
                "reason": (
                    "inspection rules are evaluated at verification time "
                    "on the verifier's machine; no signed link for this "
                    "item exists in the disclosed materials, so its outcome "
                    "cannot be attested from signatures alone"
                ),
                "rule_count": len(
                    inspection.expected_materials
                    + inspection.expected_products
                ),
            }
        )

    report = {
        "report_version": 1,
        "scope": {
            "release_package": policy["release_package"],
            "disclosable_steps": sorted(allowed_steps),
            "allowed_artifacts": sorted(allowed_artifacts),
        },
        "verification_basis": {
            "layout_step_names": sorted(layout_step_names),
            "note": (
                "each link signature was verified against the functionary "
                "public key embedded in the layout"
            ),
        },
        "signed_materials": materials,
        "claims": claims,
        "match_edges": match_edges,
        "boundaries": boundary,
        "excluded_evidence": exclusions,
    }

    out_dir = HERE / "public"
    out_dir.mkdir(exist_ok=True)
    report_path = out_dir / "attestation-report.json"
    with open(report_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"wrote {report_path.relative_to(REPO_ROOT)}")

    disclosed_keys = {}
    for step in layout.steps:
        if step.name in allowed_steps:
            for keyid in step.pubkeys:
                disclosed_keys[keyid] = dict(layout.keys[keyid])
    keys_path = out_dir / "disclosed-keys.json"
    with open(keys_path, "w", encoding="utf-8") as handle:
        json.dump(disclosed_keys, handle, indent=2, sort_keys=True)
        handle.write("\n")

    evidence_dir = REPO_ROOT / policy["evidence_source_dirs"][0]
    package_source = evidence_dir / policy["release_package"]
    package_copy = out_dir / policy["release_package"]
    shutil.copyfile(package_source, package_copy)

    hashed_paths = (
        list((out_dir / "evidence").glob("*.link"))
        + [report_path, package_copy, keys_path]
    )
    manifest = {
        "bundle_id": policy["policy_id"],
        "files": sorted(
            (path.name, sha256_file(path))
            for path in hashed_paths
        ),
        "verification_entrypoint": "scripts/verify_report.py",
    }
    manifest_path = out_dir / "bundle-manifest.json"
    with open(manifest_path, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print("wrote bundle manifest and release package copy")


if __name__ == "__main__":
    sys.exit(main())
