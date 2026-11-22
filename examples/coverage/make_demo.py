#!/usr/bin/env python3
"""Reproduce the "two zero-finding scans" coverage scenario.

Scan A (shard ``model-layer``) only ever scanned the model layer.
Scan B (shard ``full-scan``) covered both files, but rule B608 raised
on every file, so it silently never ran. Both scans report zero
findings. The coverage ledgers and the merged rule x file table show
why scan B cannot pass the coverage gate, and why the two scans were
not duplicates.

Run from this directory:

    python make_demo.py
"""
import os
import sys

from bandit.core import config as b_config
from bandit.core import coverage
from bandit.core import extension_loader
from bandit.core import manager as b_manager

HERE = os.path.dirname(os.path.abspath(__file__))
PROFILE = {"include": ["B608", "B404"]}
TARGETS = ["src/model_layer.py", "src/api_layer.py"]


def run_scan(shard_id, targets, break_b608=False):
    broken = []
    if break_b608:

        def boom(context, config=None):
            raise RuntimeError("simulated plugin crash")

        boom._test_id = "B608"
        boom._checks = {"Str"}
        boom.__name__ = "hardcoded_sql_string"
        for ext in extension_loader.MANAGER.plugins:
            if getattr(ext.plugin, "_test_id", None) == "B608":
                broken.append((ext, ext.plugin))
                ext.plugin = boom
    try:
        mgr = b_manager.BanditManager(
            b_config.BanditConfig(),
            "file",
            profile=dict(PROFILE),
            quiet=True,
            coverage_shard=shard_id,
        )
        mgr.discover_files(targets)
        mgr.run_tests()
    finally:
        for ext, plugin in broken:
            ext.plugin = plugin
    return mgr


def main():
    os.chdir(HERE)

    scan_a = run_scan("model-layer", ["src/model_layer.py"])
    scan_b = run_scan("full-scan", TARGETS, break_b608=True)
    rerun_b = run_scan("full-scan", TARGETS)

    for mgr in (scan_a, scan_b, rerun_b):
        assert not mgr.results, "demo expects zero findings in every scan"

    scan_a.coverage.save("ledger-model-layer.json")
    scan_b.coverage.save("ledger-full-scan.json")
    rerun_b.coverage.save("ledger-full-scan-rerun.json")

    merged = coverage.merge_ledgers([scan_a.coverage, scan_b.coverage])
    with open("merged.json", "w", encoding="utf-8") as fp:
        import json

        json.dump(merged.to_dict(), fp, indent=2, sort_keys=True)
        fp.write("\n")
    with open("coverage-table.txt", "w", encoding="utf-8") as fp:
        fp.write(coverage.render_table(merged))

    lines = []
    for label, ledger in [
        ("scan A (model-layer)", scan_a.coverage),
        ("scan B (full-scan)", scan_b.coverage),
        ("scan B rerun (full-scan)", rerun_b.coverage),
    ]:
        reasons = coverage.merge_ledgers([ledger]).evaluate()
        verdict = "PASS" if not reasons else "FAIL"
        lines.append(f"{label}: gate {verdict}")
        lines.extend(f"  - {reason}" for reason in reasons)
    merged_reasons = merged.evaluate()
    lines.append(
        "merged A+B: gate " + ("PASS" if not merged_reasons else "FAIL")
    )
    lines.extend(f"  - {reason}" for reason in merged_reasons)
    with open("gate-output.txt", "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines) + "\n")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
