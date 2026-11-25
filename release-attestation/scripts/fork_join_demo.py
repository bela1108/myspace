#!/usr/bin/env python3
"""Fork-then-merge re-verification demo for the public attestation bundle.

Two independent reviewers (reviewer-a, reviewer-b) each get an isolated copy
of the public bundle and run the self-contained verifier on their own machine
(the fork). A merge step then compares their verdicts. A second scenario
removes the intermediate link to show exactly where the chain breaks.

Nothing here reads internal repository paths: every input lives under
release-attestation/public/.
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BUNDLE = HERE.parent / "public"
WORKROOT = HERE.parent / "demo-workdir"
VERIFIER = HERE / "verify_report.py"

REVIEWERS = ["reviewer-a", "reviewer-b"]
INTERMEDIATE_LINK = "write-code.776a00e2.link"


def reset_workdir():
    if WORKROOT.exists():
        shutil.rmtree(WORKROOT)
    WORKROOT.mkdir(parents=True)


def provision(reviewer, remove_intermediate=False):
    target = WORKROOT / reviewer / "public"
    shutil.copytree(BUNDLE, target)
    if remove_intermediate:
        (target / "evidence" / INTERMEDIATE_LINK).unlink()
    return target


def run_verifier(reviewer_dir):
    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(reviewer_dir)],
        cwd=reviewer_dir.parent,
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        verdict = json.loads(proc.stdout)
    except json.JSONDecodeError:
        verdict = {"overall": "ERROR", "checks": [], "stderr": proc.stderr}
    verdict["exit_code"] = proc.returncode
    return verdict


def merge(verdicts):
    merged = {"scenario": verdicts[0]["scenario"], "reviewers": []}
    for verdict in verdicts:
        merged["reviewers"].append(
            {
                "reviewer": verdict["reviewer"],
                "overall": verdict["overall"],
                "exit_code": verdict["exit_code"],
                "failed_checks": [
                    check["check"]
                    for check in verdict["checks"]
                    if not check["ok"]
                ],
            }
        )

    overalls = {verdict["overall"] for verdict in verdicts}
    merged["forks_agree"] = len(overalls) == 1
    merged["merged_verdict"] = (
        next(iter(overalls)) if len(overalls) == 1 else "DIVERGENT"
    )

    if merged["merged_verdict"] == "PASS":
        merged["interpretation"] = (
            "both independent reviewers reproduced the same PASS: every public "
            "claim is re-derivable from the signed materials alone"
        )
    else:
        merged["interpretation"] = (
            "chain does not hold on public evidence; the failed checks "
            "name the "
            "exact edge/step at which verification stops"
        )
    return merged


def run_scenario(name, remove_intermediate):
    reset_workdir()
    verdicts = []
    for reviewer in REVIEWERS:
        reviewer_bundle = provision(reviewer, remove_intermediate)
        verdict = run_verifier(reviewer_bundle)
        verdict["scenario"] = name
        verdict["reviewer"] = reviewer
        verdicts.append(verdict)
    return merge(verdicts)


def main():
    reset_workdir()
    results = [
        run_scenario("intact-bundle", remove_intermediate=False),
        run_scenario(
            f"intermediate-link-removed ({INTERMEDIATE_LINK})",
            remove_intermediate=True,
        ),
    ]
    print(json.dumps(results, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
