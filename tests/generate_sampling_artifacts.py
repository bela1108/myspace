"""Generate four plain-text release sampling scenario artifacts."""

from __future__ import annotations

import hashlib
from pathlib import Path

from in_toto.verifylib import (
    FIXED_BATCH_SEED,
    compute_sample_draw,
    verify_sampling_review,
)

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "sampling_artifacts"
SEED = "fixed-batch-seed-2026-q4"
CUTOFF = "2026-11-25T12:00:00Z"
EARLY = "2026-11-25T11:30:00Z"
LATE = "2026-11-25T12:30:00Z"


def digest_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def material_batch():
    contents = {
        "01-build-notes.txt": "build notes for fixed batch 031\n",
        "02-source-list.txt": "one source list with four text artifacts\n",
        "03-checksums.txt": "checksums are bound to the signed full set\n",
        "04-release-readme.txt": "release readme waits for sample review\n",
    }
    return {
        name: {"sha256": digest_text(content)}
        for name, content in contents.items()
    }


def reviews_for(selected, reviewed_at, draw):
    return [
        {
            "artifact": name,
            "reviewed_at": reviewed_at,
            "reviewer": "sample-reviewer",
            "full_set_digest": draw["full_set_digest"],
            "draw_digest": draw["draw_digest"],
            "cutoff": CUTOFF,
        }
        for name in selected
    ]


def result_lines(result):
    return [
        f"verdict: {'PASS' if result.passed else 'BLOCKED'}",
        f"full_set_digest: {result['full_set_digest']}",
        f"draw_digest: {result['draw_digest']}",
        f"selected: {', '.join(result['selected'])}",
        f"missing: {', '.join(result['missing']) or '(none)'}",
        f"replaced_materials: "
        f"{', '.join(result['replaced_materials']) or '(none)'}",
        f"late_confirmations_retained: {len(result['late_reviews'])}",
    ]


def write_artifact(filename, title, scenario, details):
    coverage_labels = {
        "01-pass.txt": "通过 / pass",
        "02-replaced-blocked.txt": "替换 / replacement blocked",
        "03-replacement-recheck-pass.txt": "替换后重核通过 / replacement rechecked",
        "04-late-retained.txt": "迟到 / late confirmation retained",
    }
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    lines = [
        title,
        "=" * len(title),
        "",
        f"scenario: {scenario}",
        f"coverage_label: {coverage_labels.get(filename, scenario)}",
        f"fixed_seed: {SEED} (library default: {FIXED_BATCH_SEED})",
        f"review_cutoff: {CUTOFF}",
        "",
    ]
    lines.extend(details)
    lines.append("")
    (OUTPUT_DIR / filename).write_text("\n".join(lines), encoding="utf-8")


def main():
    materials = material_batch()
    draw = compute_sample_draw(
        seed=SEED,
        materials=materials,
        sample_size=2,
        cutoff=CUTOFF,
    )

    passed = verify_sampling_review(
        materials,
        reviews_for(draw["selected"], EARLY, draw),
        CUTOFF,
        seed=SEED,
        sample_size=2,
        draw_sheet=draw,
        raise_on_failure=False,
    )
    write_artifact(
        "01-pass.txt",
        "Sampling review: pass",
        "on-time confirmations for the fixed draw",
        result_lines(passed),
    )

    unselected = next(
        name for name in materials if name not in draw["selected"]
    )
    replaced = dict(materials)
    replaced[unselected] = {"sha256": digest_text("replaced text artifact\n")}
    stale = verify_sampling_review(
        replaced,
        reviews_for(draw["selected"], EARLY, draw),
        CUTOFF,
        seed=SEED,
        sample_size=2,
        draw_sheet=draw,
        raise_on_failure=False,
    )
    write_artifact(
        "02-replaced-blocked.txt",
        "Sampling review: replacement blocked",
        "an unsampled material was replaced before full-set recheck",
        result_lines(stale)
        + [
            "",
            f"replaced_unsampled_material: {unselected}",
            "action: recompute seed draw over the new complete set",
        ],
    )

    redraw = compute_sample_draw(
        seed=SEED,
        materials=replaced,
        sample_size=2,
        cutoff=CUTOFF,
    )
    rechecked = verify_sampling_review(
        replaced,
        reviews_for(redraw["selected"], EARLY, redraw),
        CUTOFF,
        seed=SEED,
        sample_size=2,
        draw_sheet=redraw,
        raise_on_failure=False,
    )
    write_artifact(
        "03-replacement-recheck-pass.txt",
        "Sampling review: replacement rechecked",
        "full set recomputed and fresh confirmations collected",
        result_lines(rechecked)
        + [
            "",
            f"new_draw_digest: {redraw['draw_digest']}",
            "action: new draw and confirmations are required after replacement",
        ],
    )

    late = verify_sampling_review(
        materials,
        reviews_for(draw["selected"], LATE, draw),
        CUTOFF,
        seed=SEED,
        sample_size=2,
        draw_sheet=draw,
        raise_on_failure=False,
    )
    write_artifact(
        "04-late-retained.txt",
        "Sampling review: late confirmation retained",
        "confirmation after cutoff cannot release this batch",
        result_lines(late)
        + [
            "",
            f"late_time: {LATE}",
            "recheck_queue: " + ", ".join(draw["selected"]),
            "policy: retain late evidence for a later review cycle",
        ],
    )


if __name__ == "__main__":
    main()
