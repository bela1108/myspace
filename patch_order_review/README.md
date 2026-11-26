# Patch-order review fixture

This directory is a small, offline fixture for reviewing the *order* in which a
legacy re-lock is applied. It does not call a live vulnerability service: each
lock state is audited by a synthetic local service and rendered with
`pip_audit._format.json.JsonFormat`, so the evidence files use the real
`pip-audit --format=json` manifest shape.

## Scenario

RG-2031-07 re-locks two legacy maintenance lines:

- `line-7`: `argonvale` (runtime schema) and `cinderloom` (signed ABI boundary).
- `line-8`: `basaltine` (data-plane coordinator) and `driftpin` (edge transport).

`cinderloom==1.0.1` and `driftpin==3.2.1` already carry signed, non-reopenable
dispositions. The tempting route reaches the smallest terminal version gap by
walking through `basaltine==2.0.1`. That release has a metadata regression:
`COMPAT-001` forces `cinderloom` back to `0.9.1`, which reopens two signed
findings in the middle of the migration even though the terminal lock is clean
again.

The alternative route uses `basaltine==2.2.0`, a bridge release that bundles the
2.0.1 migration without installing its broken metadata. It costs one extra
version component and requires the `argonvale==1.5.0` sequential schema step
first (`COMPAT-005`), but it never moves `cinderloom` below 1.0.1.

## Layout

```
patch_order_review/
  fixture/
    packages.json          four fictional distributions and candidate versions
    baseline_lock.json     current double-line lock
    advisories.json        synthetic PYSEC ranges and fix versions
    dispositions.json      signed locked/transient/residual dispositions
    constraints.json       compatibility rules, terminal requirements, gap metric
    patch_units.json       atomic single- and cross-line patch units
    routes/                the two candidate orderings
    audit/                 one pip-audit JSON document per lock state
  model.py                 fixture loading and constraint evaluation
  auditgen.py              pip-audit JSON generation for every state
  reviewer.py              continuity judging, derivation, and Markdown report
  reports/                 generated review.json and patch_order_review.md
```

## What is checked at every state

- Unit preconditions and every `COMPAT-*` lock rule hold.
- No signed non-reopenable disposition is open, even for one intermediate state.
- Any non-locked transient finding has an accepted disposition whose consecutive
  state bound is respected.
- Terminal remediation targets are closed.
- Every finding still open at the terminal lock has a signed residual acceptance.

The review records two distinct evidence sets: transient risk introduced on the
way (including the rejected reopened risks) and residual risk that remains at the
terminal lock. It also reports an endpoint-only verdict next to the continuity
verdict to make the difference explicit: both routes end with the same open
finding, so an endpoint comparison cannot tell them apart.

## Usage

From the repository root:

```bash
python -m patch_order_review          # regenerate audits and reports
python -m patch_order_review verify   # fail if the review invariants do not hold
python -m pytest test/test_patch_order_review.py
```

`review.json` is the machine-readable result; `patch_order_review.md` is the
human-readable review. The `sha256` in each `audit/index.json` step binds the
verdict to the exact pip-audit JSON document used at that state.
