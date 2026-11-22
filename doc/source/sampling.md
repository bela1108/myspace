# Release sampling acceptance

A release layout may carry an optional, owner-signed `sampling` policy. When it
is present, `in-toto-verify` first verifies the in-toto link signatures as usual,
then checks deterministic manual-review sampling acceptance against the artifacts
reported by those verified links.

The policy is part of the signed layout, so the batch seed, sample size and
release cutoff are fixed before evidence is collected. A policy looks like this:

```json
{
  "seed": "batch-2026-11-23",
  "sample_size": 2,
  "cutoff": "2026-11-23T12:00:00Z",
  "reviewers": ["<reviewer keyid>"],
  "steps": ["package"],
  "artifact_type": "materials",
  "threshold": 1,
  "algorithm": "hmac-sha256-rank-v1"
}
```

`artifact_type` may be `materials`, `products` or `both`. For `both`, artifacts
are identified as `materials:<path>` and `products:<path>`. An empty `steps`
list includes every step.

## Draw sheet

The draw is recomputable from the fixed seed and the complete signed artifact
set. Each artifact is ranked by HMAC-SHA256 with the seed as key over a canonical
representation of the algorithm, artifact id, hashes and full-set digest. The
lowest ranks are selected. The draw sheet records the policy, the complete full
set, the selected artifacts, each selection rank and two digests:

- `full_set_digest` binds every artifact, including artifacts that were not
  drawn.
- `sample_digest` binds the policy, full set and selection. Review evidence
  references this value.

The full set is taken from the links that passed signature threshold
verification. Replacing any artifact changes `full_set_digest`, invalidates the
old draw and makes all evidence bound to the old `sample_digest` stale. The
previous draw therefore cannot be reused when an unsampled artifact is replaced;
the draw is recomputed and the whole full set is checked again.

Write the draw sheet with `SamplingDraw.dump()` or pass
`sampling_draw_sheet_path` to `in_toto_verify`. It is written even when sampling
acceptance fails, so the delivered extraction list remains auditable.

## Review evidence

Review evidence is signed in-toto link metadata. Its signed `byproducts` bind it
to one draw and to the release cutoff:

```json
{
  "artifact": "materials/notes-a.txt",
  "artifact_type": "materials",
  "artifact_hashes": {"sha256": "..."},
  "draw_sheet_digest": "<sample_digest>",
  "release_cutoff": "2026-11-23T12:00:00Z",
  "reviewed_at": "2026-11-23T11:30:00Z"
}
```

The evidence metadata must contain the sampled artifact and matching hashes.
Evidence is verified with authorized reviewer keys (by default the functionary
keys in the layout) and must carry the required number of valid signatures.

Evidence signed at or before the cutoff counts toward acceptance. Evidence
signed after the cutoff does not pass this release, but is preserved in
`SamplingResult.late` and in the optional acceptance result file for a later
re-review.

## Python API

```python
from in_toto.sampling import (
    SamplingPolicy,
    compute_draw_sheet,
    create_review_evidence,
    verify_sampling_acceptance,
)

policy = SamplingPolicy(
    seed="batch-2026-11-23",
    sample_size=2,
    cutoff="2026-11-23T12:00:00Z",
    steps=["package"],
    artifact_type="materials",
)
draw = compute_draw_sheet(policy, verified_full_set)
draw.dump("sampling-draw.json")

evidence = [
    create_review_evidence(
        artifact_id,
        verified_full_set[artifact_id],
        draw,
        "2026-11-23T11:30:00Z",
        reviewer_signer,
    )
    for artifact_id in draw.selected
]

result = verify_sampling_acceptance(
    policy,
    verified_full_set,
    evidence,
    review_keys=reviewer_keys,
    draw_sheet=draw,
)
```

Use `verify_sampling_for_links(policy, verified_links, evidence, ...)` to build
the full set directly from the dictionary returned by in-toto link threshold
verification.
