# Fallback-to-normal switch verification

This example demonstrates `in_toto.switch_verify`, an offline and replayable
check for the boundary between an incident fallback build and the first normal
build after recovery.

Run it from the repository root:

```console
python examples/switch_verification/demo.py
```

The script generates fresh keys and signed metadata in a temporary directory.
Artifacts are read from the signed links, never from the live working tree, so
a concurrent writer cannot change the verdict after evidence was recorded.
It covers three cases:

1. **Incident fallback release** — legal under the signed fallback layout.
2. **First normal release with a clean cache** — legal under the signed normal
   layout; no fallback artifact remains at the junction.
3. **First normal release with unreviewed cache residue** — quarantined. The
   normal build consumes `cache/vendor.tar`, which the fallback build produced.
   A legacy `mode` marker says `normal`, and a concurrent fallback link briefly
   coexisted, but neither is allowed to hide the signed evidence.

To approve residue in a real flow, sign a review manifest whose Link
`materials` contain the exact path and digest that a human reviewed, and pass
it as `review_bom` together with the reviewer keys.
