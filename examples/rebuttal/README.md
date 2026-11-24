# Offline rebuttal examples

These files drive `evtx_scripts/evtx_rebut.py`, an offline entry point that
checks a documented case claim against raw EVTX material using python-evtx.

## Files

- `case_claim.example.json` - the narrative claim reduced to finite assertions:
  event identities (channel / event id / provider), ordering requirements and
  field interpretations. Targets `tests/data/issue_39.evtx`.
- `case_claim.malformed.json` - a claim over `tests/data/dns_log_malformed.evtx`,
  where four of five records cannot be rendered (issue #37).
- `template_proof.original.json` - both resident template GUIDs observed for the
  LiveId events are treated as authoritative.
- `template_proof.revised.json` - only the `176d51c9-...` version is confirmed;
  the `520e6584-...` version is unresolved on that side of the claim.
- `template_proof.malformed.json` - ties the single resident DNS template to the
  `dns_query` identity.

## Verdicts

Every assertion is reported as exactly one of:

- `REBUTTED` - a concrete, internally consistent record contradicts it.
- `UNCONFIRMABLE` - the deciding material is absent, unrenderable or tied to a
  template version that the proof does not confirm. A record whose template
  version cannot be established never rebuts; it only blocks confirmation.
- `SUPPORTED` - the surviving material is consistent with the assertion.

The process exit code is `0` (supported), `2` (unconfirmable) or `3` (rebutted);
`1` means the inputs could not be read or parsed.

## Reproducing the runs

    python evtx_scripts/evtx_rebut.py tests/data/issue_39.evtx \
        --claim examples/rebuttal/case_claim.example.json
    python evtx_scripts/evtx_rebut.py tests/data/issue_39.evtx \
        --claim examples/rebuttal/case_claim.example.json \
        --template-proof examples/rebuttal/template_proof.original.json
    python evtx_scripts/evtx_rebut.py tests/data/issue_39.evtx \
        --claim examples/rebuttal/case_claim.example.json \
        --template-proof examples/rebuttal/template_proof.revised.json
    python evtx_scripts/evtx_rebut.py tests/data/dns_log_malformed.evtx \
        --claim examples/rebuttal/case_claim.malformed.json

Add `--json` to emit the machine-readable report. Multiple EVTX paths are
scanned together so a claim can span several logs.

## What changes when the template proof is revised

Conclusions for identities not referenced by the template proof are computed
from the same records and stay identical. Covered identities are filtered to
authoritative template versions: the revised proof moves the shortest
contradicting material for the ordering/field assertions from the early
`520e6584-...` records to record 8, which carries the confirmed
`176d51c9-...` template, while never turning an unresolved version into a
rebuttal.

