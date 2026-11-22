# Corroboration examples

These files are an internal review fixture, not an evidentiary finding.

- `three_ntuser_case.json` - three-export case manifest. Acquisition and
  volume metadata are synthetic and marked `fixture=true`.
- `three_ntuser_review.json` / `.md` - review result. The verdict is
  `conflict`: `EXP-A` and `EXP-B` are one clone lineage and therefore
  `missing_evidence` against each other, while both conflict with the
  independent `tony` export `EXP-C`.
- `internal_review_summary_zh.md` - Chinese internal-review summary covering
  the same verdict, provenance boundaries, and replacement results.
- `clone_volume_replacement.json` / `.md` - counterfactual replacement of the
  clone volume identity record. The volume link is invalidated; clone
  lineage, hive identity, anchors, and name links survive.
- `clone_name_replacement.json` / `.md` - counterfactual replacement of the
  clone name record. The two name links are invalidated; volume and lineage
  links survive.
- `synthetic_same_subject_case.json` and
  `synthetic_same_subject_review.json` / `.md` - non-evidentiary branch demo
  for `same_subject`.

Regenerate the reports:

```bash
regipy-corroborate examples/corroboration/three_ntuser_case.json \
  -o examples/corroboration/three_ntuser_review.json \
  --markdown examples/corroboration/three_ntuser_review.md

regipy-corroborate examples/corroboration/three_ntuser_case.json \
  --replace-export EXP-B --replace-record volume \
  --replace-value "{\"volume_serial\":\"DEADBEEF\",\"disk_signature\":\"0xDEADBEEF\",\"disk_guid\":\"fixture-disk-replaced\"}" \
  -o examples/corroboration/clone_volume_replacement.json \
  --markdown examples/corroboration/clone_volume_replacement.md
```
