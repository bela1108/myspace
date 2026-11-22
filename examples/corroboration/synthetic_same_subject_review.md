# Internal Registry Corroboration Review - SYNTHETIC-SAME-SUBJECT-FIXTURE

**Classification:** internal review only. Not a court exhibit.

**Verdict:** `same_subject`

**Generated:** 2026-11-22T00:00:00+08:00

**Claim under review:** Two independent synthetic exports resolve to the same account.

## Rationale

- At least two independent export lineages resolve the same subject name nodes.
- No identity or integrity conflict was found.
- SYN-A vs SYN-B: same_subject - Independent exports resolve shared name nodes to the same values.

## Exports

| export | type | source | derived_from | volume fingerprint | lineage | primary names | suppl. names | anchors | plugins | clone of | error |
|---|---|---|---|---|---|---|---|---|---|---|---|
| SYN-A | ntuser | SYN-SRC-A |  | disk_signatu... | SYN-A | 1 | 0 | 0 | 0 |  |  |
| SYN-B | ntuser | SYN-SRC-B |  | disk_signatu... | SYN-B | 1 | 0 | 0 | 0 |  |  |

## Pairwise assessment

| pair | verdict | independent | clone | same volume | same hive id | identical anchors | reasons |
|---|---|---|---|---|---|---|---|
| SYN-A\|SYN-B | same_subject | True | False | False | False | 0/0 | Independent exports resolve shared name nodes to the same values. |

## Content anchors

No content anchors were observed.

## Association ledger

| association | kind | status | exports | origin | role | deps | summary |
|---|---|---|---|---|---|---|---|
| link:name:SYN-A:SYN-B:account-name-caseuser | shared_name_node | valid | SYN-A, SYN-B | caller | primary | 2 | Both exports independently resolve account_name='caseuser'. |
| link:name:SYN-A:SYN-B:profile-path-c-users-caseuser | shared_name_node | valid | SYN-A, SYN-B | caller | primary | 2 | Both exports independently resolve profile_path='c:\\users\\caseuser'. |

## Plugin evidence (supplemental only)

No plugin observations were collected.

## Provenance policy

- **plugin_values_are_supplemental:** True
- **plugin_values_used_as_original_source:** False
- **plugin_values_can_establish_identity:** False
- **caller_metadata_is_asserted_not_forensically_verified:** True
- **content_anchor_identity_is_not_subject_identity:** True
- **clone_content_is_not_independent_corroboration:** True
- **independence_rule:** Exports sharing a declared derivative chain, an image hash or an acquisition id are treated as one lineage.
- **verification_rule:** A caller name association becomes primary only when it is independently verifiable and verified against the cited hive value.

## Limitations

- Caller-registered sampling sources and volume identities are assertions until checked against acquisition records.
- Registry-internal hive identity is not a volume serial and does not by itself identify a person.
- Identical key paths and timestamps prove content similarity; under cloning they do not prove independent use.
- Plugin-derived values are derived observations. They supplement but never replace an original source.
- Missing acquisition metadata produces `missing_evidence`, not an inference.

## Case notes

Synthetic, non-evidentiary example used to show the same_subject branch of the reviewer. It carries no hive file and no real acquisition metadata.
