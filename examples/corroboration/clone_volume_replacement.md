# Internal Registry Corroboration Review - CASE-2026-1122-NTUSER-IDENTITY

**Classification:** internal review only. Not a court exhibit.

**Verdict:** `conflict`

**Generated:** 2026-11-22T00:00:00+08:00

**Claim under review:** The three registry exports were left by one user (investigation record).

## Rationale

- At least one export pair is in direct conflict.
- The same-subject claim is contradicted by conflicting identity or content evidence.
- EXP-A vs EXP-B: missing_evidence - Exports share one acquisition or clone lineage; identical content cannot count as independent corroboration. Matching plugin output is supplemental only and was not used to establish identity.
- EXP-A vs EXP-C: conflict - Exports disagree on comparable identity values: account_name=['vibranium'] vs ['tony']; profile_path=['c:\\users\\vibranium'] vs ['c:\\users\\tony'].
- EXP-B vs EXP-C: conflict - Exports disagree on comparable identity values: account_name=['vibranium'] vs ['tony']; profile_path=['c:\\users\\vibranium'] vs ['c:\\users\\tony'].
- Clone or copy lineage was detected; identical keys and timestamps from cloned content were not counted as independent corroboration.
- Plugin-derived values were retained as supplemental evidence and were not promoted to an original source.

## Exports

| export | type | source | derived_from | volume fingerprint | lineage | primary names | suppl. names | anchors | plugins | clone of | error |
|---|---|---|---|---|---|---|---|---|---|---|---|
| EXP-A | ntuser | SRC-ORIGINAL |  | disk_guid=fi... | EXP-B | 1 | 0 | 7 | 4 | EXP-B |  |
| EXP-B | ntuser | SRC-CLONE | EXP-A | disk_guid=fi... | EXP-B | 1 | 0 | 7 | 4 | EXP-A |  |
| EXP-C | ntuser | SRC-INDEPENDENT |  | disk_guid=fi... | EXP-C | 1 | 0 | 7 | 4 |  |  |

## Pairwise assessment

| pair | verdict | independent | clone | same volume | same hive id | identical anchors | reasons |
|---|---|---|---|---|---|---|---|
| EXP-A\|EXP-B | missing_evidence | False | True | False | True | 6/7 | Exports share one acquisition or clone lineage; identical content cannot count as independent corroboration. Matching plugin output is supplemental only and was not used to establish identity. |
| EXP-A\|EXP-C | conflict | True | False | False | False | 0/7 | Exports disagree on comparable identity values: account_name=['vibranium'] vs ['tony']; profile_path=['c:\\users\\vibranium'] vs ['c:\\users\\tony']. |
| EXP-B\|EXP-C | conflict | True | False | False | False | 0/7 | Exports disagree on comparable identity values: account_name=['vibranium'] vs ['tony']; profile_path=['c:\\users\\vibranium'] vs ['c:\\users\\tony']. |

### Coincident content anchors

- `EXP-A|EXP-B`: `\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders` at `2012-04-03T22:08:40.416558+00:00`
- `EXP-A|EXP-B`: `\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders` at `2012-04-03T21:19:54.836740+00:00`
- `EXP-A|EXP-B`: `\Control Panel\Desktop` at `2012-04-04T14:45:43.953750+00:00`
- `EXP-A|EXP-B`: `\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced` at `2012-04-03T22:08:47.836010+00:00`
- `EXP-A|EXP-B`: `\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU` at `2012-04-04T15:35:08.895090+00:00`

These are content identity observations only. For clone-related pairs they are expected and are not independent subject evidence.

## Conflicts

- **pairwise_conflict**: ["Exports disagree on comparable identity values: account_name=['vibranium'] vs ['tony']; profile_path=['c:\\\\users\\\\vibranium'] vs ['c:\\\\users\\\\tony']."]
- **pairwise_conflict**: ["Exports disagree on comparable identity values: account_name=['vibranium'] vs ['tony']; profile_path=['c:\\\\users\\\\vibranium'] vs ['c:\\\\users\\\\tony']."]
- **name_value_conflict**: Exports resolve account_name to different values: ['vibranium'] vs ['tony'].
- **name_value_conflict**: Exports resolve profile_path to different values: ['c:\\users\\vibranium'] vs ['c:\\users\\tony'].
- **name_value_conflict**: Exports resolve account_name to different values: ['vibranium'] vs ['tony'].
- **name_value_conflict**: Exports resolve profile_path to different values: ['c:\\users\\vibranium'] vs ['c:\\users\\tony'].

## Missing evidence

- **pairwise_missing_evidence**: ['Exports share one acquisition or clone lineage; identical content cannot count as independent corroboration.', 'Matching plugin output is supplemental only and was not used to establish identity.']

## Content anchors

| key path | exports | timestamps | digests |
|---|---|---|---|
| \Control Panel\Desktop | EXP-A, EXP-B, EXP-C | 2012-04-04T14:45:43.953750+00:00, 2012-04-04T14:45:43.953750+00:00, 2022-05-23T09:09:34.434736+00:00 | be12f4ab4760..., be12f4ab4760..., 4763ab255f60... |
| \Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced | EXP-A, EXP-B, EXP-C | 2012-04-03T22:08:47.836010+00:00, 2012-04-03T22:08:47.836010+00:00, 2022-05-16T22:26:26.816972+00:00 | d9227af67ff2..., d9227af67ff2..., 625fdcf3450d... |
| \Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU | EXP-A, EXP-B, EXP-C | 2012-04-04T15:35:08.895090+00:00, 2012-04-04T15:35:08.895090+00:00, 2022-05-30T12:01:31.682832+00:00 | 4f53cda18c2b..., 4f53cda18c2b..., ee2d7a95461f... |
| \Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders | EXP-A, EXP-B, EXP-C | 2012-04-03T22:08:40.416558+00:00, 2012-04-03T22:08:40.416558+00:00, 2022-02-14T13:08:49.004558+00:00 | b29f4e098176..., b29f4e098176..., 9f255a6a6db9... |
| \Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths | EXP-A, EXP-B, EXP-C | 2012-04-04T15:35:08.895090+00:00, 2012-04-04T15:35:08.895090+00:00, 2022-04-28T16:15:49.810332+00:00 | 4f53cda18c2b..., 4f53cda18c2b..., 12adc22101fb... |
| \Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders | EXP-A, EXP-B, EXP-C | 2012-04-03T21:19:54.836740+00:00, 2012-04-03T21:19:54.836740+00:00, 2022-02-14T13:08:03.006466+00:00 | b6afb640d145..., b6afb640d145..., c3b471daa6bc... |
| \Software\Microsoft\Windows\CurrentVersion\Run | EXP-A, EXP-B, EXP-C | 2012-04-03T21:19:54.837716+00:00, 2019-02-11T19:45:25.516346+00:00, 2022-05-23T08:44:40.434800+00:00 | 6516d934e7d8..., 684e62a82b8a..., c63ab2429830... |

## Association ledger

| association | kind | status | exports | origin | role | deps | summary |
|---|---|---|---|---|---|---|---|
| conflict:name:EXP-A:EXP-C:account_name | name_value_conflict | conflict | EXP-A, EXP-C | hive | primary | 2 | Exports resolve account_name to different values: ['vibranium'] vs ['tony']. |
| conflict:name:EXP-A:EXP-C:profile_path | name_value_conflict | conflict | EXP-A, EXP-C | hive | primary | 2 | Exports resolve profile_path to different values: ['c:\\users\\vibranium'] vs ['c:\\users\\tony']. |
| conflict:name:EXP-B:EXP-C:account_name | name_value_conflict | conflict | EXP-B, EXP-C | hive | primary | 2 | Exports resolve account_name to different values: ['vibranium'] vs ['tony']. |
| conflict:name:EXP-B:EXP-C:profile_path | name_value_conflict | conflict | EXP-B, EXP-C | hive | primary | 2 | Exports resolve profile_path to different values: ['c:\\users\\vibranium'] vs ['c:\\users\\tony']. |
| divergence:plugin:EXP-A:EXP-B:ntuser-persistence | plugin_divergence | supplemental | EXP-A, EXP-B | plugin | supplemental | 2 | Plugin ntuser_persistence output differs. This is supplemental activity evidence, not an identity source. |
| divergence:plugin:EXP-A:EXP-C:ntuser-persistence | plugin_divergence | supplemental | EXP-A, EXP-C | plugin | supplemental | 2 | Plugin ntuser_persistence output differs. This is supplemental activity evidence, not an identity source. |
| divergence:plugin:EXP-A:EXP-C:typed-paths | plugin_divergence | supplemental | EXP-A, EXP-C | plugin | supplemental | 2 | Plugin typed_paths output differs. This is supplemental activity evidence, not an identity source. |
| divergence:plugin:EXP-A:EXP-C:typed-urls | plugin_divergence | supplemental | EXP-A, EXP-C | plugin | supplemental | 2 | Plugin typed_urls output differs. This is supplemental activity evidence, not an identity source. |
| divergence:plugin:EXP-A:EXP-C:user-assist | plugin_divergence | supplemental | EXP-A, EXP-C | plugin | supplemental | 2 | Plugin user_assist output differs. This is supplemental activity evidence, not an identity source. |
| divergence:plugin:EXP-B:EXP-C:ntuser-persistence | plugin_divergence | supplemental | EXP-B, EXP-C | plugin | supplemental | 2 | Plugin ntuser_persistence output differs. This is supplemental activity evidence, not an identity source. |
| divergence:plugin:EXP-B:EXP-C:typed-paths | plugin_divergence | supplemental | EXP-B, EXP-C | plugin | supplemental | 2 | Plugin typed_paths output differs. This is supplemental activity evidence, not an identity source. |
| divergence:plugin:EXP-B:EXP-C:typed-urls | plugin_divergence | supplemental | EXP-B, EXP-C | plugin | supplemental | 2 | Plugin typed_urls output differs. This is supplemental activity evidence, not an identity source. |
| divergence:plugin:EXP-B:EXP-C:user-assist | plugin_divergence | supplemental | EXP-B, EXP-C | plugin | supplemental | 2 | Plugin user_assist output differs. This is supplemental activity evidence, not an identity source. |
| link:anchor:EXP-A:EXP-B:control-panel-desktop | content_anchor_match | valid | EXP-A, EXP-B | hive | primary | 2 | Identical key path and timestamp with identical value digest. This is content identity, not subject identity. |
| link:anchor:EXP-A:EXP-B:software-microsoft-windows-currentversion-explor-01234040 | content_anchor_match | valid | EXP-A, EXP-B | hive | primary | 2 | Identical key path and timestamp with identical value digest. This is content identity, not subject identity. |
| link:anchor:EXP-A:EXP-B:software-microsoft-windows-currentversion-explor-61e9f7e0 | content_anchor_match | valid | EXP-A, EXP-B | hive | primary | 2 | Identical key path and timestamp with identical value digest. This is content identity, not subject identity. |
| link:anchor:EXP-A:EXP-B:software-microsoft-windows-currentversion-explor-8a5a6b63 | content_anchor_match | valid | EXP-A, EXP-B | hive | primary | 2 | Identical key path and timestamp with identical value digest. This is content identity, not subject identity. |
| link:anchor:EXP-A:EXP-B:software-microsoft-windows-currentversion-explor-9b63e800 | content_anchor_match | valid | EXP-A, EXP-B | hive | primary | 2 | Identical key path and timestamp with identical value digest. This is content identity, not subject identity. |
| link:anchor:EXP-A:EXP-B:software-microsoft-windows-currentversion-explor-aea6d0a2 | content_anchor_match | valid | EXP-A, EXP-B | hive | primary | 2 | Identical key path and timestamp with identical value digest. This is content identity, not subject identity. |
| link:clone:EXP-A:EXP-B | clone_or_copy | valid | EXP-A, EXP-B | caller | primary | 2 | Clone or copy lineage declared by sampling source or inferred from shared hive identity and anchors. |
| link:hive_identity:EXP-A:EXP-B | shared_hive_identity | valid | EXP-A, EXP-B | hive | primary | 2 | Exports share the registry-internal hive creation identity. |
| link:name:EXP-A:EXP-B:account-name-vibranium | shared_name_node | valid | EXP-A, EXP-B | hive | primary | 2 | Both exports independently resolve account_name='vibranium'. |
| link:name:EXP-A:EXP-B:profile-path-c-users-vibranium | shared_name_node | valid | EXP-A, EXP-B | hive | primary | 2 | Both exports independently resolve profile_path='c:\\users\\vibranium'. |
| link:plugin:EXP-A:EXP-B:typed-paths | plugin_corroboration | supplemental | EXP-A, EXP-B | plugin | supplemental | 2 | Plugin typed_paths output digest matches. Supplemental only; it cannot establish identity. |
| link:plugin:EXP-A:EXP-B:typed-urls | plugin_corroboration | supplemental | EXP-A, EXP-B | plugin | supplemental | 2 | Plugin typed_urls output digest matches. Supplemental only; it cannot establish identity. |
| link:plugin:EXP-A:EXP-B:user-assist | plugin_corroboration | supplemental | EXP-A, EXP-B | plugin | supplemental | 2 | Plugin user_assist output digest matches. Supplemental only; it cannot establish identity. |
| link:source:EXP-A:EXP-B | shared_lineage | valid | EXP-A, EXP-B | caller | primary | 2 | Exports share one acquisition lineage; repeated observations are not independent. |
| plugin:supplemental:EXP-A:ntuser-persistence | plugin_supplemental | supplemental | EXP-A | plugin | supplemental | 1 | Plugin-derived value retained as supplemental evidence only; it is not an original source. |
| plugin:supplemental:EXP-A:typed-paths | plugin_supplemental | supplemental | EXP-A | plugin | supplemental | 1 | Plugin-derived value retained as supplemental evidence only; it is not an original source. |
| plugin:supplemental:EXP-A:typed-urls | plugin_supplemental | supplemental | EXP-A | plugin | supplemental | 1 | Plugin-derived value retained as supplemental evidence only; it is not an original source. |
| plugin:supplemental:EXP-A:user-assist | plugin_supplemental | supplemental | EXP-A | plugin | supplemental | 1 | Plugin-derived value retained as supplemental evidence only; it is not an original source. |
| plugin:supplemental:EXP-B:ntuser-persistence | plugin_supplemental | supplemental | EXP-B | plugin | supplemental | 1 | Plugin-derived value retained as supplemental evidence only; it is not an original source. |
| plugin:supplemental:EXP-B:typed-paths | plugin_supplemental | supplemental | EXP-B | plugin | supplemental | 1 | Plugin-derived value retained as supplemental evidence only; it is not an original source. |
| plugin:supplemental:EXP-B:typed-urls | plugin_supplemental | supplemental | EXP-B | plugin | supplemental | 1 | Plugin-derived value retained as supplemental evidence only; it is not an original source. |
| plugin:supplemental:EXP-B:user-assist | plugin_supplemental | supplemental | EXP-B | plugin | supplemental | 1 | Plugin-derived value retained as supplemental evidence only; it is not an original source. |
| plugin:supplemental:EXP-C:ntuser-persistence | plugin_supplemental | supplemental | EXP-C | plugin | supplemental | 1 | Plugin-derived value retained as supplemental evidence only; it is not an original source. |
| plugin:supplemental:EXP-C:typed-paths | plugin_supplemental | supplemental | EXP-C | plugin | supplemental | 1 | Plugin-derived value retained as supplemental evidence only; it is not an original source. |
| plugin:supplemental:EXP-C:typed-urls | plugin_supplemental | supplemental | EXP-C | plugin | supplemental | 1 | Plugin-derived value retained as supplemental evidence only; it is not an original source. |
| plugin:supplemental:EXP-C:user-assist | plugin_supplemental | supplemental | EXP-C | plugin | supplemental | 1 | Plugin-derived value retained as supplemental evidence only; it is not an original source. |

## Plugin evidence (supplemental only)

| export | plugin | origin | role | used as source | can establish identity | digest | error |
|---|---|---|---|---|---|---|---|
| EXP-A | ntuser_persistence | plugin | supplemental | False | False | 76b64ed36a5c... |  |
| EXP-A | typed_paths | plugin | supplemental | False | False | 0dccf74067c2... |  |
| EXP-A | typed_urls | plugin | supplemental | False | False | 7e8c6dc6da65... |  |
| EXP-A | user_assist | plugin | supplemental | False | False | 8d6e0f788777... |  |
| EXP-B | ntuser_persistence | plugin | supplemental | False | False | f73c3a8e8ff6... |  |
| EXP-B | typed_paths | plugin | supplemental | False | False | 0dccf74067c2... |  |
| EXP-B | typed_urls | plugin | supplemental | False | False | 7e8c6dc6da65... |  |
| EXP-B | user_assist | plugin | supplemental | False | False | 8d6e0f788777... |  |
| EXP-C | ntuser_persistence | plugin | supplemental | False | False | 9343f6466354... |  |
| EXP-C | typed_paths | plugin | supplemental | False | False | b51275913fb0... |  |
| EXP-C | typed_urls | plugin | supplemental | False | False | 6a12bcdc69aa... |  |
| EXP-C | user_assist | plugin | supplemental | False | False | f97309aa8de1... |  |

## Record replacement and invalidation

- Replaced record: `EXP-B:volume` (volume_identity)
- Old value: `{"volume_serial": "1A2B3C4D", "disk_signature": "0xA1B2C3D4", "disk_guid": "fixture-disk-01", "volume_label": "FIXTURE-VOL-01", "device_serial": null, "image_sha256": null, "origin": "caller", "independently_verifiable": false, "evidence_path": "acquisition manifest (fixture)", "fixture": true, "note": "Clone retains the source volume identity in this fixture.", "fingerprint": "disk_guid=fixture-disk-01|disk_signature=0xa1b2c3d4|volume_serial=1a2b3c4d"}`
- New value: `{"volume_serial": "DEADBEEF", "disk_signature": "0xDEADBEEF", "disk_guid": "fixture-disk-replaced", "volume_label": "REPLACED", "device_serial": null, "image_sha256": null, "origin": "caller", "independently_verifiable": false, "evidence_path": "acquisition manifest (fixture)", "fixture": true, "note": "Clone retains the source volume identity in this fixture.", "fingerprint": "disk_guid=fixture-disk-replaced|disk_signature=0xdeadbeef|volume_serial=deadbeef"}`
- Verdict before: `conflict`
- Verdict after: `conflict`
- Note: Counterfactual: replace the clone volume identity record; show which associations depend on it.

**Invalidated associations**

- `link:volume:EXP-A:EXP-B` - Exports report the same volume fingerprint. Volume identity groups artifacts; it does not prove a user.

**Surviving associations**

- `link:anchor:EXP-A:EXP-B:control-panel-desktop` - Identical key path and timestamp with identical value digest. This is content identity, not subject identity.
- `link:anchor:EXP-A:EXP-B:software-microsoft-windows-currentversion-explor-01234040` - Identical key path and timestamp with identical value digest. This is content identity, not subject identity.
- `link:anchor:EXP-A:EXP-B:software-microsoft-windows-currentversion-explor-61e9f7e0` - Identical key path and timestamp with identical value digest. This is content identity, not subject identity.
- `link:anchor:EXP-A:EXP-B:software-microsoft-windows-currentversion-explor-8a5a6b63` - Identical key path and timestamp with identical value digest. This is content identity, not subject identity.
- `link:anchor:EXP-A:EXP-B:software-microsoft-windows-currentversion-explor-9b63e800` - Identical key path and timestamp with identical value digest. This is content identity, not subject identity.
- `link:anchor:EXP-A:EXP-B:software-microsoft-windows-currentversion-explor-aea6d0a2` - Identical key path and timestamp with identical value digest. This is content identity, not subject identity.
- `link:clone:EXP-A:EXP-B` - Clone or copy lineage declared by sampling source or inferred from shared hive identity and anchors.
- `link:hive_identity:EXP-A:EXP-B` - Exports share the registry-internal hive creation identity.
- `link:name:EXP-A:EXP-B:account-name-vibranium` - Both exports independently resolve account_name='vibranium'.
- `link:name:EXP-A:EXP-B:profile-path-c-users-vibranium` - Both exports independently resolve profile_path='c:\\users\\vibranium'.
- `link:source:EXP-A:EXP-B` - Exports share one acquisition lineage; repeated observations are not independent.
- 24 supplemental associations also survive and are listed in the JSON result.

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

Internal review fixture. The three hive files are the repository NTUSER fixtures. Acquisition/volume metadata below is synthetic and marked fixture=true; replace it with the case acquisition records before relying on the result. EXP-B is a derived clone of EXP-A (NTUSER_modified carries the same hive creation GUID and 6 of 7 anchor digests). EXP-C is the independent tony export.
