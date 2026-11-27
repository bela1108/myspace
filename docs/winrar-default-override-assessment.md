# WinRAR Read-Only Observations: Default Template vs. User Override

## Scope and Evidence Standard

This assessment uses only the two synthetic NTUSER hives whose embedded REGF file name identifies the same preserved user scope, `\??\C:\Users\tony\ntuser.dat`:

- `regipy_tests/data/NTUSER_BAGMRU.DAT.xz`
- `regipy_tests/data/NTUSER_with_winscp.DAT.xz`

A value is described as adopted by Tony only when it can be traced to Tony's own saved registry observation in one of those hives. A value appearing in both hives because it belongs to a WinRAR installation template is not, by itself, evidence of adoption.

Both hives have mismatched primary and secondary sequence numbers and no corresponding WinRAR-specific transaction logs were included in the sampled material. The assessment therefore covers the saved primary-hive state readable at analysis time only; transaction-log-only changes cannot be confirmed.

## Read-Only Plugin Boundary

`WinRARPlugin` reads only these saved history paths:

- `\SOFTWARE\WinRAR\ArcHistory`
- `\SOFTWARE\WinRAR\DialogEditHistory\ArcName`
- `\SOFTWARE\WinRAR\DialogEditHistory\ExtrPath`

It does not enumerate `\SOFTWARE\WinRAR\Profiles`. Consequently, the five WinRAR profiles are contextual template evidence, not plugin-reported user history. The plugin output has no identical history entry across the two hives: the first contains 26 observations, the second contains 5, and their intersection is empty.

## Preserved User Scope and Readable Template Version

| Evidence | `NTUSER_BAGMRU.DAT.xz` | `NTUSER_with_winscp.DAT.xz` | Assessment |
| --- | --- | --- | --- |
| Embedded user scope | `\??\C:\Users\tony\ntuser.dat` | `\??\C:\Users\tony\ntuser.dat` | Same target user, separate preserved snapshots. |
| WinRAR profile parent last write | `2021-07-20T15:21:17.692428+00:00` | `2022-03-09T12:23:26.494118+00:00` | Different readable template/install states. |
| Profile subkeys present | `0` through `4` | `0` through `4` | No extra user-created profile key is present. |
| `General\VerInfo` | `000106006d23e6e27a7dd701` | `000a060028d3347ab033d801` | Supports separate WinRAR version/installation states; exact marketing version is not decoded by the plugin. |
| Sequence numbers | primary `29989`, secondary `29988` | primary `5161`, secondary `5160` | Both primary hives are dirty; absent logs leave possible transaction-only updates unconfirmed. |

## Default Template and Override Matrix

| Profile | Default-template marker and displayed value | Evidence in first snapshot | Evidence in second snapshot | Report conclusion |
| --- | --- | --- | --- | --- |
| `0` | `Name = Default Profile`; `Default = 1`; `Method = 3`; `RAR5 = 1`; `Solid = 0`; `UseRAR = 1`; `GenerateMask = yyyymmddhhmmss`; `VolumeSize = 0` | 75 values; last write `2021-07-20T15:21:17.686354+00:00` | 75 values; last write `2022-03-09T12:23:26.482834+00:00` | Default profile is present in both. Do not call its common settings user-adopted solely because both archives display them. |
| `0` override candidate | `StoreNames` | `*.rar *.zip *.cab *.7z *.ace *.arj *.bz2 *.gz *.lha *.lzh *.taz *.tgz *.xz *.txz` | Adds `*.zipx` to the association list | This is a readable template/version difference, not sufficient evidence that Tony manually changed the default profile. No UI action, transaction log, or separate user-created profile is available to prove an intentional override. |
| `1` | `Name = Create e-mail attachment`; `Default = 0`; `Method = 5`; `RAR5 = 1`; `Solid = 1`; `UseRAR = 1` | 75/75 values identical to second snapshot; last write `2021-07-20T15:21:17.687884+00:00` | 75/75 values identical; last write `2022-03-09T12:23:26.487908+00:00` | Preset template only. No confirmed Tony override. |
| `2` | `Name = Backup selected files`; `Default = 0`; `Method = 3`; `RAR5 = 1`; `Solid = 0`; `UseRAR = 1` | 75/75 values identical; last write `2021-07-20T15:21:17.690028+00:00` | 75/75 values identical; last write `2022-03-09T12:23:26.491110+00:00` | Preset template only. No confirmed Tony override. |
| `3` | `Name = Create 10 MB volumes`; `Default = 0`; `Method = 3`; `RAR5 = 1`; `Solid = 1`; `UseRAR = 1`; `VolumeSize = 10485760` | 75/75 values identical; last write `2021-07-20T15:21:17.691430+00:00` | 75/75 values identical; last write `2022-03-09T12:23:26.494118+00:00` | Preset template only. The displayed 10 MB volume size is not evidence that Tony selected that profile. |
| `4` | `Name = ZIP archive (low compression)`; `Default = 0`; `Method = 3`; `RAR5 = 1`; `Solid = 0`; `UseRAR = 0` | 73/73 values identical; last write `2021-07-20T15:21:17.693426+00:00` | 73/73 values identical; last write `2022-03-09T12:23:26.497258+00:00` | Preset template only. No confirmed Tony override. |
| Any additional custom profile | Expected as a subkey under `\SOFTWARE\WinRAR\Profiles` | Only `0` through `4` exist | Only `0` through `4` exist | No saved custom profile is available in either sampled primary hive. |

## Saved User Observations That Support Adoption

The following plugin observations are saved under Tony's NTUSER hive and can support user-level activity findings. They are distinct from the preset profile values.

| Snapshot | Operation and source key | Saved observations | Tony-scoped observations | Conclusion |
| --- | --- | ---: | ---: | --- |
| `NTUSER_BAGMRU.DAT.xz` | `archive_opened` from `ArcHistory` | 4 | 4 under `C:\Users\tony` | Adopted/saved open-history observations for this snapshot. |
| `NTUSER_BAGMRU.DAT.xz` | `archive_created` from `DialogEditHistory\ArcName` | 6 | 0 direct user-directory values; filenames alone are saved | Archive-creation history is present; target location is not encoded in these values. |
| `NTUSER_BAGMRU.DAT.xz` | `archive_extracted` from `DialogEditHistory\ExtrPath` | 16 | 8 under `C:\Users\tony`; other paths include `C:\Offline` and `C:\Training` | Extraction history is present; do not reclassify non-user-profile paths as template defaults. |
| `NTUSER_with_winscp.DAT.xz` | `archive_opened` from `ArcHistory` | 4 | 3 under `C:\Users\tony`; one is `D:\VPN Certs.zip` | Adopted/saved open-history observations for this snapshot. |
| `NTUSER_with_winscp.DAT.xz` | `archive_created` from `DialogEditHistory\ArcName` | 1 (`confluence.zip`) | 0 direct user-directory value; filename alone is saved | Archive-creation history is present; target location is not encoded in this value. |
| `NTUSER_with_winscp.DAT.xz` | `archive_extracted` from `DialogEditHistory\ExtrPath` | Key absent | 0 | No extraction adoption can be claimed from this snapshot. |

## Reporting Wording

### Supported

- Say WinRAR's built-in profiles `0` through `4` were present in Tony's preserved NTUSER hives.
- Say profiles `1` through `4` had identical saved values in both readable template states.
- Say profile `0` differed only in `StoreNames`; the later readable template state includes `*.zipx`.
- Say the plugin observed specific saved open/create/extract history entries in the corresponding history keys.
- Say a plugin history entry is a user-scoped observation when its saved path lies under `C:\Users\tony` or when the report explicitly limits the claim to activity in Tony's preserved NTUSER hive.

### Not Supported From Current Sampling

- Do not state that Tony adopted `Create e-mail attachment`, `Backup selected files`, `Create 10 MB volumes`, or `ZIP archive (low compression)` merely because both hives contain those profile names and values.
- Do not infer that Tony manually edited `Default Profile` from the `.zipx` difference alone; the difference aligns with a later WinRAR template/installation state, but no direct edit action is preserved.
- Do not claim a custom WinRAR profile existed; only profile subkeys `0` through `4` are present in both primary hives.
- Do not reconstruct missing transaction-log writes or claim that the primary hives represent the complete dirty-hive state.
- Do not treat a value shared by both synthetic archives as adopted unless it can be tied back to Tony's own saved history key or another explicit user-write observation.
