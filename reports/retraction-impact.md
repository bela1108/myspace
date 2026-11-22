# Advisory retraction impact review

- Advisory: `CVE-2026-0001`
- As of: `2026-11-01T00:00:00+00:00`
- Advisory interval: `2026-09-01T00:00:00+00:00` to `2026-10-01T00:00:00+00:00`
- Retracted at: `2026-10-03T00:00:00+00:00`

## Provable scope

| Outcome | Assets |
| --- | --- |
| Confirmed closed | wls-01 |
| Still affected | wls-02 |
| Insufficient evidence | wls-03 |
| Excluded families | apache_log4j |
| Exclusion not proven | openssl |

## Asset assessments

### `wls-01` (oracle_weblogic)

- Status: **confirmed_closed**
- historical_match: inventory evidence contains at least one CPE matching the advisory condition (cpe:2.3:a:oracle:weblogic_server:12.2.1.3:*:*:*:*:*:*:*)
- verified_replacement: verified replacement evidence shows the affected component was replaced at 2026-10-18T00:00:00+00:00 (CHG-4711 / signed install receipt)
- Observed matches: `cpe:2.3:a:oracle:weblogic_server:12.2.1.3:*:*:*:*:*:*:*` at `2026-09-15T00:00:00+00:00`

### `wls-02` (oracle_weblogic)

- Status: **still_affected**
- historical_match: inventory evidence contains at least one CPE matching the advisory condition (cpe:2.3:a:oracle:weblogic_server:12.2.1.3:*:*:*:*:*:*:*)
- cpe_match: the latest observation still matches the advisory condition (cpe:2.3:a:oracle:weblogic_server:12.2.1.3:*:*:*:*:*:*:*)
- Observed matches: `cpe:2.3:a:oracle:weblogic_server:12.2.1.3:*:*:*:*:*:*:*` at `2026-09-15T00:00:00+00:00`, `cpe:2.3:a:oracle:weblogic_server:12.2.1.3:*:*:*:*:*:*:*` at `2026-10-20T00:00:00+00:00`

### `wls-03` (oracle_weblogic)

- Status: **missing_evidence**
- incomplete_manifest: the asset manifest is incomplete; a non-match cannot prove the component is absent (only 1 of 3 package sources submitted)

## Family exclusions

- `apache_log4j`: excluded — inventory coverage for family 'apache_log4j' is complete
- `openssl`: not excluded — inventory coverage for family 'openssl' is incomplete; a non-match cannot exclude it

