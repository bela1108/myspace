# Dependency Remediation Handover

- Package: `HO-8EF266C692A1`
- Schema: `pip-audit-handover/1`
- Status: **in_progress**
- Items: 1 closed / 1 in progress
- Receipts: 3 received, 1 duplicate

## Disclosure

External index addresses are omitted. Internal filesystem paths are redacted. Item identities and SHA-256 bindings below remain sufficient for item-by-item reconciliation against the original plan.

## Reconciliation

| Plan item | Target identity | Package | Target version | Confirmed | Required | Missing | Receipts | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| RMD-001 | TGT-A30DFCA28FE0 | urllib3 | 2.2.2 | 2.2.2 | environment_version, vendor_attestation, version_confirmation | - | RCPT-1001 | closed |
| RMD-002 | TGT-EB59176EB406 | jinja2 | 3.1.4 | 3.1.4 | environment_version, hash_manifest, vendor_attestation, version_confirmation | hash_manifest, vendor_attestation | RCPT-1002 | in_progress |

## Missing Materials

- `RMD-001`: none
- `RMD-002`: hash_manifest, vendor_attestation

## Receipt Reconciliation

| Receipt | Plan item | Version | Materials |
| --- | --- | --- | --- |
| RCPT-1001 | RMD-001 | - | vendor_attestation, version_confirmation |
| RCPT-1002 | RMD-002 | - | version_confirmation |

## Duplicate Receipts

- `RCPT-1003` duplicates `RCPT-1002` (same_item_same_material_set); no additional evidence counted.

## Sign-off

- Ready for sign-off: **no**
- Payload SHA-256: `9ec9433f476234026e98d4e741520558c715f0e653e592ab2b004302916392ff`
- Signature: `sha256` `9ec9433f476234026e98d4e741520558c715f0e653e592ab2b004302916392ff`
- Signer: project-release-approver

Approver: ______________________________

Date: ______________________________

Signature: ______________________________
