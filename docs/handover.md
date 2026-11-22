# Offline remediation handovers

`pip-audit-handover` builds a disclosure-safe, signable handover package from
three offline inputs:

1. the project team's original remediation plan,
2. a `pip-audit -f json` result collected in an isolated environment, and
3. zero or more receipts from the remediation vendor.

The output binds the original plan, the disclosure-safe target identities, and
the versions confirmed by the offline audit. It deliberately omits external
index addresses and internal filesystem paths.

## Quick start

```console
$ pip-audit-handover \
    --plan examples/handover/remediation-plan.json \
    --audit examples/handover/pip-audit-offline.json \
    --receipt examples/handover/receipts/RCPT-1001.json \
    --receipt examples/handover/receipts/RCPT-1002.json \
    --receipt examples/handover/receipts/RCPT-1003.json \
    --output-dir examples/handover \
    --generated-at 2026-11-22T00:00:00Z \
    --signer project-release-approver
```

This writes two mutually consistent artifacts:

* `handover.json` - the machine-readable package and reconciliation record.
* `HANDOVER.md` - a human-readable sign-off sheet.

The command exits successfully even when the package is partial. Add
`--fail-on-incomplete` to exit with status `2` if any item remains in progress.

## Package layout

The JSON package exposes the following reconciliation surfaces:

* `bindings.plan` - plan ID plus raw and canonical SHA-256 digests.
* `bindings.audit` - offline audit digest and any audit conflicts or skips.
* `bindings.receipts` - digest for every submitted receipt.
* `targets` - package name, target version, `target_id`, and opaque
  `disclosure_id` for each plan item.
* `environment.confirmed_versions` - versions confirmed by the offline audit.
* `receipts` - the complete receipt register, including match and duplicate
  state.
* `items` - per-item evidence, close-out state, and reconciliation digest.
* `missing_materials` and `pending_missing_materials` - the materials still
  owed for every item and for pending items respectively.
* `next_actions` - the exact follow-up the vendor must perform.
* `signoff` - payload digest, signature, and ready/pending item lists.

## Input schemas

### Remediation plan

```json
{
  "plan_id": "RP-2026-11",
  "title": "Release 2026.11 dependency remediation",
  "items": [
    {
      "item_id": "RMD-001",
      "package": "urllib3",
      "target_version": "2.2.2",
      "aliases": ["KITE-17", "KITE-31"],
      "required_materials": ["version_confirmation", "vendor_attestation"],
      "advisories": ["CVE-2024-37891"]
    }
  ]
}
```

`aliases`, `codenames`, `rotating_names`, and `receipt_names` are accepted as
synonyms. The same applies to `item_id`/`id`, `package`/`name`,
`target_version`/`version`, and `required_materials`/`required_evidence`.

`required_materials` may be a list of names or an object mapping a name to a
minimum count. The environment version is required implicitly whenever the
plan item declares a target version.

### Offline audit result

The modern `pip-audit -f json` shape is supported:

```json
{
  "dependencies": [
    {"name": "urllib3", "version": "2.2.2", "vulns": []}
  ],
  "fixes": []
}
```

A bare dependency array, a `{name: version}` map, and CycloneDX components are
also accepted. Vulnerability descriptions and URLs are never copied into the
handover package; only IDs, aliases, and fix versions are retained for
reconciliation.

### Vendor receipt

```json
{
  "receipt_id": "RCPT-1001",
  "target": "KITE-17",
  "materials": ["version_confirmation", "vendor_attestation"],
  "received_at": "2026-11-20T09:30:00Z",
  "vendor": "Northwind Remediation"
}
```

A receipt may identify its target through a plan item ID, a rotating alias, a
package name, or a `target_id` such as `urllib3@2.2.2`. Receipts need not repeat
the package name or version; those identities are bound from the original plan
and the offline audit result.

## Reconciliation and close-out rules

* Receipts are matched to exactly one plan item. Ambiguous or unknown receipts
  are reported in `unmatched_receipts` and never contribute evidence.
* The same receipt ID submitted twice is ignored after the first occurrence.
* Two receipts for the same item with the same material set are recorded as
  duplicates and contribute no additional evidence. Receiving an item twice
  therefore cannot close an item that is still missing a required material.
* An item is `closed` only when every required material is present, with the
  required multiplicity, and the audited environment version matches the
  plan's target version. Otherwise it remains `in_progress`.
* A partial package always includes `missing_materials` and `next_actions`, so
  the vendor can return exactly the missing evidence.

## Disclosure guarantees

The generated package never includes input file paths. URLs and absolute
filesystem paths found in free-text or metadata are replaced with
`[redacted:url]` and `[redacted:path]`. Fields named like `index_url`,
`extra_index_urls`, `registry_url`, `artifact_path`, `path`, and `url` are
dropped. Real registries and workspace roots therefore never reach the
approver.

The approver can still reconcile each item through:

* `plan_item_id` and the plan item's SHA-256 digest,
* `target_id` and the opaque `disclosure_id`,
* the package name and target version,
* the confirmed environment version and its audit-row digest,
* matched receipt IDs, receipt digests, and the item's
  `reconciliation_sha256`.

## Sign-off and verification

`signoff.payload_sha256` is the SHA-256 of the canonical package payload with
the `signoff` member removed. Canonical JSON uses sorted keys, compact
separators, and UTF-8 without ASCII escaping. If the
`PIP_AUDIT_HANDOVER_SIGNING_KEY` environment variable is set, the payload digest
is HMAC-SHA-256 signed; otherwise the digest itself is published as a detached
integrity value.

Verify a package from Python:

```python
import json
from pip_audit.handover import verify_handover

package = json.load(open("examples/handover/handover.json"))
assert verify_handover(package)
```

With a shared key:

```python
assert verify_handover(package, signing_key="shared-secret")
```

The Markdown sign-off sheet includes the payload digest and blank approver,
date, and signature lines.
