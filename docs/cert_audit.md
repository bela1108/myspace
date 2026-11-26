# cert_audit: public-material-only certificate archive review

`cert_audit` is a local review tool for display-only certificate handovers.
It parses PKCS#12 (`.p12`/`.pfx`) and X.509 (PEM/DER) data with
[asn1crypto](https://github.com/wbond/asn1crypto) and never exports private
key material.

## What it does

- Extracts certificate bags, friendly names, local key ids and trusted-key
  usages from PKCS#12 files, plus plain X.509 PEM/DER input.
- Counts `key_bag`, `pkcs8_shrouded_key_bag`, CRL and secret bags without
  parsing or dumping their contents. Encrypted safe contents are flagged as
  opaque instead of being decrypted.
- Rejects PEM private-key blocks outright.
- Confirms leaf chains from the archive's own public material (CA flag,
  issuer name, AKI/SKI). When `cryptography` is installed, each signature is
  additionally verified with the issuer public key; use
  `--no-signature-verification` for structural-only confirmation.
- Compares each leaf against a credential manifest of approved leaves and
  intermediates, including approved leaf-to-intermediate associations and
  authorized extended key usages.
- Retains three review situations as explicit findings:
  - `duplicate_friendly_name` — two same-subject certificates under one name,
  - `no_confirmable_chain` — no issuer/chain can be confirmed locally,
  - `unauthorized_usage` — the leaf is not approved or its EKU/issuer is not
    authorized.
- Compares two batches and states which one contains the complete public
  material needed for handover.

## Credential manifest

Manifests are JSON (YAML also works if a YAML loader is installed):

```json
{
  "allowed_usage": ["server_auth", "client_auth"],
  "intermediates": [
    {"subject_key_identifier": "3661DBB1..."}
  ],
  "leaves": [
    {
      "sha256_fingerprint": "C61EF8CD...",
      "usage": ["server_auth"],
      "allowed_issuers": [
        {"subject_key_identifier": "3661DBB1..."}
      ]
    }
  ]
}
```

Selector fields (all fields in one selector must match):

- `sha256_fingerprint` — 64 hex chars, colons/spaces allowed
- `subject_key_identifier`, `authority_key_identifier` — hex, separators allowed
- `subject`, `issuer` — asn1crypto `Name.human_friendly` strings
- `serial_number` — decimal serial number
- `friendly_name` — PKCS#12 friendly name

A leaf is authorized when a manifest entry matches it, its EKU intersects the
entry's `usage` (or top-level `allowed_usage`), and — when `allowed_issuers`
is given — an approved issuer selector matches a certificate on its confirmed
chain. `any_extended_key_usage` in a leaf EKU satisfies any requested usage.

## Command line

```bash
# Compare two batches; print the handover verdict and write JSON
python -m cert_audit batch-a.p12 batch-b.p12 -m manifest.json -o report.json

# Single archive, structural chain checks only
python -m cert_audit archive.pfx -m manifest.json --no-signature-verification
```

The JSON report contains the full inventory, per-leaf chains, manifest
decisions, retained findings and the comparison verdict.

## Private-key-free demo

```bash
python -m cert_audit.demo "$TMPDIR/cert-audit-demo"
```

The demo generates short-lived test certificates in memory with
`cryptography`, writes two certificate-only PFX files (no key bags and no
MAC), and prints which batch has complete handover material. The generated
private keys never leave the process.

## Python API

```python
from cert_audit import build_comparison, build_report, load_archive, load_manifest

manifest = load_manifest('manifest.json')
review_a = build_report(load_archive('batch-a.p12'), manifest)
review_b = build_report(load_archive('batch-b.p12'), manifest)
comparison = build_comparison(review_a, review_b)
```

## Tests

```bash
python -m tests
```

`tests/test_cert_audit.py` covers both batches, all three finding types,
cert-only and key-bag PFX files, PEM/DER input, manifest decisions and the
CLI. `tests/cert_audit_fixtures.py` builds deterministic test material with
`cryptography`; the archives themselves contain public certificates only.
