# Differential review example: SMB signing

This example demonstrates why a single registry value cannot always be reported
as one unambiguous "enabled" finding.

`EnableSecuritySignature` exists under both:

- `HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters`
- `HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters`

The two keys describe different scopes. The workstation flag describes client
behaviour; the server flag describes the server role. On the supplied SYSTEM
hive the workstation flag is `1`, while the server flags are both `0`, and the
machine is domain-joined (`Domain = shieldbase.local`).

## The two interpretations

- `smb_signing_legacy.json` reproduces the historical report: it looks only at
  the workstation flag and concludes `enabled`.
- `smb_signing_domain_server.json` is a legitimate alternative: on a
  domain-joined host the server-side parameters govern the claim, so the same
  collection is consistent with `disabled`.

Run both against one hive:

```bash
regipy-review /path/to/SYSTEM \
  --rule-set examples/review/smb_signing_legacy.json \
  --rule-set examples/review/smb_signing_domain_server.json \
  --prior-claim smb_signing=enabled
```

Or use the Python API:

```python
from regipy.review import review_hive

report = review_hive(
    "/path/to/SYSTEM",
    [
        "examples/review/smb_signing_legacy.json",
        "examples/review/smb_signing_domain_server.json",
    ],
    prior_claims={"smb_signing": "enabled"},
)
print(report["results"]["smb_signing"]["status"])  # pending
```

The result is intentionally `pending`, not `enabled`. It contains:

- `candidates`: both `enabled` and `disabled`;
- `prior_claim.status`: `disputed`, with the alternative interpretation listed
  under `refuting_interpretations`;
- `divergence.assumptions`: exactly the two assumptions that differ between the
  interpretations:
  - `scope` — whether workstation or server parameters govern the host;
  - `sufficiency` — whether one enable flag is enough, or both server flags are
    required.

Each condition keeps its raw hive path/value and, where the same value appears
in plugin output, the plugin name plus the entry path and list indices. That is
the audit trail an investigator can use to challenge the historical one-line
finding.

## Demo script

```bash
python examples/review/demo_smb_signing.py /path/to/SYSTEM
```
