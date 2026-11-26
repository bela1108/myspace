# Secure handoff protocol

`asn1crypto.handoff` keeps four concerns separate when a parsed CMS object is
passed across a process boundary:

- `PresentableProjection` is report text or another lazy display value.
- `VerifiableMaterial` is the exact original byte string that a verifier can
  hash or parse.
- `VerificationReceipt` is an independent conclusion bound to an
  `EvidenceIdentity`.
- `HandoffBundle` combines those inputs and decides whether the current receipt
  is reusable.

The evidence identity is derived from the material digest and the canonical
inspection scope. Projection text, Python object ids, lazy expansion, cloning
and display-only re-encoding do not affect it. A changed scope produces a new
identity even when the rendered report text is identical.

```python
from asn1crypto.cms import ContentInfo
from asn1crypto.handoff import (
    HandoffBundle,
    LocalSignoff,
    PresentableProjection,
    VerifiableMaterial,
)

der = open('message.p7s', 'rb').read()
scope = {'purpose': 'print', 'sections': ['header', 'approval']}
material = VerifiableMaterial(der, spec='cms')
identity = material.evidence_identity(scope)

# The local clerk structure is an ordinary sign-off record. HMAC is optional
# and only authenticates the local record; it is not CMS signature verification.
receipt = LocalSignoff.sign_off(
    identity,
    decision='verified',
    signed_by='independent-reviewer',
    secret='local-hmac-secret',
)

bundle = HandoffBundle(
    PresentableProjection('Approval report'),
    material,
    receipt,
    scope,
    receipt_secret='local-hmac-secret',
)

bundle.view_report()       # Does not call a verifier or change status.
transferred = bundle.to_bytes()
restored = HandoffBundle.from_bytes(transferred)
cloned = restored.clone()  # Identity and receipt binding survive.

wider = cloned.with_scope(dict(scope, sections=['header', 'approval', 'certs']))
assert str(wider.view_report()) == 'Approval report'
assert wider.status == 'pending'
assert wider.needs_reverification
```

`VerifiableMaterial.reencode()` explicitly returns new material. Canonical DER
that remains byte-identical keeps the same identity; a worker-added default or
other reconstruction that changes bytes produces a new identity and requires a
new receipt.
