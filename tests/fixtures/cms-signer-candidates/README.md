# CMS signer certificate candidate fixtures

These fixtures are intentionally small and only model certificate matching and
evidence layering. The signatures are placeholders and are not cryptographically
valid.

- `issuer-serial-duplicate.der`: one outer SignerInfo identified by issuer and
  serial number, with the same matching certificate encoded twice in the
  package certificate set.
- `ski-conflict.der`: one outer SignerInfo identified by subject key identifier,
  with two distinct certificates that carry the same key identifier.
- `nested-missing.der`: one outer signer with a matching certificate and one
  Microsoft nested-signature signer whose nested certificate set is empty.

Run `python build.py` from this directory to regenerate the `.der` files. The
builder reads `../keys/test-der.crt` and does not require private keys.
