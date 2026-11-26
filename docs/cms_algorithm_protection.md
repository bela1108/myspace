# CMS Algorithm Protection Review (RFC 6211)

`asn1crypto.cms_algorithm_protection` performs a structural, offline review of
the CMS `id-aa-CMSAlgorithmProtect` attribute (OID
`1.2.840.113549.1.9.52`).  It answers a narrow question for each `SignerInfo`
and for `AuthenticatedData`:

> Does the algorithm protection attribute actually declare the digest,
> signature or MAC algorithm used by this structure, in a location covered by
> the signature or MAC?

The review does **not** verify signatures or MACs.  `signature_verified` is
always `false` and `verification` is always `not_performed`; callers must
perform cryptographic verification separately.

## Usage

```python
from asn1crypto import cms, cms_algorithm_protection

content_info = cms.ContentInfo.load(der_bytes)
review = cms_algorithm_protection.review(content_info)

for result in review.results:
    print(result.path, result.identity, result.status, result.verdict)
    for issue in result.issues:
        print('  ', issue['path'], issue['code'], issue['message'])

print(review.format_text())
```

`review()` accepts a `cms.ContentInfo`, `cms.SignedData`,
`cms.SignerInfo`, `cms.AuthenticatedData`, or DER/PEM `bytes`.  Equivalent
aliases are `analyze()`, `review_algorithm_protection()`,
`analyze_algorithm_protection()` and `check_algorithm_protection()`.
Convenience methods are also available as
`content_info.review_algorithm_protection()`,
`signer_info.algorithm_protection_review()` and
`authenticated_data.algorithm_protection_review()`.

Each result contains:

 - `kind`, `index` and `path`
 - `identity` (`issuer_and_serial_number` or `subject_key_identifier` for a
   signer, or the `AuthenticatedData` marker)
 - `attribute_locations`, including the exact attribute path and whether the
   location is authenticated (`signed_attrs` / `auth_attrs`)
 - one `checks` entry per digest, signature and MAC identifier
 - `issues` with a stable code, locatable path and human-readable message
 - `status`, `verdict`, `migratable`, `needs_materials` and
   `requires_manual_review`

## Status and verdict

| Status | Meaning | Verdict |
| --- | --- | --- |
| `protected` | Exactly one authenticated protection value, and every applicable algorithm identifier matches or is an allowed equivalent | `migrate` |
| `unprotected` | No protection attribute anywhere; the ledger claim is unsupported, not a contradiction | `supplement` |
| `unauthenticated` | Attribute exists only in `unsignedAttrs` / `unauthAttrs` | `supplement` |
| `duplicate` | Multiple attributes, multiple values, or an authenticated copy plus an unauthenticated copy | `supplement` |
| `algorithm_mismatch` | Algorithm OID/name differs | `supplement` |
| `parameter_mismatch` | Same algorithm name, but parameters are semantically different | `supplement` |
| `indeterminate` | Parameters or identifiers cannot be interpreted by this build | `manual_review` |
| `unexpected_component` | E.g. a MAC identifier in a `SignedData` signer | `supplement` |
| `malformed` | The attribute value cannot be decoded as a single `CMSAlgorithmProtection` | `supplement` |

`unprotected` is deliberately distinct from a conflict.  A legacy file with
no `CMSAlgorithmProtection` attribute has not made a false algorithm claim;
it simply has not supplied the material needed to support the ledger column.

## Permitted parameter equivalences

The comparison is semantic rather than a byte comparison of the `parameters`
field.  The following equivalences are reported with an explanation and do not
produce a false conflict:

 - **Digest and HMAC identifiers:** absent parameters and explicit `NULL` are
   equivalent because these identifiers carry no parameters in CMS.
 - **RSA PKCS#1 v1.5:** `NULL` is the defined parameter (RFC 4055 / RFC 8017);
   an absent field is accepted for legacy CMS files.
 - **DSA / ECDSA:** absent parameters are required (RFC 5758 / RFC 5480); a
   legacy explicit `NULL` is accepted because it conveys no digest or curve
   information.
 - **Ed25519 / Ed448:** absent parameters are required (RFC 8410); a legacy
   explicit `NULL` is accepted for review because it conveys no algorithm
   information.
 - **RSASSA-PSS:** parameters are normalized using the ASN.1 defaults
   (`SHA-1`, `MGF1` with `SHA-1`, `saltLength=20`, `trailerField=BC`).  An
   omitted/empty parameter set and an explicit set of those defaults are
   equivalent.  Different hash, MGF hash, salt length or trailer field values
   are a `parameter_mismatch`.
 - **OID aliases:** OIDs that asn1crypto maps to the same algorithm name (for
   example the legacy and current DSA OIDs for `sha1_dsa`) are treated as the
   same algorithm and the alias is called out in `notes`.
 - **Generic vs. digest-specific signature OIDs:** an older producer may use
   `rsaEncryption` where a newer one uses `sha256_rsa` (or the DSA/ECDSA
   equivalents).  These are treated as the same signature algorithm when the
   digest from `SignerInfo.digestAlgorithm` agrees with the digest-specific
   name, and the equivalence is called out in `notes`.

Opaque parameters for an algorithm this build does not know are reported as
`indeterminate`, even when both byte strings happen to be identical, because
semantic equivalence cannot be established.

## In-memory samples

`tests/cms_algorithm_protection_samples.py` builds a complete sample set in
memory and returns `cms.ContentInfo` objects.  It covers a protected signer, a
legacy signer with no declaration, an attribute in an unauthenticated location,
duplicate attributes and duplicate values, an OID alias, NULL/absent
equivalence, RSASSA-PSS default equivalence, a real RSASSA-PSS parameter
conflict, uninterpretable parameters, `AuthenticatedData`, and a mixed ledger
with one migratable signer and one signer that must return for materials.

Each sample round-trips through `content_info.dump()` and
`cms.ContentInfo.load()`; no binary fixture files are required.

To print the reviewer-facing ledger for all samples:

```bash
python -m tests.cms_algorithm_protection_samples
```
