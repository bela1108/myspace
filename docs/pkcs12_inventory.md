# PKCS#12 Protection Inventory

`asn1crypto.pkcs12_audit` provides a read-only, layer-aware view of the
protection already visible in a PKCS#12 archive. It does not try passwords,
decrypt content, verify the MAC, or rewrite the file. Sealed content is kept as
`unobservable` so a caller can not mistake absence of evidence for a pass.

The same functionality is available as `Pfx.inventory()` and
`asn1crypto.pkcs12.inventory()`.

## Layer paths

Every conclusion names the ASN.1 layer where the protection is applied:

 - `pfx.auth_safe` - the outer ContentInfo around `AuthenticatedSafe`
 - `pfx.authenticated_safe[i]` - one ContentInfo inside `AuthenticatedSafe`
 - `pfx.authenticated_safe[i].encrypted_content_info` - the visible algorithm
   and parameters of an `encryptedData` layer
 - `pfx.authenticated_safe[i].safe_contents[j]` - a readable `SafeBag`
 - `...safe_contents[j].bag_value` - a shrouded key, key, certificate or secret
   bag value
 - `pfx.mac_data` - the PKCS#12 integrity MAC

A `SafeBag` entry reports its `bag_id`, its `bag_value` protection or key
algorithm, and its visible attributes (for example `friendly_name` and
`local_key_id`). A `pkcs8_shrouded_key_bag` exposes the encryption algorithm of
`EncryptedPrivateKeyInfo`, but its key material remains `unobservable`.

## Inventory

```python
from asn1crypto import pkcs12_audit

inventory = pkcs12_audit.inventory("archive.p12")

print(inventory["encapsulation"][1]["cipher"])
print(inventory["safe_bags"][0]["attributes"])
print(inventory["integrity"]["algorithm"])
print(inventory["summary"]["status"])
```

The main collections are:

 - `encapsulation` - publicly readable ContentInfo protection
 - `safe_bags` - readable SafeBags, visible attributes and visible bag
   protection algorithms
 - `integrity` - the primary PKCS#12 MAC; `integrities` also includes
   SignedData digest observations
 - `unobservable` - layers whose payload is sealed
 - `unknown` - readable wrappers whose payload type can not be interpreted
 - `entries` - all of the above descriptors in one list
 - `checks`, `findings`, `summary` - policy results bound to layer paths

`Pkcs12Inventory` subclasses `OrderedDict`; keys are also available as
attributes. `to_dict()` returns nested plain containers and `to_json()` returns
a JSON document (byte strings are rendered as hex).

## Policy results

The built-in checks cover the effective cipher (for PBES2 this is the inner
encryption scheme, not just the `pbes2` OID), the KDF and PBKDF2 iteration
count, the PRF, the integrity algorithm, and readable `keyBag` values that are
not encrypted. Defaults are in `DEFAULT_POLICY`; pass a dict to override
thresholds (`require_encrypted_private_keys` controls the last check):

```python
report = pkcs12_audit.governance_report(
    [("weak-inner", "weak-inner.p12"), ("strong-inner", "strong-inner.p12")],
    policy={"min_pbkdf2_iterations": 200000}
)

print(report["recommended_layers"])
```

Statuses are `pass`, `fail`, `unknown` and `unobservable`. Sealed content adds
an `unobservable` review item and makes the archive non-compliant; an unknown
wrapper produces an `unknown` item. Neither is converted to `pass`. A
`governance_report()` has:

 - `layers_to_change` - failing checks, highest severity first, each with
   `archive`, `layer`, `code` and `message`
 - `review_required` - unobservable or unknown layers, each with a layer path
 - `recommended_layers` - the exact layer paths to remediate first
 - `summary` - counts and `compliant`, which is only true when the conclusion
   is `pass`

## Paired samples

`tests/fixtures/pkcs12_inventory/` contains two archives with identical outer
`encryptedData` parameters and identical MAC settings:

 - `shared-outer-weak-inner.p12` - the inner shrouded key uses
   `pkcs12_sha1_rc2_40` with 2048 iterations
 - `shared-outer-strong-inner.p12` - the inner shrouded key uses PBES2 with
   AES-256-CBC and PBKDF2/SHA-256 at 120000 iterations

For the pair, the governance report points at
`pfx.authenticated_safe[1].safe_contents[0].bag_value` in the first archive only.
The identical outer layer is not proposed for replacement. Regenerate the
fixtures with:

```bash
python tests/fixtures/pkcs12_inventory/make_samples.py
```
