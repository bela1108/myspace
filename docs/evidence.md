# CMS Attribute Evidence View

When a reviewer is given a CMS packet and a list of attribute explanations,
the explanations look interchangeable. The `asn1crypto.evidence` module ties
each parsed signed attribute back to the exact bytes it was decoded from, so a
compliance reviewer can tell which explanations are backed by the bytes that
were actually signed, and which have no provenance.

The view is strictly read-only. The source packet is parsed but never
re-encoded or mutated.

## Building a View

```python
from asn1crypto import evidence

with open('signed.p7m', 'rb') as f:
    packet = f.read()

view = evidence.evidence_for_packet(packet)
```

An already-parsed `cms.ContentInfo` may be passed together with its original
bytes as `(content_info, raw_bytes)`. The optional `signer_index` selects a
signer when the packet contains more than one.

## Parsed Value, Original Location and Bounds

Each entry exposes the parsed value and a `ByteLocation` recorded against the
packet's `PacketBounds`:

```python
for item in view:
    print(item.type_name, item.type_oid, item.statuses)
    print(item.location.offset, item.location.length)
    print(item.location.relative_offset)  # offset from the packet start
    print(item.verify_bytes(packet))      # re-check the original bytes
```

`item.original_bytes` and `item.location.bytes_from(packet)` return the exact
signed bytes, allowing an independent re-parse. `verify_bytes()` returns
`True` only when the recorded location still contains those bytes.

## Statuses

Every located attribute starts with `STATUS_ORIGINAL`. Additional statuses
describe compliance problems:

- `STATUS_DUPLICATE` - another attribute uses the same type OID. CMS SET OF
  attributes must not repeat an attribute type.
- `STATUS_UNKNOWN` - the type OID is not mapped in `cms.CMSAttributeType`, so
  the field has no semantic name. `item.known` is `False`.
- `STATUS_RELOCATED` - the value round-trips, but canonical DER re-encoding
  changes the byte layout, for example when a SET OF is not DER-sorted. The
  `canonical_location` and `canonical_bytes` record where the attribute would
  move after canonicalization.

Convenience collections are available on the view: `view.duplicates`,
`view.unknown` and `view.relocated`.

## Explanations With and Without Provenance

An `AttributeExplanation` is only a claim about an attribute. Pass a list of
them to cross-check each claim against the signed bytes:

```python
explanations = [
    evidence.AttributeExplanation(
        'Content type',
        '1.2.840.113549.1.9.3',
        expected_value='data',
    ),
    evidence.AttributeExplanation(
        'Claim with no source',
        '9.9.9.9.9',
    ),
]

result = evidence.evidence_for_packet(packet, explanations=explanations)

for entry in result:
    print(entry.explanation.label, entry.verifiable, entry.statuses)
```

An explanation whose type OID exists in the signed attributes is
`verifiable` and is linked to the matching `AttributeEvidence` and its
original location. An explanation that cannot be matched to any signed bytes
is reported with `STATUS_UNLOCATED`, exposes no location, and fails
`verify_bytes()`. The two are always kept separate in
`result.verifiable` and `result.unlocated`, so a reader never treats an
unsourced explanation as evidence of what was signed.
