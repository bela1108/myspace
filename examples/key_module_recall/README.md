# Cryptographic key module recall reconciliation

This demo reconciles a procurement recall of devices that contain an old-type
cryptographic key module. It covers three physical states that must not be
conflated:

* modules **actually installed** in field devices;
* spares that are **allowed replacements** for those installed modules;
* spares that are **confirmed sealed** in a warehouse.

## Separation of responsibilities

| Concern | File | What it is allowed to say |
| --- | --- | --- |
| Component type and lifecycle | `data/asset_inventory.json` + `asset_inventory.py` | Which bom-ref exists, its CycloneDX `type`, and whether it is installed/spare/sealed |
| Replacement restrictions | `data/replacement_policy.json` + `replacement_policy.py` | Only which spare bom-ref may replace which installed bom-ref |
| Local disposition | `data/disposition_list.json` + `reconcile.py` | Which physical objects have actually been recalled |

The replacement policy deliberately contains no component type or lifecycle
information, and the reconciliation never infers replacement eligibility from
naming or shared product versions. A spare is replaceable only when the
independent policy declares a rule for it.

## CycloneDX mapping

The asset inventory is rendered as a CycloneDX 1.7 BOM:

* field devices are nested `device` components;
* installed and spare key modules use `cryptographic-asset` components;
* the single shared spare is one top-level component, not one copy per device;
* per-component state is carried in namespaced properties
  (`urn:example:key-module-recall:lifecycle`) so it remains bound to the
  physical object after a JSON round trip;
* BOM metadata keeps the standard `operations` lifecycle phase;
* the warehouse seal is recorded as seal properties plus an `evidence`
  external reference. The seal property explicitly states that it proves
  current unavailability only and is not recall evidence.

## Running the demo

```shell
.venv/bin/python -m examples.key_module_recall.demo
```

The script serializes the BOM to JSON, validates it against the CycloneDX 1.7
schema, deserializes it again, asserts the re-serialized document is
identical, and reconciles the reparsed BOM against the two local lists.

Generated artifacts are written to `out/` (git-ignored):

* `sbom.json` - serialized CycloneDX BOM;
* `roundtrip_sbom.json` - BOM produced after deserialization;
* `reconciliation_report.json` - coverage report.

## Expected outcome of the bundled scenario

* `device-bravo` and `module-bravo` are listed as recalled, so Bravo is
  reported as a covered device.
* `device-alpha` / `module-alpha` have no disposition entry, so Alpha is the
  pending recall device.
* `spare-k100-shared` may replace both installed modules according to the
  independent policy, but it is only warehouse-sealed. It is reported as
  `sealed-pending` and appears in `sealOnlyRefs`: the seal proves the spare is
  currently unavailable, not that the recall obligation has been met.
