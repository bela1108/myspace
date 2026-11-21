# Manifest comparison fixtures

These CycloneDX 1.6 manifests model the same inventory seen through two
different SBOM generators/versions.

- `baseline.json` contains the old inventory and three synthetic alerts.
- `current.json` contains no vulnerability declarations: the alerts appear to
  have "disappeared" because the inventory changed shape.

The fixture intentionally covers:

- `widget-suite` being split into `widget-core` and `widget-ui`;
- `legacy-parser` being repackaged as `parser-ng` with an identical SHA-256;
- the dependency on `legacy-parser` moving to `parser-ng` under the new parent;
- `telemetry` keeping its PURL while its old hash also appears in a new
  `telemetry-loader` component, producing conflicting evidence;
- an `opaque` component with the same name but no hash, coordinate or evidence
  link, which must remain unmatched rather than being guessed by name.

Run:

```console
python -m cyclonedx.contrib.bom.compare \
  tests/_data/compare/1.6/baseline.json \
  tests/_data/compare/1.6/current.json --pretty
```

Expected report highlights:

- `widget-suite` -> `status: split`, candidates `widget-core` and `widget-ui`;
- `legacy-parser` -> `status: matched`, selected `parser-ng`,
  `relationship: repackaged`;
- `telemetry` -> `status: conflict`, `selected: null`, candidates `telemetry`
  and `telemetry-loader`;
- `opaque` -> `status: unmatched` despite the identical component name;
- every old alert appears under `alerts` with current dependency paths and
  `may_affect: true` for each unresolved candidate.
