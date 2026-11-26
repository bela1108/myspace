# Offline two-layer accounting example

This example shows the `--account` offline entrypoint projecting one
audit report onto two accounting layers, using a declared ledger of
composition relationships and provenance. It is fully offline: no
environment is collected and no vulnerability service is contacted.

The ledger (`ledger.json`) declares:

* two release packages: `web-bundle` (pins `libfoo==1.2.3`, which has a
  known vulnerability, and `libsafe==2.0.0`, which is clean) and
  `data-bundle` (pins `libbar==4.5.6`, which has a known vulnerability);
* three services: `svc-gateway` and `svc-api` both embed `web-bundle`
  as-is (`shared` provenance), `svc-api` also embeds `data-bundle`
  as-is, and `svc-worker` embeds a **repackaged** copy of
  `data-bundle`;
* an `audit` report in the classic `pip-audit --format json` shape,
  whose version-level facts (name, version, vulnerability IDs, fix
  versions, aliases, descriptions) are carried through verbatim. A
  separate report file can be referenced with
  `"audit_report": "path/to/report.json"` instead of embedding `audit`.

Run it:

    pip-audit --account examples/offline-accounting/ledger.json

The output has two layers plus a reconciling summary:

* **Deliverable layer** (supply-chain quota): three deliverable units.
  `web-bundle#shared` is a single unit even though two services embed
  it, so its `libfoo` finding is charged to the quota **once**, not
  twice. `data-bundle#repackaged:svc-worker` is a separate unit from
  `data-bundle#shared`, because repackaging genuinely adds one unit of
  responsibility. Quota: 3 pending findings.
* **Service layer** (business-group ledger): each service sees its own
  pending items (4 in total), annotated with `shared_with` so teams can
  see which items are shared with other services.

The summary reconciles the layers: 4 service-layer items vs. 3
deliverable-layer findings, i.e. `shared_findings: 1` — the quota is
not multiplied by the number of services embedding the same release
package.
