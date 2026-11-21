.. # Licensed under the Apache License, Version 2.0 (the "License");
   # you may not use this file except in compliance with the License.
   # You may obtain a copy of the License at
   #
   #     http://www.apache.org/licenses/LICENSE-2.0
   #
   # Unless required by applicable law or agreed to in writing, software
   # distributed under the License is distributed on an "AS IS" BASIS,
   # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   # See the License for the specific language governing permissions and
   # limitations under the License.
   #
   # SPDX-License-Identifier: Apache-2.0

Manifest comparison
===================

The manifest comparison entry point is independent of the SBOM generator.  It
loads two CycloneDX JSON or XML documents and compares their components in
three stages:

1. verifiable content hashes (algorithm and digest must both match),
2. component coordinates (PURL, CPE, group/name/version),
3. component evidence (identity values, occurrences and call stacks).

A later stage never silently overrides an earlier stage.  A component is
selected only when all non-empty stages agree on exactly one current
candidate.  Otherwise the report keeps every candidate and explains why.

Command line
------------

.. code-block:: console

   python -m cyclonedx.contrib.bom.compare baseline.json current.json --pretty

The same entry point is installed as ``cyclonedx-bom-compare``.  Use
``--output report.json`` to write the JSON report to a file.  The report can be
consumed by an investigator or another tool.

Python API
----------

.. code-block:: python

   from cyclonedx.contrib.bom.compare import compare_manifests

   comparison = compare_manifests("baseline.json", "current.json")
   report = comparison.to_dict()
   split = comparison.match_for_bom_ref("widget-suite@1.4.0")
   alert_traces = comparison.trace_for_vulnerability("CVE-2026-1001")

Split, repackaging and dependency transfer
------------------------------------------

When a baseline component is split into several current components, the report
uses ``status: split`` and retains all candidates.  Each candidate includes:

* its own current dependency edges,
* the baseline dependency edges it came from,
* preserved, transferred, dropped and added dependencies.

When content is repackaged under a new coordinate, a matching hash can select
the new component and the relationship is reported as ``repackaged``.  If a
dependency edge moved from the old component to the repackaged one, the report
also contains a ``dependency_transfers`` entry.

Conflicting evidence
--------------------

If hashes, coordinates and evidence point at different current components, the
status is ``conflict`` (or ``split`` when the baseline evidence is genuinely
partitioned across candidates).  In both cases ``selected`` is ``null``.  The
report deliberately does not choose the "most similar" component.

Alerts
------

Vulnerabilities declared in the baseline manifest are traced through the
component matching result.  Every trace candidate has ``may_affect: true``,
its match basis, a selection marker and current dependency paths from the
manifest root.  A disappeared alert therefore remains visible as an unresolved
or split candidate instead of being silently dropped.

Local fixtures
--------------

``tests/_data/compare/1.6`` contains JSON fixtures for split, repackaging,
dependency transfer, conflicting evidence and a same-name-only component that
must not be matched.  The fixture README describes each case and the exact
command to reproduce the report.
