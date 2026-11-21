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

Offline Impact Explanation
==========================

Two BOMs may describe the same vulnerability while the production image and the test image pull it in through
different dependency trees. The :func:`cyclonedx.impact.analyze_impact` helper reconstructs, fully offline, the
dependency paths that connect a chosen deployment root to the components referenced by a vulnerability
(``vulnerability.affects``), walking the BOM own ``dependencies`` graph.

The caller supplies the deployment root and the component scopes considered applicable (by default only
``required`` components). Every reported :class:`~cyclonedx.impact.model.ImpactPath` lists the ordered
components from the root to the affected component, so each conclusion can be reviewed against the BOM.

.. code-block:: python

    from cyclonedx.impact import analyze_impact
    from cyclonedx.model.component import ComponentScope

    report = analyze_impact(
        bom,
        deployment_root=production_image,
        applicable_scope=(ComponentScope.REQUIRED,),
    )
    for impact in report.risks:
        for path in impact.confirmed_paths:
            print(impact.vulnerability_id, " -> ".join(path.bom_refs))

Confirmed and pending conclusions
--------------------------------

A path is ``confirmed`` only when every edge is a present, in-scope dependency edge and the ``affects`` entry
explicitly marks the reached component as affected. The report never hides information that cannot be verified:

* **cycles** -- an edge that revisits a component already on the current path stops the branch and is recorded with
  :attr:`~cyclonedx.impact.enums.ImpactEdgeStatus.CYCLE`.
* **missing references** -- an edge pointing at a ``bom-ref`` that no component declares is recorded with
  :attr:`~cyclonedx.impact.enums.ImpactEdgeStatus.MISSING_REFERENCE`; the subtree behind it cannot be inspected.
* **out of scope** -- an edge leaving the applicable component scope is recorded with
  :attr:`~cyclonedx.impact.enums.ImpactEdgeStatus.OUT_OF_SCOPE` and not traversed.
* **unknown range** -- an ``affects`` target without an explicit affected/unaffected version status yields
  :attr:`~cyclonedx.impact.enums.AffectedStatus.UNKNOWN_RANGE` and reachable paths are marked ``pending`` instead
  of being treated as risks.

All such edges are exposed on :class:`~cyclonedx.impact.model.ImpactReport` (``unresolved_edges`` and
``all_unresolved_edges``) and on the pending paths themselves, so a reviewer can confirm or dismiss them.
Because each deployment root is analyzed independently, fixing one deployment path does not remove the
vulnerability from another root risk list while an independent confirmed path still exists.

API reference
-------------

.. automodule:: cyclonedx.impact.analyzer
   :members:

.. automodule:: cyclonedx.impact.model
   :members:

.. automodule:: cyclonedx.impact.enums
   :members:
