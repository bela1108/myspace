# This file is part of CycloneDX Python Library
#
# Licensed under the Apache License, Version 2.0 (the "License");
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
# Copyright (c) OWASP Foundation. All Rights Reserved.

"""Offline risk-acceptance sign-off walkthrough.

Three groups (procurement, platform, product) signed off on a component,
but every sign-off merely references another one. The script demonstrates
the three acceptance stages without any network access:

1. a three-node reference cycle with no independent material - every
   sign-off is held back as circular/pending;
2. one independently reviewable, artifact-scoped piece of material is
   attached - all three sign-offs become independently supported;
3. the material is revoked - the same three decisions flip back to
   circular/pending.

A final stage replaces the component with a new bom-ref while keeping the
declared group/name/version, showing that evidence scope is re-checked
against the declared artifact rather than the bom-ref.
"""

from cyclonedx.model import ExternalReference, ExternalReferenceType
from cyclonedx.model.bom import Bom
from cyclonedx.riskacceptance import (
    ArtifactCoordinates,
    SignOffStatus,
    evaluate_bom,
    make_evidence_reference,
    make_signoff_component,
)

ARTIFACT = ArtifactCoordinates(
    group="com.example", name="acme-lib", version="1.2.3",
    bom_ref="acme-lib-1.2.3",
)
EVIDENCE_URL = "urn:evidence:independent-audit-77"


def _build_bom(artifact: ArtifactCoordinates, with_material: bool) -> Bom:
    evidence = [
        make_evidence_reference(EVIDENCE_URL, artifact)
    ] if with_material else []
    procurement = make_signoff_component(
        artifact, signoff_id="RA-PROCUREMENT", owner="procurement",
        references=("RA-PLATFORM",), evidence=evidence)
    platform = make_signoff_component(
        artifact, signoff_id="RA-PLATFORM", owner="platform",
        references=("RA-PRODUCT",))
    product = make_signoff_component(
        artifact, signoff_id="RA-PRODUCT", owner="product",
        references=("RA-PROCUREMENT",))
    return Bom(components=[procurement, platform, product])


def _print_stage(title: str, bom: Bom) -> None:
    print(title)
    print("-" * len(title))
    for verdict in sorted(evaluate_bom(bom), key=lambda item: item.signoff_id):
        chain = " -> ".join(verdict.chain)
        print(f"  {verdict.signoff_id:<15} {verdict.status.value:<24} {chain}")
    print()

def main() -> None:
    stage_one = _build_bom(ARTIFACT, with_material=False)
    _print_stage("Stage 1 - three-node cycle, no independent material", stage_one)

    stage_two = _build_bom(ARTIFACT, with_material=True)
    before = {item.signoff_id: item.status
              for item in evaluate_bom(stage_two)}
    _print_stage("Stage 2 - independently scoped material attached", stage_two)

    procurement = next(
        component for component in stage_two.components
        if any(prop.name == "risk:signoff:id"
               and prop.value == "RA-PROCUREMENT"
               for prop in component.properties)
    )
    procurement.external_references = [ExternalReference(
        type=ExternalReferenceType.EVIDENCE,
        url="urn:evidence:unscoped-note",
    )]
    after = {item.signoff_id: item for item in evaluate_bom(stage_two)}
    changed = sorted(
        signoff_id for signoff_id, status in before.items()
        if after[signoff_id].status != status
    )
    _print_stage("Stage 3 - material revoked (unscoped note only)", stage_two)
    print(f"Decisions changed by the revocation: {changed}")
    print()

    replaced = ArtifactCoordinates(
        group=ARTIFACT.group, name=ARTIFACT.name, version=ARTIFACT.version,
        bom_ref="replacement-bom-ref-9",
    )
    stage_four = _build_bom(replaced, with_material=True)
    _print_stage("Stage 4 - component replaced, bom-ref changed", stage_four)
    for verdict in evaluate_bom(stage_four):
        assert verdict.status is SignOffStatus.INDEPENDENTLY_SUPPORTED
    print("Evidence scope was re-checked against the declared artifact;")
    print("the new bom-ref does not invalidate the independent material.")


if __name__ == "__main__":
    main()
