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

"""End-to-end JSON round-trip demo for the key module recall scenario.

Run with the repository virtual environment::

    .venv/bin/python -m examples.key_module_recall.demo

The demo writes three artifacts into ``examples/key_module_recall/out``:

* ``sbom.json`` - the CycloneDX 1.7 BOM built from the asset inventory;
* ``roundtrip_sbom.json`` - the BOM re-serialized after JSON deserialization,
  proving type, lifecycle and seal properties survive the round trip;
* "reconciliation_report.json" - the recall coverage report.
"""

from __future__ import annotations

import json
from json import loads as json_loads
from pathlib import Path
from typing import Any, Dict

from cyclonedx.model.bom import Bom
from cyclonedx.output.json import JsonV1Dot7
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

from .asset_inventory import build_sbom, load_asset_inventory
from .reconcile import load_disposition_list, reconcile
from .replacement_policy import load_replacement_policy

DATA_DIR = Path(__file__).parent / 'data'
OUT_DIR = Path(__file__).parent / 'out'


def run() -> Dict[str, Any]:
    """Execute the full build -> serialize -> deserialize -> reconcile flow."""
    entries = load_asset_inventory(DATA_DIR / 'asset_inventory.json')
    replacement_rules = load_replacement_policy(DATA_DIR / 'replacement_policy.json')
    dispositions = load_disposition_list(DATA_DIR / 'disposition_list.json')

    bom = build_sbom(entries)
    outputter = JsonV1Dot7(bom)
    serialized = outputter.output_as_string(indent=2)

    validator = JsonStrictValidator(SchemaVersion.V1_7)
    validation_error = validator.validate_str(serialized)
    if validation_error is not None:
        raise RuntimeError(f'generated BOM failed schema validation: {validation_error!r}')

    # JSON round trip: parse the serialized document back into a Bom object,
    # then render it again. Reconciliation runs against the reparsed BOM.
    roundtripped_bom = Bom.from_json(json_loads(serialized))  # type: ignore[attr-defined]
    roundtripped = JsonV1Dot7(roundtripped_bom).output_as_string(indent=2)
    if json_loads(roundtripped) != json_loads(serialized):
        raise RuntimeError('JSON round trip changed the BOM content')

    report = reconcile(roundtripped_bom, replacement_rules, dispositions)
    report_json = report.to_json()

    OUT_DIR.mkdir(exist_ok=True)
    (OUT_DIR / 'sbom.json').write_text(serialized + '\n', encoding='utf-8')
    (OUT_DIR / 'roundtrip_sbom.json').write_text(roundtripped + '\n', encoding='utf-8')
    (OUT_DIR / 'reconciliation_report.json').write_text(
        json.dumps(report_json, indent=2, ensure_ascii=False) + '\n', encoding='utf-8'
    )
    return report_json


def _print_summary(report: Dict[str, Any]) -> None:
    print('Recall reconciliation summary')
    print('  complete           :', report['complete'])
    print('  pending devices    :', ', '.join(report['pendingDeviceRefs']) or '-')
    print('  covered devices    :', ', '.join(report['coveredDeviceRefs']) or '-')
    print('  seal-only objects  :', ', '.join(report['sealOnlyRefs']) or '-')
    print()
    for item in report['items']:  # type: ignore[assignment]
        print(f"  {item['bomRef']:<22} {item['lifecycle']:<9} -> {item['status']}")
        for note in item['notes']:
            print(f"      note: {note}")


def main() -> None:
    report = run()
    _print_summary(report)
    print()
    print(f'artifacts written to {OUT_DIR}')


if __name__ == '__main__':
    main()
