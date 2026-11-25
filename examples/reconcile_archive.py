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

"""Audit a two-layer archive fixture, then re-audit after an exclusion change."""

from pathlib import Path

from cyclonedx.reconcile import Reconciler, diff_audits, render_audit, render_diff
from cyclonedx.reconcile.loaders import (
    declarations_from_bom_file,
    decisions_from_file,
    manifest_from_file,
)

FIXTURE = Path(__file__).parent.parent / 'tests' / '_data' / 'reconcile' / 'two_layer'


def main() -> None:
    manifest = manifest_from_file(str(FIXTURE / 'manifest.json'))
    declarations = declarations_from_bom_file(str(FIXTURE / 'sbom.cdx.json'))
    reconciler = Reconciler(manifest, declarations)

    baseline = reconciler.audit(decisions_from_file(str(FIXTURE / 'decisions-v1.json')))
    revised = reconciler.audit(decisions_from_file(str(FIXTURE / 'decisions-v2.json')))

    print('=== baseline decision set ===')
    print(render_audit(baseline), end='')
    print()
    print('=== re-audit after exclusion scope change ===')
    print(render_diff(diff_audits(baseline, revised)), end='')
    print()
    print(render_audit(revised), end='')


if __name__ == '__main__':
    main()
