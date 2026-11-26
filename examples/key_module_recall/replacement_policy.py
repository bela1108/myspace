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

"""Independent replacement restriction list.

This list is intentionally separate from both the asset inventory and the
disposition list. It only states which spare bom-ref may replace which
installed bom-ref. It contains no component type, no lifecycle and no recall
information, and the reconciliation never infers replacement eligibility
from anything else.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Mapping, Set


@dataclass(frozen=True)
class ReplacementRule:
    """Declaration that ``spare_ref`` is an allowed replacement for ``installed_ref``."""

    installed_ref: str
    spare_ref: str
    note: str = ''

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> 'ReplacementRule':
        return cls(
            installed_ref=data['installedRef'],
            spare_ref=data['spareRef'],
            note=data.get('note', ''),
        )


def load_replacement_policy(path: Path) -> List[ReplacementRule]:
    """Load the standalone replacement restriction JSON document."""
    document = json.loads(path.read_text(encoding='utf-8'))
    rules = [ReplacementRule.from_json(item) for item in document['replacementRules']]
    _validate_policy(rules)
    return rules


def _validate_policy(rules: List[ReplacementRule]) -> None:
    pairs = [(rule.installed_ref, rule.spare_ref) for rule in rules]
    if len(pairs) != len(set(pairs)):
        raise ValueError('replacement policy contains duplicate (installedRef, spareRef) pairs')


def build_replacement_index(rules: List[ReplacementRule]) -> Mapping[str, Set[str]]:
    """Map each installed bom-ref to the set of bom-refs allowed to replace it."""
    index: Dict[str, Set[str]] = {}
    for rule in rules:
        index.setdefault(rule.installed_ref, set()).add(rule.spare_ref)
    return index


def build_reverse_replacement_index(rules: List[ReplacementRule]) -> Mapping[str, Set[str]]:
    """Map each spare bom-ref to the installed bom-refs it is allowed to replace."""
    index: Dict[str, Set[str]] = {}
    for rule in rules:
        index.setdefault(rule.spare_ref, set()).add(rule.installed_ref)
    return index
