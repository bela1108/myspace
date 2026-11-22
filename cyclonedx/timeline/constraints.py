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

# Parse and resolve caller-provided evidence ordering claims.

import json
import os
import re
from hashlib import sha256
from typing import Any, Iterable, Optional

from .model import ConstraintEdge, Evidence, OrderConstraint


class ConstraintError(ValueError):
    pass


_RELATION_ALIASES = {
    'before': 'before',
    'strict_before': 'before',
    'strictly_before': 'before',
    'precedes': 'before',
    'then': 'before',
    'lt': 'before',
    '<': 'before',
    'after': 'after',
    'strict_after': 'after',
    'strictly_after': 'after',
    'follows': 'after',
    'gt': 'after',
    '>': 'after',
    'not_before': 'not_before',
    'on_or_after': 'not_before',
    'gte': 'not_before',
    '>=': 'not_before',
    'not_after': 'not_after',
    'on_or_before': 'not_after',
    'lte': 'not_after',
    '<=': 'not_after',
    'same': 'same',
    'equal': 'same',
    'equals': 'same',
    '==': 'same',
}


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def _digest(value: str) -> str:
    return sha256(value.encode('utf-8')).hexdigest()


def _normalize_relation(value: object) -> str:
    key = str(value or 'before').strip().lower().replace('-', '_').replace(' ', '_')
    if key not in _RELATION_ALIASES:
        raise ConstraintError(f'unsupported ordering relation: {value!r}')
    return _RELATION_ALIASES[key]


_EXPRESSION_RE = re.compile(
    r'^\s*(?P<left>.+?)\s*'
    r'(?P<op><=|>=|==|<|>|->|\bbefore\b|\bafter\b|\bthen\b|\bprecedes\b|\bfollows\b)'
    r'\s*(?P<right>.+?)\s*$',
    re.IGNORECASE,
)


def _parse_expression(text: str) -> dict[str, Any]:
    match = _EXPRESSION_RE.match(text)
    if match is None:
        raise ConstraintError(f'cannot parse ordering claim: {text!r}')
    return {
        'before': match.group('left').strip(),
        'after': match.group('right').strip(),
        'relation': match.group('op').strip().lower(),
    }


def _constraint_from_item(item: object) -> dict[str, Any]:  # noqa: C901
    if isinstance(item, str):
        return _parse_expression(item)
    if isinstance(item, (list, tuple)):
        if len(item) < 2:
            raise ConstraintError(f'ordering claim needs two evidence selectors: {item!r}')
        return {'before': item[0], 'after': item[1]}
    if not isinstance(item, dict):
        raise ConstraintError(f'unsupported ordering claim: {item!r}')

    def pick(*names: str) -> Optional[object]:
        for name in names:
            if name in item and item[name] is not None:
                return item[name]
        return None

    left = pick('before', 'from', 'left', 'a', 'earlier', 'first', 'source')
    right = pick('after', 'to', 'right', 'b', 'later', 'second', 'target')
    if left is None or right is None:
        raise ConstraintError(f'ordering claim needs two evidence selectors: {item!r}')
    result: dict[str, Any] = {
        'before': str(left),
        'after': str(right),
        'relation': _normalize_relation(pick('relation', 'op', 'kind')),
    }
    for key in ('id', 'note', 'description', 'origin', 'source'):
        value = item.get(key)
        if value is not None:
            result[key] = str(value)
    return result


def _parse_payload(payload: object) -> list[object]:  # noqa: C901
    if payload is None:
        return []
    if isinstance(payload, dict):
        for key in ('constraints', 'order', 'claims', 'relations'):
            value = payload.get(key)
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                return [value]
        if any(key in payload for key in ('before', 'after', 'from', 'to', 'left', 'right')):
            return [payload]
        raise ConstraintError(f'constraint document has no constraint list: {payload!r}')
    if isinstance(payload, list):
        return payload
    if isinstance(payload, str):
        text = payload.strip()
        if not text:
            return []
        if text.startswith(('[', '{')):
            try:
                return _parse_payload(json.loads(text))
            except json.JSONDecodeError as error:
                raise ConstraintError(f'invalid constraint JSON: {error}') from error
        items: list[object] = []
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            items.append(_parse_expression(line))
        return items
    raise ConstraintError(f'unsupported constraint payload: {payload!r}')


def load_constraint_payload(value: object) -> tuple[list[object], Optional[str]]:
    if isinstance(value, str) and os.path.isfile(value):
        with open(value, encoding='utf-8-sig') as stream:
            text = stream.read()
        return _parse_payload(text), os.path.basename(value)
    return _parse_payload(value), None


def parse_constraints(value: object, *, source: Optional[str] = None) -> list[OrderConstraint]:
    payload, payload_source = load_constraint_payload(value)
    source = source or payload_source
    constraints: list[OrderConstraint] = []
    used: set[str] = set()
    semantic_seen: set[str] = set()
    for raw in payload:
        item = _constraint_from_item(raw)
        relation = _normalize_relation(item.get('relation', 'before'))
        left = str(item['before'])
        right = str(item['after'])
        normalized_relation = relation
        if relation == 'after':
            left, right = right, left
            normalized_relation = 'before'
        elif relation == 'not_before':
            left, right = right, left
            normalized_relation = 'non_strict_before'
        elif relation == 'not_after':
            normalized_relation = 'non_strict_before'
        elif relation == 'same':
            normalized_relation = 'equal'
        else:
            normalized_relation = 'strict_before'

        fingerprint = _canonical({
            'before': left,
            'after': right,
            'relation': normalized_relation,
            'origin': item.get('origin', 'caller'),
            'note': item.get('note'),
        })
        if fingerprint in semantic_seen:
            continue
        semantic_seen.add(fingerprint)
        provided_id = str(item.get('id', '')).strip()
        if provided_id:
            identifier = provided_id
        else:
            identifier = 'caller:' + _digest(fingerprint)[:16]
        if identifier in used:
            identifier = f'{identifier}~{_digest(_canonical(item))[:8]}'
        while identifier in used:
            identifier = identifier + '-x'
        used.add(identifier)
        constraints.append(OrderConstraint(
            id=identifier,
            before_selector=left,
            after_selector=right,
            relation=normalized_relation,
            origin=str(item.get('origin', 'caller')),
            note=item.get('note'),
            source=source,
        ))
    return sorted(constraints, key=lambda item: item.id)


def _norm(value: object) -> str:
    return str(value or '').strip().lower()


def _matches(evidence: Evidence, selector: str) -> bool:
    needle = _norm(selector)
    fields = (
        evidence.id, evidence.phase, evidence.lifecycle_name, evidence.property_name,
        evidence.component_ref, evidence.component_name, evidence.component_version,
        evidence.purl, evidence.occurrence_ref, evidence.location, evidence.label,
        evidence.bom_id, evidence.source,
    )
    for field in fields:
        if field is not None and _norm(field) == needle:
            return True
    if evidence.component_name and evidence.component_version:
        if _norm(f'{evidence.component_name}@{evidence.component_version}') == needle:
            return True
    if evidence.kind == 'manifest':
        serial = evidence.details.get('serialNumber')
        if serial is not None and _norm(serial) == needle:
            return True
        if any(needle == _norm(label) for label in evidence.details.get('lifecycleLabels', [])):
            return True
    return False


def _contains(evidence: Evidence, selector: str) -> bool:
    needle = _norm(selector)
    fields = (
        evidence.id, evidence.label, evidence.location, evidence.property_name,
        evidence.component_ref, evidence.component_name, evidence.purl,
        evidence.bom_id, evidence.source,
    )
    if any(field is not None and needle in _norm(field) for field in fields):
        return True
    if evidence.kind == 'manifest':
        serial = evidence.details.get('serialNumber')
        if serial is not None and needle in _norm(serial):
            return True
        if any(needle in _norm(label) for label in evidence.details.get('lifecycleLabels', [])):
            return True
    return False


def _manifest_ids(evidence: list[Evidence]) -> list[Evidence]:
    return [item for item in evidence if item.kind == 'manifest']


def resolve_selector(selector: object, evidence: list[Evidence]) -> list[str]:  # noqa: C901
    text = str(selector).strip()
    if not text:
        return []
    if text in ('*', 'all', 'ANY'):
        return sorted(item.id for item in evidence)
    by_id = {item.id: item for item in evidence}
    if text in by_id:
        return [text]
    if text.startswith('evidence:'):
        candidate = text.split(':', 1)[1]
        if candidate in by_id:
            return [candidate]
        matches = [item.id for item in evidence if _norm(item.id) == _norm(candidate)]
        return sorted(matches)

    kind, sep, value = text.partition(':')
    kind = kind.strip().lower()
    value = value.strip()
    manifests = _manifest_ids(evidence)

    if sep and kind in ('phase', 'lifecycle', 'stage'):
        lifecycle_matches = [
            item.id for item in evidence
            if item.kind == 'lifecycle'
            and value.lower() in (_norm(item.phase), _norm(item.lifecycle_name))
        ]
        if kind == 'lifecycle' and lifecycle_matches:
            return sorted(lifecycle_matches)
        matches = [
            item.id for item in manifests
            if value.lower() in [str(label).lower() for label in item.details.get('lifecycleLabels', [])]
        ]
        if not matches:
            matches = lifecycle_matches
        return sorted(matches)

    if sep and kind in ('bom', 'manifest', 'serial'):
        matches = [
            item.id for item in manifests
            if value.lower() in _norm(item.bom_id)
            or value.lower() in _norm(item.details.get('serialNumber'))
            or value.lower() == _norm(item.source)
        ]
        return sorted(matches)

    if sep and kind in ('file', 'source'):
        matches = []
        for item in manifests:
            source = item.source
            stem = os.path.splitext(source)[0]
            if value == source or value == stem:
                matches.append(item.id)
        return sorted(matches)

    if sep and kind in ('component', 'comp'):
        matches = [
            item.id for item in evidence
            if item.kind == 'component'
            and (
                _norm(value) in (_norm(item.component_ref), _norm(item.purl), _norm(item.component_name))
                or _norm(value) == _norm(item.label)
                or _norm(value) in _norm(item.id)
            )
        ]
        return sorted(matches)

    if sep and kind in ('occurrence', 'occ'):
        matches = [
            item.id for item in evidence
            if item.kind == 'occurrence'
            and (
                _norm(value) in (_norm(item.location), _norm(item.occurrence_ref), _norm(item.label))
                or _norm(value) in _norm(item.id)
            )
        ]
        return sorted(matches)

    if sep and kind in ('property', 'prop'):
        matches = [
            item.id for item in evidence
            if item.kind == 'property'
            and (_norm(value) == _norm(item.property_name) or _norm(value) in _norm(item.property_name))
        ]
        return sorted(matches)

    exact = [item.id for item in evidence if _matches(item, text)]
    if exact:
        phase_exact = [
            item.id for item in manifests
            if text.lower() in [str(label).lower() for label in item.details.get('lifecycleLabels', [])]
        ]
        if phase_exact:
            return sorted(phase_exact)
        return sorted(exact)

    contained = [item.id for item in evidence if _contains(item, text)]
    return sorted(contained)


def resolve_constraints(
    constraints: Iterable[OrderConstraint],
    evidence: list[Evidence],
) -> tuple[list[OrderConstraint], list[dict[str, Any]]]:
    errors: list[dict[str, Any]] = []
    resolved: list[OrderConstraint] = []
    exact_ids = {item.id for item in evidence}
    for constraint in constraints:
        before_ids = resolve_selector(constraint.before_selector, evidence)
        after_ids = resolve_selector(constraint.after_selector, evidence)
        for selector, matches in ((constraint.before_selector, before_ids), (constraint.after_selector, after_ids)):
            if not matches:
                errors.append({
                    'type': 'unresolved-selector',
                    'constraintId': constraint.id,
                    'selector': selector,
                    'message': f'no evidence matches selector {selector!r}',
                })
        edges: list[ConstraintEdge] = []
        if before_ids and after_ids:
            for before in before_ids:
                for after in after_ids:
                    if before == after:
                        if constraint.relation != 'strict_before':
                            continue
                        if not (constraint.before_selector == constraint.after_selector
                                and constraint.before_selector in exact_ids):
                            continue
                    edge_id = constraint.id + ':' + _digest(_canonical([before, after, constraint.relation]))[:10]
                    edges.append(ConstraintEdge(
                        id=edge_id,
                        constraint_id=constraint.id,
                        before=before,
                        after=after,
                        kind=constraint.relation,
                    ))
        constraint.edges = sorted(edges, key=lambda item: item.id)
        resolved.append(constraint)
    return sorted(resolved, key=lambda item: item.id), errors
