#!/usr/bin/env python3

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

"""离线证据复核入口（offline evidence review）。

取回两份交付清单（CycloneDX BOM，JSON 格式），对同一份材料输出三个判断：

1. 字节同一性（byte identity）：摘要是否一致；
2. 历史角色（historical role）：该清单在交付中的角色（正式构建 / 仅测试等）；
3. 声明的环境范围（declared environment scope）：清单声明的适用环境。

当两份声明来自不同采集方时，同时输出原材料出处与最早可确认的时点，保证可追溯。
全程离线，仅读取本地文件。

用法::

    python tools/evidence_review.py review  bom-a.json bom-b.json
    python tools/evidence_review.py query   bom-a.json bom-b.json --component libalpha
"""

import argparse
import sys
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from json import loads as json_loads
from pathlib import Path
from typing import Optional, Sequence

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component
from cyclonedx.model.lifecycle import LifecyclePhase, PredefinedLifecycle

ROLE_PROPERTY_NAMES = ('cdx:evidence:role', 'evidence:role', 'role')
ENVIRONMENT_PROPERTY_NAMES = ('cdx:evidence:environment', 'evidence:environment', 'environment', 'scope')

UNDECLARED = '未声明'
NO_RECORD = '无记录'
UNKNOWN_COLLECTOR = '未知采集方'


class ByteIdentity(str, Enum):
    """字节同一性判断结果。"""

    IDENTICAL = 'identical'
    DIFFERENT = 'different'
    UNKNOWN = 'unknown'


class MaterialRole(str, Enum):
    """清单在交付中的历史角色。"""

    PRODUCTION = 'production'
    TEST = 'test'
    BUILD = 'build'
    UNKNOWN = 'unknown'


_PHASE_ROLES = {
    LifecyclePhase.OPERATIONS: MaterialRole.PRODUCTION,
    LifecyclePhase.BUILD: MaterialRole.BUILD,
    LifecyclePhase.PRE_BUILD: MaterialRole.BUILD,
    LifecyclePhase.POST_BUILD: MaterialRole.BUILD,
}

_ROLE_VALUES = {role.value: role for role in MaterialRole}


@dataclass
class SideEvidence:
    """一份清单（一侧）就某份材料提供的证据。"""

    label: str
    collectors: list[str]
    timestamp: Optional[datetime]
    role: MaterialRole
    environment: str
    sources: list[str]
    hashes: dict[str, str]


@dataclass
class MaterialReview:
    """同一份材料在两份清单中的复核结果。"""

    key: str
    left: SideEvidence
    right: SideEvidence
    byte_identity: ByteIdentity
    compared_algorithms: list[str]


def load_bom(path: Path) -> Bom:
    """离线读取一份 CycloneDX JSON 清单。"""
    bom = Bom.from_json(  # type: ignore[attr-defined]
        json_loads(path.read_text(encoding='utf-8')))
    if not isinstance(bom, Bom):
        raise ValueError(f'{path}: 不是有效的 CycloneDX BOM')
    return bom


def component_key(component: Component) -> str:
    """材料的匹配键：优先 purl，其次 name@version。"""
    if component.purl is not None:
        return component.purl.to_string()
    version = component.version or ''
    return f'{component.name}@{version}' if version else str(component.name)


def _property_value(component: Component, bom: Bom, names: Sequence[str]) -> Optional[str]:
    for source in (component.properties, bom.metadata.properties, bom.properties):
        for prop in source:
            if prop.name in names and prop.value:
                return prop.value
    return None


def _role_from_lifecycles(bom: Bom) -> MaterialRole:
    for lifecycle in bom.metadata.lifecycles:
        if isinstance(lifecycle, PredefinedLifecycle):
            role = _PHASE_ROLES.get(lifecycle.phase)
            if role is not None:
                return role
    return MaterialRole.UNKNOWN


def _role_of(component: Component, bom: Bom) -> MaterialRole:
    declared = _property_value(component, bom, ROLE_PROPERTY_NAMES)
    if declared is not None:
        return _ROLE_VALUES.get(declared.strip().lower(), MaterialRole.UNKNOWN)
    return _role_from_lifecycles(bom)


def _collectors_of(bom: Bom) -> list[str]:
    collectors = []
    repository = bom.metadata.tools
    for tool in repository.tools:
        collectors.append(' '.join(part for part in (tool.vendor, tool.name, tool.version) if part))
    for component in repository.components:
        vendor = component.supplier.name if component.supplier else None
        collectors.append(' '.join(part for part in (vendor, component.name, component.version) if part))
    for service in repository.services:
        provider = service.provider.name if service.provider else None
        collectors.append(' '.join(part for part in (provider, service.name, service.version) if part))
    return [collector if collector else UNKNOWN_COLLECTOR for collector in collectors]


def _sources_of(component: Component) -> list[str]:
    sources = []
    if component.pedigree is not None:
        sources.append('谱系记录(pedigree)')
    for reference in component.external_references:
        sources.append(f'{reference.type.value}: {reference.url}')
    return sources


def collect_side(bom: Bom, component: Component, label: str) -> SideEvidence:
    """从一份清单中采集某材料的单侧证据。"""
    return SideEvidence(
        label=label,
        collectors=_collectors_of(bom),
        timestamp=bom.metadata.timestamp,
        role=_role_of(component, bom),
        environment=_property_value(component, bom, ENVIRONMENT_PROPERTY_NAMES) or UNDECLARED,
        sources=_sources_of(component),
        hashes={hash_.alg.value: hash_.content for hash_ in component.hashes},
    )


def compare_hashes(left: dict[str, str], right: dict[str, str]) -> tuple[ByteIdentity, list[str]]:
    """比对两侧摘要：共同算法全部一致为同一，任一不一致为不同，无共同算法则无法确认。"""
    common = sorted(set(left) & set(right))
    if not common:
        return ByteIdentity.UNKNOWN, []
    if all(left[alg] == right[alg] for alg in common):
        return ByteIdentity.IDENTICAL, common
    return ByteIdentity.DIFFERENT, common


def review_boms(path_a: Path, path_b: Path) -> list[MaterialReview]:
    """复核两份清单，返回共同材料的复核结果（按匹配键排序）。"""
    bom_a, bom_b = load_bom(path_a), load_bom(path_b)
    components_a = {component_key(c): c for c in bom_a.components}
    components_b = {component_key(c): c for c in bom_b.components}
    reviews = []
    for key in sorted(set(components_a) & set(components_b)):
        left = collect_side(bom_a, components_a[key], path_a.name)
        right = collect_side(bom_b, components_b[key], path_b.name)
        identity, algorithms = compare_hashes(left.hashes, right.hashes)
        reviews.append(MaterialReview(key=key, left=left, right=right,
                                      byte_identity=identity, compared_algorithms=algorithms))
    return reviews


def production_provenance_provable(review: MaterialReview) -> bool:
    """生产出处是否可证明：存在生产角色一侧，且出处、采集方、时点均可追溯。"""
    for side in (review.left, review.right):
        if side.role is MaterialRole.PRODUCTION \
                and side.sources and side.collectors and side.timestamp is not None:
            return True
    return False


def verdict_sentence(review: MaterialReview) -> str:
    """把复核结论说成一句话。"""
    if review.byte_identity is ByteIdentity.DIFFERENT:
        return '这份材料内容不一致，同一性不成立。'
    if review.byte_identity is ByteIdentity.UNKNOWN:
        return '这份材料缺少可比对的摘要，内容同一性无法确认。'
    if production_provenance_provable(review):
        side = next(s for s in (review.left, review.right) if s.role is MaterialRole.PRODUCTION)
        return f'这份材料可以确认内容相同，生产出处可追溯至 {side.sources[0]}。'
    return '这份材料可以确认内容相同，生产出处目前无从证明。'


def _fmt_list(values: Sequence[str], empty: str) -> str:
    return '；'.join(values) if values else empty


def _fmt_side(side: SideEvidence) -> str:
    timestamp = side.timestamp.isoformat() if side.timestamp else NO_RECORD
    return (f'{side.label}（采集方: {_fmt_list(side.collectors, UNKNOWN_COLLECTOR)}，'
            f'可确认时点: {timestamp}）')


def render_review(review: MaterialReview) -> str:
    """渲染一份材料的三个判断与可追溯信息。"""
    left, right = review.left, review.right
    identity_text = {
        ByteIdentity.IDENTICAL: f'相同（{"、".join(review.compared_algorithms)} 摘要一致）',
        ByteIdentity.DIFFERENT: f'不同（{"、".join(review.compared_algorithms)} 摘要不一致）',
        ByteIdentity.UNKNOWN: '无法确认（没有可共同比对的摘要算法）',
    }[review.byte_identity]
    lines = [
        f'材料: {review.key}',
        f'  判断一 · 字节同一性: {identity_text}',
        f'  判断二 · 历史角色: {left.label}={left.role.value}；{right.label}={right.role.value}',
        f'  判断三 · 声明的环境范围: {left.label}={left.environment}；{right.label}={right.environment}',
    ]
    if left.collectors != right.collectors:
        lines.append(f'  声明来自不同采集方: {_fmt_side(left)} vs {_fmt_side(right)}')
    lines.append(f'  原材料出处: {left.label}={_fmt_list(left.sources, NO_RECORD)}；'
                 f'{right.label}={_fmt_list(right.sources, NO_RECORD)}')
    timestamps = [s.timestamp for s in (left, right) if s.timestamp is not None]
    earliest = min(timestamps).isoformat() if timestamps else NO_RECORD
    lines.append(f'  最早可确认的时点: {earliest}')
    lines.append(f'  结论: {verdict_sentence(review)}')
    return '\n'.join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description='CycloneDX 离线证据复核入口')
    subparsers = parser.add_subparsers(dest='command', required=True)
    for command, help_text in (('review', '复核两份清单中的全部共同材料'),
                               ('query', '查询某一份材料的复核结论')):
        sub = subparsers.add_parser(command, help=help_text)
        sub.add_argument('bom_a', type=Path, help='第一份清单（如正式构建）')
        sub.add_argument('bom_b', type=Path, help='第二份清单（如测试）')
        if command == 'query':
            sub.add_argument('--component', required=True, help='材料名或 purl 片段')
    args = parser.parse_args(argv)

    reviews = review_boms(args.bom_a, args.bom_b)
    if args.command == 'query':
        matched = [r for r in reviews if args.component in r.key]
        if not matched:
            print(f'未在两份清单中找到共同材料: {args.component}', file=sys.stderr)
            return 1
        reviews = matched
    if not reviews:
        print('两份清单没有共同材料。')
        return 0
    print('\n\n'.join(render_review(review) for review in reviews))
    return 0


if __name__ == '__main__':
    sys.exit(main())
