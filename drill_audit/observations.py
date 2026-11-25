#!/usr/bin/env python3
"""本地无害观察：全部使用合成数据，不触网、不访问工作区外资源。

用法：
    .venv/bin/python drill_audit/observations.py
"""
from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from audit import (  # noqa: E402
    CANDIDATES,
    GENERATIONS,
    SOURCE_LOST,
    classify_field,
    load_pipelines,
    load_yaml,
    probe_rule,
    resolve_field,
    ROOT,
)

ALLOWED = load_yaml(ROOT / "config" / "allowed_fields.yml")


def observation_1_rename_keeps_grouping() -> None:
    """观察一：普通改名（gen1 的 client 在 gen2 改名 client_host）不产生真的分组变化。"""
    alerts = [("web-01", "A1"), ("web-02", "A2"), ("web-01", "A3")]

    def canonical_groups(alias: str, gen: str) -> Counter:
        pipelines = load_pipelines()
        resolved = resolve_field(pipelines, alias)[gen]
        assert len(resolved) == 1, f"{alias} 在 {gen} 下应为一一映射"
        canonical = resolved[0]
        return Counter((canonical, value) for value, _ in alerts)

    groups_gen1 = canonical_groups("client", "gen1")
    groups_gen2 = canonical_groups("client_host", "gen2")
    expected = Counter({("host", "web-01"): 2, ("host", "web-02"): 1})
    assert groups_gen1 == expected, f"gen1 别名分组结果异常: {groups_gen1}"
    assert groups_gen2 == expected, f"gen2 别名分组结果异常: {groups_gen2}"
    assert groups_gen1 == groups_gen2, "普通改名前后分组不一致"
    print("PASS 观察一：client/client_host 普通改名后规范分组完全一致（host 维度）")


def observation_2_provenance_tracking() -> None:
    """观察二：pySigma 跟踪可指明字段由哪一代配置的哪个处理项支持。"""
    pipelines = load_pipelines()
    rule = probe_rule("client_host")
    pipelines["gen2"].apply(rule)
    assert pipelines["gen2"].field_mappings["client_host"] == {"host"}
    item = rule.detection.detections["selection"].detection_items[0]
    assert item.was_processed_by("gen2/rename-client-host")
    assert not item.was_processed_by("gen1/rename-client")
    print("PASS 观察二：client_host->host 由处理项 gen2/rename-client-host 支持，可追溯")


def observation_3_unknown_alias_stays_pending() -> None:
    """观察三：无法识别来源的字段不被任何一代配置改写，记录保持待核验。"""
    pipelines = load_pipelines()
    for gen in GENERATIONS:
        rule = probe_rule("workstation_id")
        pipelines[gen].apply(rule)
        item = rule.detection.detections["selection"].detection_items[0]
        assert item.field == "workstation_id", f"{gen} 不应改写未知字段"
        assert "workstation_id" not in pipelines[gen].field_mappings
    resolved = resolve_field(load_pipelines(), "workstation_id")
    result = classify_field("workstation_id", ALLOWED["ops"], resolved)
    assert result["status"] == SOURCE_LOST, "未知字段应判为来源丢失"
    print("PASS 观察三：workstation_id 两代配置均未改写，判为来源丢失并保持待核验")


def observation_4_one_to_many_kept_as_candidates() -> None:
    """观察四：一对多别名展开为候选，不被静默归为单一分组。"""
    pipelines = load_pipelines()
    rule = probe_rule("peer")
    pipelines["gen2"].apply(rule)
    assert pipelines["gen2"].field_mappings["peer"] == {"src_ip", "dst_ip"}
    nested = rule.detection.detections["selection"].detection_items[0]
    expanded = sorted(item.field for item in nested.detection_items)
    assert expanded == ["dst_ip", "src_ip"], f"一对多应展开为两个检测项: {expanded}"
    resolved = resolve_field(load_pipelines(), "peer")
    result = classify_field("peer", ALLOWED["security"], resolved)
    assert result["status"] == CANDIDATES
    assert {cand["allowed_field"] for cand in result["candidates"]} == {"src_ip", "dst_ip"}
    print("PASS 观察四：peer 一对多映射保留 src_ip/dst_ip 两个候选，未静默归并")


def main() -> None:
    observation_1_rename_keeps_grouping()
    observation_2_provenance_tracking()
    observation_3_unknown_alias_stays_pending()
    observation_4_one_to_many_kept_as_candidates()
    print("全部 4 条本地无害观察通过。")


if __name__ == "__main__":
    main()
