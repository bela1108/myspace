"""Audits testimony dependencies in the local STIX casefile, before and
after the observation-date correction.

Rules
-----
* Every citation is bound to a concrete object version (id + ``modified``).
  A citation resolves only if that exact version exists in the local data
  source, is not revoked, and has not been superseded by a newer version.
* A testimony's independent support is the number of *distinct* evidence
  leaves (``observed-data``) reachable through resolvable citations.
  Sources that only cite each other contribute no evidence leaf, so mutual
  references cannot manufacture the required independent sources.
* The correction adds v2 of ``observed-data`` E_A; citations pinned to v1
  then dangle, so each downstream testimony loses exactly the paths that
  went through E_A@v1.

Usage:  python audit.py   (writes audit_report.md)
"""

import json
from datetime import datetime, timezone

from stix2 import MemoryStore, parse

from testimony import Testimony  # noqa: F401  (registers x-testimony)

CASEFILE = "casefile.json"
CORRECTION = "correction.json"
REPORT = "audit_report.md"


def load_store(*paths):
    store = MemoryStore()
    for path in paths:
        with open(path, encoding="utf-8") as f:
            store.add(parse(f.read(), allow_custom=True))
    return store


def parse_ts(value):
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc)
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
        timezone.utc)


class Audit:
    def __init__(self, store):
        self.store = store
        self.nodes = {}
        for obj in store.query():
            self.nodes[obj["id"]] = obj

    def citation_status(self, citation):
        """Resolve one version-pinned citation -> (object_or_None, reason)."""
        ref = citation["source_ref"]
        version = parse_ts(citation["version"])
        versions = self.store.source.all_versions(ref)
        if not versions:
            return None, "target missing"
        pinned = next((v for v in versions if v["modified"] == version), None)
        if pinned is None:
            return None, f"pinned version {version.isoformat()} missing"
        if pinned.get("revoked"):
            return None, "pinned version revoked"
        latest = max(v["modified"] for v in versions)
        if pinned["modified"] != latest:
            return None, f"superseded by correction (latest {latest.isoformat()})"
        return pinned, "ok"

    def evaluate(self, root_id):
        """DFS to evidence leaves.  Returns (leaves, traces, broken)."""
        leaves, traces, broken = set(), [], []

        def walk(node_id, path, visited):
            obj = self.nodes.get(node_id)
            if obj is None:
                return
            if obj["type"] == "observed-data":
                leaves.add(node_id)
                traces.append(path + [node_id])
                return
            if node_id in visited:          # mutual citation cycle: stop
                return
            visited = visited | {node_id}
            for cit in obj.get("citations", []):
                target, reason = self.citation_status(cit)
                if target is None:
                    broken.append((path + [node_id], cit["source_ref"], reason))
                    continue
                walk(target["id"], path + [node_id], visited)

        walk(root_id, [], set())
        return leaves, traces, broken


def short(oid):
    kind, _, rest = oid.partition("--")
    return f"{kind}--{rest[:8]}"


NAMES = {}        # id -> display label (证词甲 / E_A ...)
NAME_TO_ID = {}   # T1/T2/T3/E_x -> id


def label(oid):
    return NAMES.get(oid, short(oid))


def run_phase(store, title, lines):
    audit = Audit(store)
    lines.append(f"## {title}\n")
    results = {}
    for root in ("T1", "T2", "T3"):
        rid = NAME_TO_ID[root]
        obj = audit.nodes[rid]
        req = obj["required_independent_sources"]
        leaves, traces, broken = audit.evaluate(rid)
        ok = len(leaves) >= req
        results[root] = (ok, leaves, traces, broken, req)
        lines.append(
            f"### {root} {obj['statement']}\n"
            f"- 声明的独立来源条件: 需要 {req} 个独立证物来源\n"
            f"- 实际可追到的独立证物: {len(leaves)} 个 "
            f"({', '.join(sorted(label(x) for x in leaves)) or '无'})\n"
            f"- 结论: **{'成立' if ok else '不成立'}**\n"
        )
        lines.append("- 依赖链 (证词 → 证物节点):")
        for trace in traces:
            lines.append("  - " + " → ".join(label(x) for x in trace))
        for path, ref, reason in broken:
            lines.append(
                f"  - {' → '.join(label(x) for x in path)} ✗ {label(ref)}"
                f"  [断链: {reason}]")
        lines.append("")
    return results


def main():
    global NAMES, NAME_TO_ID
    with open(CASEFILE, encoding="utf-8") as f:
        objects = json.load(f)["objects"]
    alias = {}
    for obj in objects:
        if obj["type"] == "observed-data":
            tag = obj["objects"]["0"]["name"].split()[0]   # exhibit-X.evt
            alias[obj["id"]] = "E_" + tag.split("-")[1].split(".")[0]
        elif obj["type"] == "x-testimony":
            alias[obj["id"]] = obj["statement"].split(":")[0]
    NAMES = alias
    for oid_, name in alias.items():
        key = name.replace("证词甲", "T1").replace("证词乙", "T2") \
                  .replace("证词丙", "T3")
        NAME_TO_ID.setdefault(key, oid_)
    for wanted in ("T1", "T2", "T3"):
        assert wanted in NAME_TO_ID, wanted

    lines = ["# 证词依赖核对报告\n",
             "本地数据源: STIX MemoryStore, 引用绑定到具体观察版本 "
             "(id + modified)。\n"]

    before = run_phase(load_store(CASEFILE), "更正前依赖图", lines)

    lines.append("---\n")
    lines.append("更正操作: E_A 发布 v2 (first_observed 2026-01-05 → "
                 "2026-02-04), 绑定 v1 的引用随之断链。\n")
    after = run_phase(load_store(CASEFILE, CORRECTION), "更正后依赖图", lines)

    lines.append("---\n## 复核结论\n")
    verdicts = {
        (True, True): "仍有独立支撑",
        (True, False): "该重审 (更正后独立来源不足)",
        (False, False): "仍差材料",
        (False, True): "更正后反而成立 (需人工确认)",
    }
    for root in ("T1", "T2", "T3"):
        b_ok, b_leaves = before[root][0], before[root][1]
        a_ok, a_leaves = after[root][0], after[root][1]
        req = after[root][4]
        lines.append(
            f"- **{root}**: {verdicts[(b_ok, a_ok)]} "
            f"(更正前 {len(b_leaves)}/{req}, 更正后 {len(a_leaves)}/{req}; "
            f"证物节点: "
            f"{', '.join(sorted(label(x) for x in a_leaves)) or '无'})"
        )

    report = "\n".join(lines) + "\n"
    with open(REPORT, "w", encoding="utf-8") as f:
        f.write(report)
    print(report)


if __name__ == "__main__":
    main()
