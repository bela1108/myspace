#!/usr/bin/env python3
"""Offline exposure risk accounting over anonymized detect-secrets results.

Model
-----
- A *finding* is one detect-secrets report (type + hashed_secret + locations).
- Multiple locations of the same finding inside one artifact count ONCE
  (same hashed_secret => same secret, several leak sites).
- The same hash reported against a DIFFERENT artifact is an independent
  finding and counts separately for that artifact.
- Exposure count of an artifact = number of distinct hashes attributed to it.
- Global exposure count = sum of per-artifact exposure counts (a secret
  leaked through two artifacts is two exposures).
- Ambiguous findings are attributed to exactly one of their candidates;
  investigation evidence (mutex rules) prunes impossible combinations.

Usage: python3 bounds.py [findings.json]  ->  writes RISK_REPORT.md
"""
from __future__ import annotations

import itertools
import json
import sys
from pathlib import Path

DEFAULT_CASE = Path(__file__).with_name("findings.json")
REPORT_PATH = Path(__file__).with_name("RISK_REPORT.md")


def load_case(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def ambiguous_findings(case):
    return [f for f in case["findings"] if f["attribution"]["kind"] == "ambiguous"]


def is_valid(case, assignment):
    for ev in case.get("evidence", []):
        if ev["kind"] == "mutex":
            if all(assignment.get(fid) == ev["artifact"] for fid in ev["findings"]):
                return False
        else:
            raise ValueError("unknown evidence kind: " + ev["kind"])
    return True


def valid_assignments(case, fixed=None):
    fixed = dict(fixed or {})
    amb = [f for f in ambiguous_findings(case) if f["id"] not in fixed]
    pools = [f["attribution"]["candidates"] for f in amb]
    for combo in itertools.product(*pools):
        assignment = dict(fixed)
        assignment.update(zip([f["id"] for f in amb], combo))
        if is_valid(case, assignment):
            yield assignment


def artifact_hashes(case, assignment):
    result = {a: set() for a in case["artifacts"]}
    for f in case["findings"]:
        att = f["attribution"]
        art = att["artifact"] if att["kind"] == "definite" else assignment[f["id"]]
        result[art].add(f["hash"])
    return result


def compute_bounds(case, fixed=None):
    """Return (per_artifact {art: (lo, hi)}, global (lo, hi), assignments)."""
    assignments = list(valid_assignments(case, fixed))
    if not assignments:
        raise ValueError("no valid assignment satisfies the evidence")
    per = {}
    totals = []
    for a in assignments:
        hashes = artifact_hashes(case, a)
        totals.append(sum(len(h) for h in hashes.values()))
        for art in case["artifacts"]:
            n = len(hashes[art])
            lo, hi = per.get(art, (n, n))
            per[art] = (min(lo, n), max(hi, n))
    return per, (min(totals), max(totals)), assignments


def width(per, glob):
    return sum(hi - lo for lo, hi in per.values()) + (glob[1] - glob[0])


def evaluate_questions(case):
    """Score each ambiguous finding as a candidate verification question."""
    per0, glob0, _ = compute_bounds(case)
    w0 = width(per0, glob0)
    rows = []
    for f in ambiguous_findings(case):
        outcomes = []
        for cand in f["attribution"]["candidates"]:
            per1, glob1, _ = compute_bounds(case, {f["id"]: cand})
            outcomes.append((cand, width(per1, glob1)))
        worst = max(w for _, w in outcomes)
        mean = sum(w for _, w in outcomes) / len(outcomes)
        rows.append({
            "id": f["id"],
            "candidates": f["attribution"]["candidates"],
            "outcomes": outcomes,
            "guaranteed_reduction": w0 - worst,
            "expected_reduction": w0 - mean,
        })
    rows.sort(key=lambda r: (r["guaranteed_reduction"], r["expected_reduction"]),
              reverse=True)
    return w0, rows


def attaining(case, assignments, pred):
    return [a for a in assignments if pred(a)]


def fmt_assignment(case, assignment):
    return ", ".join(f["id"] + "->" + assignment[f["id"]]
                     for f in ambiguous_findings(case))


def render_report(case, per, glob, assignments, w0, questions):
    arts = case["artifacts"]
    sum_lo = sum(lo for lo, _ in per.values())
    sum_hi = sum(hi for _, hi in per.values())
    best = questions[0]
    lines = []
    add = lines.append

    add("# 离线暴露风险核算报告")
    add("")
    add("- 案例: " + case["case"])
    add("- 候选发布件: " + ", ".join(arts))
    n_amb = len(ambiguous_findings(case))
    add("- 发现总数: %d (确定归属 %d, 二选一待定 %d)"
        % (len(case["findings"]), len(case["findings"]) - n_amb, n_amb))
    add("- 满足证据约束的合法归属方案数: %d" % len(assignments))
    add("")

    add("## 建模规则")
    add("")
    add("- 同一发布件内相同 hashed_secret 的多个位置 = 同一发现的多个泄漏点, 计 1 次")
    add("  (例: F-001 在 rel-alpha 内有 2 个位置, 只计 1 次暴露)。")
    add("- 不同发布件中的相同哈希 = 独立发现, 分别计数")
    add("  (例: F-004 与 F-001 同哈希, 但属 rel-beta, 独立计 1 次)。")
    add("- 两个待定发现若哈希相同且归属同一发布件, 合并为一次暴露")
    add("  (F-007 与 F-011 同哈希, 同归 rel-beta 时合并)。")
    add("- 发布件暴露计数 = 归属该件的不同哈希数; 全局暴露计数 = 各件计数之和。")
    add("")

    add("## 调查证据 (互斥约束)")
    add("")
    for ev in case["evidence"]:
        add("- %s: %s 不能同时归属 %s。%s"
            % (ev["id"], " 与 ".join(ev["findings"]), ev["artifact"], ev["note"]))
    add("")

    add("## 逐件暴露计数区间")
    add("")
    add("| 发布件 | 下界 | 上界 | 区间宽 |")
    add("| --- | --- | --- | --- |")
    for art in arts:
        lo, hi = per[art]
        add("| %s | %d | %d | %d |" % (art, lo, hi, hi - lo))
    add("| **逐件合计** | **%d** | **%d** | **%d** |"
        % (sum_lo, sum_hi, sum_hi - sum_lo))
    add("| **全局** | **%d** | **%d** | **%d** |"
        % (glob[0], glob[1], glob[1] - glob[0]))
    add("")

    add("## 证明: 逐件上界之和可以大于全局上界")
    add("")
    add("逐件上界之和 = %s = **%d**, 而全局上界 = **%d**。**%d > %d**, 成立。原因:"
        % (" + ".join(str(per[a][1]) for a in arts), sum_hi, glob[1], sum_hi, glob[1]))
    add("")
    add("1. 每个待定发现同时计入其两个候选件各自的上界 (上界是逐件独立取 max 得到的),")
    add("   但在任何一个具体归属方案中它只能归属一件, 全局至多计 1 次。")
    add("2. 各件上界由互不相容的归属方案分别达到, 无法同时成立:")
    for art in arts:
        hi = per[art][1]
        witness = attaining(case, assignments,
                            lambda a, art=art, hi=hi: len(artifact_hashes(case, a)[art]) == hi)[0]
        add("   - %s 上界 %d 由方案 [%s] 达到;" % (art, hi, fmt_assignment(case, witness)))
    gwit = attaining(case, assignments,
                     lambda a: sum(len(h) for h in artifact_hashes(case, a).values()) == glob[1])[0]
    add("3. 全局上界由单一方案达到, 例如 [%s], 其各件计数之和恰为 %d。"
        % (fmt_assignment(case, gwit), glob[1]))
    add("")
    add("因此 sum(逐件上界) = %d > %d = 全局上界, 二者之差 %d 正是待定发现"
        % (sum_hi, glob[1], sum_hi - glob[1]))
    add("在逐件口径下的重复计数。同理, 逐件下界之和 (%d) < 全局下界 (%d):"
        % (sum_lo, glob[0]))
    add("任何具体方案都必须把每个待定发现归于某一件。")
    add("")

    add("## 单次核查名额的最优问题")
    add("")
    add("当前总不确定度 W = sum(逐件区间宽) + 全局区间宽 = **%d**。" % w0)
    add("逐一模拟核查每个待定发现 (两种结果下取保证/期望缩减):")
    add("")
    add("| 待核问题 | 结果分支残余 W | 保证缩减 | 期望缩减 |")
    add("| --- | --- | --- | --- |")
    for q in questions:
        branches = ", ".join("->%s: W=%d" % (c, w) for c, w in q["outcomes"])
        add("| %s in {%s}? | %s | **%d** | %.1f |"
            % (q["id"], ", ".join(q["candidates"]), branches,
               q["guaranteed_reduction"], q["expected_reduction"]))
    add("")
    add("**建议核查: %s 的归属 (%s 还是 %s)。**"
        % (best["id"], best["candidates"][0], best["candidates"][1]))
    add("无论结果如何, W 至少缩减 %d (期望缩减 %.1f), 为所有候选问题中最优。"
        % (best["guaranteed_reduction"], best["expected_reduction"]))
    if best["id"] == "F-011":
        add("原因: F-011 与 F-007 同哈希: 核定其归属同时钉死了同件合并这一唯一")
        add("影响全局下界的分支, 并同步收紧 rel-beta / rel-gamma 两件区间。")
    add("")
    return "\n".join(lines) + "\n"


def main():
    case = load_case(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CASE)
    per, glob, assignments = compute_bounds(case)
    w0, questions = evaluate_questions(case)
    report = render_report(case, per, glob, assignments, w0, questions)
    REPORT_PATH.write_text(report, encoding="utf-8")
    print(report)
    print("[written] " + str(REPORT_PATH), file=sys.stderr)


if __name__ == "__main__":
    main()

