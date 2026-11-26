# 离线暴露风险核算报告

- 案例: offline-exposure-accounting-2026-11
- 候选发布件: rel-alpha, rel-beta, rel-gamma, rel-delta
- 发现总数: 11 (确定归属 6, 二选一待定 5)
- 满足证据约束的合法归属方案数: 18

## 建模规则

- 同一发布件内相同 hashed_secret 的多个位置 = 同一发现的多个泄漏点, 计 1 次
  (例: F-001 在 rel-alpha 内有 2 个位置, 只计 1 次暴露)。
- 不同发布件中的相同哈希 = 独立发现, 分别计数
  (例: F-004 与 F-001 同哈希, 但属 rel-beta, 独立计 1 次)。
- 两个待定发现若哈希相同且归属同一发布件, 合并为一次暴露
  (F-007 与 F-011 同哈希, 同归 rel-beta 时合并)。
- 发布件暴露计数 = 归属该件的不同哈希数; 全局暴露计数 = 各件计数之和。

## 调查证据 (互斥约束)

- E-1: F-007 与 F-008 不能同时归属 rel-alpha。Build manifest of rel-alpha contains only one of the two anonymized source modules; F-007 and F-008 cannot both belong to rel-alpha.
- E-2: F-009 与 F-010 不能同时归属 rel-delta。Release log of rel-delta shows the two leak sites were introduced by different, non-overlapping exports; F-009 and F-010 cannot both belong to rel-delta.

## 逐件暴露计数区间

| 发布件 | 下界 | 上界 | 区间宽 |
| --- | --- | --- | --- |
| rel-alpha | 2 | 3 | 1 |
| rel-beta | 2 | 4 | 2 |
| rel-gamma | 1 | 4 | 3 |
| rel-delta | 1 | 2 | 1 |
| **逐件合计** | **6** | **13** | **7** |
| **全局** | **10** | **11** | **1** |

## 证明: 逐件上界之和可以大于全局上界

逐件上界之和 = 3 + 4 + 4 + 2 = **13**, 而全局上界 = **11**。**13 > 11**, 成立。原因:

1. 每个待定发现同时计入其两个候选件各自的上界 (上界是逐件独立取 max 得到的),
   但在任何一个具体归属方案中它只能归属一件, 全局至多计 1 次。
2. 各件上界由互不相容的归属方案分别达到, 无法同时成立:
   - rel-alpha 上界 3 由方案 [F-007->rel-alpha, F-008->rel-gamma, F-009->rel-beta, F-010->rel-gamma, F-011->rel-beta] 达到;
   - rel-beta 上界 4 由方案 [F-007->rel-alpha, F-008->rel-gamma, F-009->rel-beta, F-010->rel-gamma, F-011->rel-beta] 达到;
   - rel-gamma 上界 4 由方案 [F-007->rel-alpha, F-008->rel-gamma, F-009->rel-beta, F-010->rel-gamma, F-011->rel-gamma] 达到;
   - rel-delta 上界 2 由方案 [F-007->rel-alpha, F-008->rel-gamma, F-009->rel-beta, F-010->rel-delta, F-011->rel-beta] 达到;
3. 全局上界由单一方案达到, 例如 [F-007->rel-alpha, F-008->rel-gamma, F-009->rel-beta, F-010->rel-gamma, F-011->rel-beta], 其各件计数之和恰为 11。

因此 sum(逐件上界) = 13 > 11 = 全局上界, 二者之差 2 正是待定发现
在逐件口径下的重复计数。同理, 逐件下界之和 (6) < 全局下界 (10):
任何具体方案都必须把每个待定发现归于某一件。

## 单次核查名额的最优问题

当前总不确定度 W = sum(逐件区间宽) + 全局区间宽 = **8**。
逐一模拟核查每个待定发现 (两种结果下取保证/期望缩减):

| 待核问题 | 结果分支残余 W | 保证缩减 | 期望缩减 |
| --- | --- | --- | --- |
| F-011 in {rel-beta, rel-gamma}? | ->rel-beta: W=6, ->rel-gamma: W=6 | **2** | 2.0 |
| F-007 in {rel-alpha, rel-beta}? | ->rel-alpha: W=5, ->rel-beta: W=7 | **1** | 2.0 |
| F-008 in {rel-alpha, rel-gamma}? | ->rel-alpha: W=5, ->rel-gamma: W=7 | **1** | 2.0 |
| F-009 in {rel-beta, rel-delta}? | ->rel-beta: W=7, ->rel-delta: W=5 | **1** | 2.0 |
| F-010 in {rel-gamma, rel-delta}? | ->rel-gamma: W=7, ->rel-delta: W=5 | **1** | 2.0 |

**建议核查: F-011 的归属 (rel-beta 还是 rel-gamma)。**
无论结果如何, W 至少缩减 2 (期望缩减 2.0), 为所有候选问题中最优。
原因: F-011 与 F-007 同哈希: 核定其归属同时钉死了同件合并这一唯一
影响全局下界的分支, 并同步收紧 rel-beta / rel-gamma 两件区间。

