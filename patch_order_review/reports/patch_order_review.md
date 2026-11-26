# 补丁顺序审查：RG-2031-07 双维护线重锁

- 审查日期：2026-11-27
- 夹具摘要：`2bd685037bf436ee1a58b2d35b8054ffa9a44e88732644b3bd0b838c6b93b467`
- 审计来源：离线 pydef 夹具经 `pip_audit._format.json.JsonFormat` 生成的本地 pip-audit JSON
- 路线：`min_delta`（最小端点版本差）与 `bridge_release`（桥接版本、持有已签 ABI 边界）

## 结论

| 路线 | 端点版本差 | 仅端点判决 | 逐步连续性判决 | 终态 |
| --- | ---: | --- | --- | --- |
| `min_delta` | 6 | pass | fail | reject |
| `bridge_release` | 7 | pass | pass | accept |

推荐 `bridge_release`：Bridge release / hold the signed ABI boundary。它的端点版本差为 7，但每一个中间锁都保持已签风险关闭。

不能只比较端点：两条路线的终态开放风险完全相同，但 `min_delta` 在中途重开了 PYSEC-2026-0003；仅端点比较会把它判为 pass。

## 夹具：四个虚构分发包

| 包 | 维护线 | 角色 | 候选版本 |
| --- | --- | --- | --- |
| `argonvale` | line-7 | runtime schema and query engine | 1.4.1, 1.5.0, 1.6.0 |
| `cinderloom` | line-7 | ABI boundary and plugin loader | 0.9.1, 1.0.1 |
| `basaltine` | line-8 | data-plane coordinator | 2.0.0, 2.0.1, 2.1.0, 2.2.0 |
| `driftpin` | line-8 | edge transport agent | 3.2.1, 3.3.0 |

基线锁：`argonvale==1.4.1`，`cinderloom==1.0.1`，`basaltine==2.0.0`，`driftpin==3.2.1`

终态要求：`argonvale>=1.6.0`，`cinderloom==1.0.1`，`basaltine>=2.1.0,<2.3`，`driftpin==3.3.0`

## 明示的兼容约束

| 约束 | 触发条件 | 要求 | 原因 |
| --- | --- | --- | --- |
| `COMPAT-001` | `basaltine==2.0.1` | `cinderloom<1.0.0` | 2.0.1 metadata regression RG-4411 still loads the legacy ABI slot. |
| `COMPAT-002` | `basaltine>=2.1.0,<2.3` | `cinderloom>=1.0.0,<1.1` | 2.1.0 and the 2.2.0 bridge both require the signed ABI boundary. |
| `COMPAT-003` | `cinderloom<1.0.0` | `driftpin<3.3.0` | The legacy cinderloom ABI cannot speak the 3.3 relay handshake. |
| `COMPAT-004` | `driftpin>=3.3.0` | `basaltine>=2.1.0`, `cinderloom>=1.0.1` | The 3.3 relay handshake requires both the coordinator fix and the 1.0.1 ABI boundary. |
| `COMPAT-005` | `basaltine>=2.2.0` | `argonvale>=1.5.0` | The 2.2.0 bridge bundles the 2.0.1 migration but requires the 1.5.0 runtime schema. |

## 逐状态审计：`min_delta`

Reach the nearest fixed versions with the smallest terminal version gap.

| 步 | 补丁单元 | 线路 | `argonvale` | `cinderloom` | `basaltine` | `driftpin` | 开放风险 | 锁定风险重开 |
| ---: | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | baseline | line-7 + line-8 | 1.4.1 | 1.0.1 | 2.0.0 | 3.2.1 | PYSEC-2026-0002 | — |
| 1 | `L7-A-150` | line-7 | 1.5.0 | 1.0.1 | 2.0.0 | 3.2.1 | PYSEC-2026-0008, PYSEC-2026-0002 | — |
| 2 | `L7-A-160` | line-7 | 1.6.0 | 1.0.1 | 2.0.0 | 3.2.1 | PYSEC-2026-0002 | — |
| 3 | `L8-B-201--L7-C-091` | line-8 + line-7 | 1.6.0 | 0.9.1 | 2.0.1 | 3.2.1 | PYSEC-2026-0003, PYSEC-2026-0002, PYSEC-2026-0007 | PYSEC-2026-0003 |
| 4 | `L8-B-210--L7-C-101` | line-8 + line-7 | 1.6.0 | 1.0.1 | 2.1.0 | 3.2.1 | — | — |
| 5 | `L8-D-330` | line-8 | 1.6.0 | 1.0.1 | 2.1.0 | 3.3.0 | PYSEC-2026-0006 | — |

判决理由：
- PYSEC-2026-0003 reopens at states [3] after a signed (abi-security) non-reopenable disposition
- PYSEC-2026-0007 is exposed for 1 state(s) without an accepted transient disposition

## 逐状态审计：`bridge_release`

Use the 2.2.0 bridge and never downgrade cinderloom below the signed 1.0.1 boundary.

| 步 | 补丁单元 | 线路 | `argonvale` | `cinderloom` | `basaltine` | `driftpin` | 开放风险 | 锁定风险重开 |
| ---: | --- | --- | --- | --- | --- | --- | --- | --- |
| 0 | baseline | line-7 + line-8 | 1.4.1 | 1.0.1 | 2.0.0 | 3.2.1 | PYSEC-2026-0002 | — |
| 1 | `L7-A-150` | line-7 | 1.5.0 | 1.0.1 | 2.0.0 | 3.2.1 | PYSEC-2026-0008, PYSEC-2026-0002 | — |
| 2 | `L7-A-160` | line-7 | 1.6.0 | 1.0.1 | 2.0.0 | 3.2.1 | PYSEC-2026-0002 | — |
| 3 | `L8-B-220` | line-8 | 1.6.0 | 1.0.1 | 2.2.0 | 3.2.1 | — | — |
| 4 | `L8-D-330` | line-8 | 1.6.0 | 1.0.1 | 2.2.0 | 3.3.0 | PYSEC-2026-0006 | — |

## 证据 A：临时引入风险

下表保留两类临时风险：未列入处置的临时引入风险，以及重开已签处置的阻断项。

| 路线 | 状态 | 风险 | 类别 | 连续状态数 | 处置 |
| --- | --- | --- | --- | ---: | --- |
| `min_delta` | [3] | `PYSEC-2026-0003` (cinderloom@0.9.1) | 重开已签处置（不可重开） | 1 | 阻断：abi-security，2026-07-30 |
| `min_delta` | [3] | `PYSEC-2026-0007` (basaltine@2.0.1) | 临时引入 | 1 | 未接受，阻断 |
| `min_delta` | [1] | `PYSEC-2026-0008` (argonvale@1.5.0) | 临时引入 | 1 | 已接受至 2026-12-15；Set ARGONVALE_LEGACY_JSON=0 and keep WAF rule W-118 enabled for the migration window. |
| `bridge_release` | [1] | `PYSEC-2026-0008` (argonvale@1.5.0) | 临时引入 | 1 | 已接受至 2026-12-15；Set ARGONVALE_LEGACY_JSON=0 and keep WAF rule W-118 enabled for the migration window. |

## 证据 B：终态仍留风险

| 路线 | 风险 | 终态版本 | 可用修复版本 | 处置 |
| --- | --- | --- | --- | --- |
| `min_delta` | `PYSEC-2026-0006` (driftpin) | 3.3.0 | 无 | 已接受至 2027-03-31；owner=data-plane-security；Apply egress allowlist DP-EGRESS-3 and signed relay pinning until an upstream fix exists. |
| `bridge_release` | `PYSEC-2026-0006` (driftpin) | 3.3.0 | 无 | 已接受至 2027-03-31；owner=data-plane-security；Apply egress allowlist DP-EGRESS-3 and signed relay pinning until an upstream fix exists. |

## 推导：为什么必须多付一个版本差

- 候选锁空间为 3 × 2 × 4 × 2 = 48 个版本组合；在补丁单元前置条件与兼容约束下，共有 13 条可达终态的合法排序。
- 忽略中间状态的搜索里，最小端点版本差为 6，代表顺序为 ['L7-A-150', 'L7-A-160', 'L8-B-201--L7-C-091', 'L8-B-210--L7-C-101', 'L8-D-330']；同差路线 10 条，其中 0 条连续安全。
- 最小端点差路线不是连续安全的：PYSEC-2026-0003 reopens at states [3] after a signed (abi-security) non-reopenable disposition; PYSEC-2026-0007 is exposed for 1 state(s) without an accepted transient disposition。
- 对锁定风险做连续约束后，最小安全端点版本差为 7，代表顺序为 ['L7-A-150', 'L7-A-160', 'L8-B-220', 'L8-D-330']；同差安全路线 2 条。
- 安全溢价 = 1 个版本分量。
- 关键排序：`basaltine==2.0.1` 触发 `COMPAT-001`，迫使 `cinderloom` 从 1.0.1 降级到 0.9.1，重开 0003；`basaltine==2.2.0` 是打包了 2.0.1 迁移的桥接版本，绕过坏元数据，但要求 `argonvale>=1.5.0`（`COMPAT-005`），因此必须先执行 `argonvale` 的 1.5.0 顺序迁移，再上桥接版本。

## 复现

```bash
python -m patch_order_review
python -m patch_order_review verify
python -m pytest test/test_patch_order_review.py
```

`python -m patch_order_review` 会重写 `patch_order_review/fixture/audit/` 下的逐状态 pip-audit JSON、`patch_order_review/reports/review.json` 与本报告。
