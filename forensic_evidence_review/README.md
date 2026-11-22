# 证物比对能力表（STIX 2.1 本地对象链路）

取证台账中两份结论均为「文件吻合」的报告，针对同一份短文本证物
`evidence/statement-2023-0518.txt`：

- 旧报告 `FR-2023-0518`（2023-05-18 签字）：只归档了一枚旧 MD5 摘要，数字样品未保留。
- 新报告 `FR-2026-1112`（2026-11-12 签字）：保留授权数字样品与 MD5/SHA-1/SHA-256/SHA-512 多种摘要。

本目录在本地构建一个 STIX 2.1 Bundle，把两份报告、证物 SCO、证物比对能力表和双日期对照串成一条完整引用链路。所有摘要均由 `build_bundle.py` 在本地从样品实时计算，不存在伪造或手写的哈希值。

## 目录结构

- `evidence/statement-2023-0518.txt` — 授权保留的短文本数字样品（282 字节）。
- `custom_types.py` — 两个自定义 SDO：`x-hash-capability-table` 与 `x-digest-cross-date-review`。
- `build_bundle.py` — 复算摘要、组装 14 个 STIX 对象并写出 Bundle；重复运行产物逐字节一致。
- `bundle/evidence-comparison-bundle.json` — 最终 Bundle（14 个对象，全部本地引用可解析）。
- `validate_bundle.py` — 独立校验：引用完整性、复算值一致性、枚举口径、确定性 ID。

## 运行方式

```bash
.venv/bin/python forensic_evidence_review/build_bundle.py
.venv/bin/python forensic_evidence_review/validate_bundle.py
```

## 证物比对能力表（复核日 2026-11-20 口径）

能力值口径：`confirm`=可用于同一性确认；`lead`=只可作线索；`inconclusive`=保留未得结论。

### 旧报告 FR-2023-0518（无样品，补算窗口从未开启）

| 算法 | 判定日期 | 能力 | 实际补算 | 依据 |
| --- | --- | --- | --- | --- |
| MD5 | 2023-05-18 | confirm | 否 | 签字时规程接受 MD5 确认；历史判断保留可回查。 |
| MD5 | 2026-11-20 | lead | 否 | 复核规程降级；仅存旧摘要，无法补算强算法。 |
| SHA-1 | 2026-11-20 | lead | 否 | 档案无 SHA-1 也无样品，保持未得结论。 |
| SHA-256 | 2026-11-20 | inconclusive | 否 | 算法可确认但缺原件，无法实际补算。 |
| SHA-512 | 2026-11-20 | inconclusive | 否 | 同上，补算窗口从未开启。 |
| SSDEEP | 2026-11-20 | inconclusive | 否 | 无样品且历史 ssdeep 版本未记录，版本无法对齐。 |

### 新报告 FR-2026-1112（样品在手，授权窗口 2026-11-12T09:30Z/10:05Z）

| 算法 | 判定日期 | 能力 | 实际补算 | 依据 |
| --- | --- | --- | --- | --- |
| MD5 | 2023-05-18 | confirm | 否 | 仅记录历史规程状态；该报告当时尚未签署。 |
| MD5 | 2026-11-20 | lead | 是 | 补算值与 A 旧摘要逐字一致，但复核日只作线索。 |
| SHA-1 | 2026-11-20 | lead | 是 | 已补算；碰撞问题使其只能作线索。 |
| SHA-256 | 2026-11-20 | confirm | 是 | 已补算，对 B 样品构成确认；不外推到缺原件的 A。 |
| SHA-512 | 2026-11-20 | confirm | 是 | 已补算，第二确认算法，与 SHA-256 交叉支撑。 |
| SSDEEP | 2026-11-20 | inconclusive | 否 | 样品在手但版本无法对齐，版本固定前不补算。 |

## 同一短文本在两个判定日期的对照

对照对象是同一枚短文本样品的同一种摘要，并列 2023-05-18 与 2026-11-20 两个判定日期。标注口径：`lead_only`=只能当线索；`recomputed`=已从授权样品实际补算；`missing_original_or_version`=缺原件或版本不对齐、保留未得结论。

| 算法 | 2023-05-18 能力 | 2026-11-20 能力 | 标注 | 摘要值（本地实算） |
| --- | --- | --- | --- | --- |
| MD5 | confirm | lead | lead_only | `e6ee1d87dcebb3b487e6687892303199` |
| SHA-1 | not_recorded | lead | lead_only | `e4708009341a08e3e00b8a3af305cd88ffee1a16` |
| SHA-256 | not_recorded | confirm | recomputed | `fc8c7c3189d596814526c984483f8b1d991d2526d0e742b16f1b404a3bdb882d` |
| SHA-512 | not_recorded | confirm | recomputed | `a4ada485cfe95e8fe0ee72515b7ad081c8fbee112d260fed9a70bd9ce439b768cb54d1c665daf4105e44b4bddfc1d88b13b318eb9c91133851005ad94f67202e` |
| SSDEEP | not_recorded | inconclusive | missing_original_or_version | 无（版本无法对齐，未补算） |

说明：

- MD5 是唯一在两个日期都有判断的摘要：2023 年可确认、2026 年只能当线索；2026-11-12 已从 B 样品实际补算，且与 A 报告旧 MD5 逐字一致，但 A 自身仍缺原件。
- SHA-256、SHA-512 是实际补算过的确认级摘要，结论只覆盖仍持有样品的 B 报告；A 报告缺原件，对其证物本身保持未得结论，不做跨报告强同一认定。
- SSDEEP 在两份报告上都保留未得结论：A 缺原件且无版本记录；B 虽有样品，但复核环境 ssdeep 版本与历史版本无法对齐，在版本固定前不补算，避免产生不可比的模糊哈希。

## 关键结论

1. 历史可回查：2023-05-18 以 MD5 作出的「文件吻合」判断符合当时规程，作为历史签字结论保留并可回查，不因今日降级而抹除。
2. 复核日确认路径：只有 SHA-256、SHA-512 可用于确认，且必须持有样品实际补算；该路径仅对 B 报告成立。
3. 线索级：MD5（含与旧摘要一致的补算值）与 SHA-1 只可作线索，不能单独确认同一性。
4. 未得结论：A 报告的 SHA-256/SHA-512/SSDEEP 因缺原件无法补算；SSDEEP 另因版本无法对齐，在 B 报告上同样未得结论。样品或版本一旦补齐，可在授权范围内重新打开补算窗口。

## STIX 对象与本地链路

14 个对象（`validate_bundle.py` 验证所有引用均在 Bundle 内闭合）：

- SCO：2 个 `file`（A 仅含 MD5；B 含四种实算摘要并 `content_ref` 指向样品）、1 个内嵌 payload 的 `artifact`。
- SDO：2 个 `observed-data`、2 个 `report`、1 个 `identity`、1 个 `note`，以及两个自定义 SDO `x-hash-capability-table`（12 条能力条目）和 `x-digest-cross-date-review`（5 条双日期对照）。
- SRO：2 条 `derived-from` 关系，把能力表挂到两份报告；自定义 SDO 内另以类型化 `ReferenceProperty` 显式引用报告、证物、样品、能力表。
- 标记：全部对象带规范 TLP:RED `marking-definition`。

幂等性：所有 SDO/SRO 使用固定 ID 与固定时间戳，SCO 由属性生成确定性 UUID5；重复执行 `build_bundle.py` 输出逐字节一致。
