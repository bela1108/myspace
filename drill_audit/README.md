# 合成演练告警摘要核对（值班交接）

## 目的

值班需将合成演练的告警摘要分别交安全组与运维组。待确认记录中的字段别名可能是
配置换版前（gen1）留下来的，本目录用 pySigma 的公开规则与两代处理配置核对已有摘要，
逐项说明每个分组由哪个允许字段、哪一代配置支持，并保留两类待核验结果。

## 目录

- `config/pipeline_gen1.yml`：上一代处理配置（换版前），pySigma processing pipeline
- `config/pipeline_gen2.yml`：现行处理配置（换版后），pySigma processing pipeline
- `config/allowed_fields.yml`：交接契约——安全组/运维组各自允许的规范字段
- `data/summaries.yml`：已有告警摘要（分组字段 + 接收组）
- `data/pending_records.yml`：待确认记录（字段别名可能来自换版前）
- `audit.py`：核对脚本，产出 `results/audit_report.{json,md}`
- `observations.py`：本地无害观察（合成数据，不触网）

## 方法

1. 用 `ProcessingPipeline.from_yaml` 分别加载 gen1 / gen2 两代处理配置。
2. 对每个分组字段与记录字段构造一条只含该字段的合成 Sigma 规则，应用两代管线。
3. 解析结果直接取自 pySigma 的 `FieldMappingTracking`（`pipeline.field_mappings`），
   处理项标识（如 `gen2/rename-client-host`）即"哪一代配置支持"的来源依据。
4. 按接收组的允许字段定级：已确认 / 候选（多种别名） / 来源丢失。

## 核对结论（每项分组的支持字段与配置代）

| 摘要 | 接收组 | 分组字段 | 允许字段 | 支持配置 |
| --- | --- | --- | --- | --- |
| SUM-01 | 安全组 | src_ip | src_ip | gen1+gen2（规范字段，无需改写） |
| SUM-02 | 安全组 | source_ip | src_ip | gen1+gen2 |
| SUM-03 | 运维组 | client | host | 仅 gen1（gen2 已改名为 client_host） |
| SUM-04 | 安全组 | origin | 候选：src_ip（gen1）/ dst_ip（gen2） | 两代冲突，待核验 |
| SUM-05 | 安全组 | peer | 候选：src_ip、dst_ip（均 gen2 一对多） | 待核验 |
| SUM-06 | 运维组 | workstation_id | 来源丢失 | 两代均无此别名，待核验 |
| SUM-07 | 运维组 | host, service | host, service | gen1+gen2（规范字段） |

待确认记录：REC-101、REC-102、REC-106 已确认（REC-102 仅靠 gen1 支持，属换版前遗留格式）；
REC-103、REC-104 为候选，REC-105 来源丢失，均保持待核验。
完整逐项结论见 `results/audit_report.md`。

## 保留的两类结果

- **候选（多种别名导致）**：SUM-04、SUM-05、REC-103、REC-104。
  一个别名在两代配置或一对多映射下指向多个允许字段，全部候选保留，不静默归并。
- **来源丢失**：SUM-06、REC-105（`workstation_id`）。
  两代配置均无此别名且非规范字段，无法识别来源，保持待核验。

## 本地无害观察（observations.py，全部通过）

1. 普通改名（gen1 `client` → gen2 `client_host`）后规范分组完全一致，不产生真的分组变化。
2. pySigma 跟踪可指明字段由哪一代配置的哪个处理项支持（`was_processed_by`）。
3. 未知字段 `workstation_id` 不被任何一代配置改写，记录保持待核验。
4. 一对多别名 `peer` 展开为 src_ip/dst_ip 两个候选，不静默归为单一分组。

## 复现

```bash
.venv/bin/python drill_audit/audit.py          # 生成 results/audit_report.{json,md}
.venv/bin/python drill_audit/observations.py   # 运行 4 条本地无害观察
```

