# EVTX 离线保管核对（custody_audit）

临近销档日期时，把 EVTX 源证物交接给长期保管人的离线核对工具。
全程只读本地文件、不访问网络，基于调用方提供的记录范围、保管人权限和签收时间，
把源证物的每条记录划入三类，并从外部清单与内部责任表两个方向交叉核对。

## 三类核对结论

- **可继续复查（reviewable）**：外部清单以 `full` 模式列出该范围，且存在落在该范围上的有效回执，签收人具备 `evtx.full_review` 权限，原始记录可继续复查。
- **仅剩摘要（summary_only）**：外部清单以 `summary` 模式交接，有效回执的签收人仅具备 `evtx.summary` 权限，原始记录不再随外部清单流转，外部材料只保留脱敏元数据。
- **尚未被承接（not_accepted）**：清单未列出该范围，或没有任何有效回执。上一任保管人仍持有同一份副本不构成移交。

## 回执有效条件（全部满足）

1. 签收人存在于内部责任表；
2. 签收时间处于签收人的责任期内，且不晚于销档日期；
3. 签收人持有与交接模式匹配的权限（`evtx.full_review` / `evtx.summary`）；
4. 回执范围（EVTX 文件 + 起止记录号）与外部清单条目完全一致，模式也一致。

换岗回执（`shift_change`）与事后补签回执（`retroactive`）采用同一套效力规则；
同一范围存在多张有效回执时，以签收时间最晚者为准。不满足条件的回执会被逐条否决并列入报告，
相关记录仍判为“尚未被承接”。

## 外部清单脱敏要求

外部清单条目只允许以下字段：`evtx_file`、`first_record`、`last_record`、`mode`、
`record_count`、`record_sha256`、`file_sha256`、`handover_due`。
出现原始 XML、事件数据、用户/账号、进程、命令行、二进制载荷等敏感字段时，
工具报 `MANIFEST_SENSITIVE_KEY` 错误并阻断交接结论。报告本身也只打印记录编号、哈希与结论，不含事件原文。

## 输入文件

- `audit_config.json`：销档日期 `archive_cutoff` 与每个 EVTX 的记录范围 `scope`；
- `custodian_roster.json`：内部责任表，含保管人编号、权限、责任起止时间；
- `external_manifest.json`：外部交接清单（脱敏）；
- `handover_receipts.json`：换岗/补签回执列表。

## 运行方式

```
python -m custody_audit.cli \\
  --evtx-dir custody_audit/sample_data/evtx \\
  --config custody_audit/sample_data/audit_config.json \\
  --roster custody_audit/sample_data/custodian_roster.json \\
  --manifest custody_audit/sample_data/external_manifest.json \\
  --receipts custody_audit/sample_data/handover_receipts.json
```

退出码 `0` 表示无阻断性差异；`1` 表示存在错误级差异（如无效回执、清单缺签收、敏感字段）。
样例 JSON 可由 `python -m custody_audit.sample_data.generate_sample` 重新生成，哈希直接从源 EVTX 计算。

## 样例场景

样例含两份短日志（`security_short.evtx` 1 条记录、`dns_short.evtx` 5 条记录，其中 2-5 为无法完整渲染的损坏记录，仍按编号与哈希纳入核对）：

- `security_short.evtx#1`：换岗回执 R-01，长期保管人 C002 完整签收 → 可继续复查；
- `dns_short.evtx#1`：换岗回执 R-02，摘要保管人 C003 仅签收摘要 → 仅剩摘要；
- `dns_short.evtx#4-5`：补签回执 R-04，C002 在责任期内补签 → 可继续复查；
- `dns_short.evtx#2-3`：补签回执 R-03 由已离任的前任 C001 签署，被否决 → 尚未被承接。
