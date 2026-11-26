# 第一批：移交双工具输出受理

- 批次：batch-1-handoff-2024-rules
- 规则集：archivist-rules-2024.1 — 档案参数规则 v2024.1（历史连字符算法记法）
- 明文接触：否；未调用 load_key()，未生成解密文件
- 保护包：3
- 证词条目：114
- 文件哈希核验：6
- 记法等价项：26
- 实际保护差异：1
- 待补签：1
- 来源规范冲突：0
- 未接受证词：0
- 复核案例全部验证：是

## 档案员重点

| 案例 | 包 | 预期判定 | 实际判定 | 验证 | 说明 |
|---|---|---|---|---|---|
| CASE-NOTATION-001 | ARCH-001 | notation_only | notation_only | 是 | 16 字节与 128 位、SHA-1 说明与 SHA1 令牌是同一组参数 |
| CASE-UPDATE-002 | ARCH-002 | actual_update | actual_update_requires_reapproval | 是 | 批准单为 50000 轮，保护包实测为 100000 轮，需要补签 |

## 分类输出

- 纯记法/转写说明：transcription-notes.md 与 transcription-notes.json
- 实际保护属性差异：protection-differences.md 与 protection-differences.json
- 待补签队列：reapproval-queue.md 与 reapproval-queue.json
- 全量逐项证词台账：ledger.csv 与 ledger.json
- 哈希完整性核验：artifact-checks.json
- 复核案例机读结果：review-cases.json

## 规范化兼容性

新版 archivist-rules-2026.2 用 hash.v1_canonical_compat 接受 2024.1 批准单中的 SHA-1/SHA-512 历史连字符值，并转写为 Office/msoffcrypto 使用的 SHA1/SHA512 令牌。length.bytes_to_bits 明确处理 16 字节到 128 位这类长度单位换算。规则目录未列出的单位或算法别名会被标记为 normalization_rejected，而不会被静默猜测。
