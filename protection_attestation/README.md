# Office 保护参数证词受理层

这个目录为档案移交提供不解密、不输出明文的参数受理与核对能力。它通过
msoffcrypto.OfficeFile 读取加密 OOXML 的 EncryptionInfo 元数据，不会调用
load_key()、密码校验或 decrypt()。

## 运行

在仓库根目录执行：

    .venv/bin/python -m protection_attestation build-handoff-outputs
    .venv/bin/python -m protection_attestation run-batch +      --config protection_attestation/handoff/batch-1-handoff.json +      --out protection_attestation/reports/batch-1-handoff-2024-rules
    .venv/bin/python -m protection_attestation run-batch +      --config protection_attestation/handoff/batch-2-recheck.json +      --out protection_attestation/reports/batch-2-recheck-2026-rules

build-handoff-outputs 会从三个仓库内置的小型合法加密包重新生成两份记法不同的
工具输出。第二份 archive-desk-scanner 是移交场景中的显示方言样例：使用
“字节”“中文算法说明”和“N 轮 PBKDF2”等历史写法。

## 数据源

- tests/inputs/ecma376agile_sha1_password.xlsx：ARCH-001，SHA1/AES-128。
- tests/inputs/example_password.docx：ARCH-002，SHA512/AES-256。
- tests/inputs/example_password.xlsx：ARCH-003，与 ARCH-002 参数基线一致的对照包。
- handoff/approvals.json：AP-2024-018 至 AP-2024-020 批准单。
- handoff/batch-1-handoff.json：第一批，使用 archivist-rules-2024.1。
- handoff/batch-2-recheck.json：第二批，使用 archivist-rules-2026.2 复核。

## 逐项证词

ledger.csv 和 ledger.json 中每个参数确认都包含：

- recorded_value：来源中的原始记录值。
- source：来源类型、工具/批准单、文件 SHA-256 和 JSON/XML 定位器。
- normalization.rule_id 与 rule_version：明确接受的规范化规则。
- normalization.canonical_value：规范化后的可比较值。
- notation_transform：是否仅发生单位或记法换算。
- historical_compatibility：是否通过新版规则兼容历史规则值。

未列入规则目录的单位或算法别名会得到 accepted=false，并进入
rejected-claims.json；受理层不会猜测。

## 分类报告

每批报告分别输出：

- transcription-notes.md/json：原始写法不同但规范值相同的纯转写项。
- protection-differences.md/json：规范化后仍不同的实际保护属性差异。
- reapproval-queue.md/json：必须补签批准的参数更新。
- review-cases.json：两个档案员复核案例的独立验证结果。
- artifact-checks.json：工具输出记录的包 SHA-256 与现包是否一致。

当前样例的结论固定为：

- CASE-NOTATION-001：ARCH-001 的 16 字节与 128 位、SHA-1 摘要算法
  与 SHA1、AES-128-CBC 描述均为纯记法变动，不需要补签。
- CASE-UPDATE-002：ARCH-002 的 spin_count 从批准值 50000 变为实测值
  100000，属于实际参数更新，AP-2024-019 不能继续覆盖，需要补签。

## 规则版本兼容

archivist-rules-2024.1 使用历史档案规范名 SHA-1、SHA-512。
archivist-rules-2026.2 改用 Office/msoffcrypto 令牌 SHA1、SHA512，但通过
hash.v1_canonical_compat 明确接受旧批准单中的连字符值。长度始终规范为 bit，
字节值必须经 length.bytes_to_bits 显式乘 8。
