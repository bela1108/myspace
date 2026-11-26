# 离线证物核查移交计划

- 虚拟时钟起点：`2031-05-01T08:00:00Z`
- 计划摘要：共 7 件，完成 4，部分 2，受阻 1；操作 12 次，延期 3 处，移交 2 / 4 次。
- 计划摘要指纹：`d29842e448f5f892242f33e15cd2f90d52e98054c6b03024be5b673b69f20b40`
- 观察范围：仅保护外层；未使用密码、未解密载荷、未执行宏。
- 回执交付只依赖已捕获的证据摘要，可晚于附件可用期，但必须早于证据到期。

## 证据与职责

| 证物 | 格式 | 加密方案 | 所需检查 | 采用检查 | 保管员 | 状态 |
| --- | --- | --- | --- | --- | --- | --- |
| `ev-001-docx-agile` | ooxml | agile AES-256 | shell | shell | records-desk | complete |
| `ev-002-docx-standard` | ooxml | standard AES-128 | shell | shell | records-desk | complete |
| `ev-003-doc-rc4` | doc97 | rc4_cryptoapi RC4-128 | sealed_receipt | sealed_receipt | evidence-custodian | partial |
| `ev-004-xls-rc4` | xls97 | rc4_cryptoapi RC4-128 | sealed_receipt | sealed_receipt | evidence-custodian | complete |
| `ev-005-ppt-rc4` | ppt97 | rc4_cryptoapi RC4-128 | sealed_receipt | sealed_receipt | evidence-custodian | complete |
| `ev-006-xls-xor` | xls97 | xor XOR-16 | sealed_receipt | sealed_receipt | evidence-custodian | partial |
| `ev-007-docx-payload` | ooxml | agile AES-256 | payload_decrypt | - | evidence-custodian | blocked |

## 最小移交集合

- `ev-003-doc-rc4` → sealed_receipt / evidence-custodian（deferred）
- `ev-004-xls-rc4` → sealed_receipt / evidence-custodian（scheduled）
- `ev-005-ppt-rc4` → sealed_receipt / evidence-custodian（scheduled）
- `ev-006-xls-xor` → sealed_receipt / evidence-custodian（deferred）

## 可重放时间线

| 开始 | 结束 | 证物 | 操作 | 保管员 | 产物 |
| --- | --- | --- | --- | --- | --- |
| 2031-05-01T08:00:00Z | 2031-05-01T08:01:00Z | `ev-002-docx-standard` | inspect | - | - |
| 2031-05-01T08:01:00Z | 2031-05-01T08:02:00Z | `ev-001-docx-agile` | inspect | - | - |
| 2031-05-01T09:00:00Z | 2031-05-01T09:01:30Z | `ev-004-xls-rc4` | inspect | - | - |
| 2031-05-01T09:01:30Z | 2031-05-01T09:02:00Z | `ev-004-xls-rc4` | seal | evidence-custodian | 88d33c10ea845463 |
| 2031-05-01T09:02:00Z | 2031-05-01T09:03:30Z | `ev-003-doc-rc4` | inspect | - | - |
| 2031-05-01T09:03:30Z | 2031-05-01T09:04:00Z | `ev-003-doc-rc4` | seal | evidence-custodian | bc202678208036af |
| 2031-05-01T09:30:00Z | 2031-05-01T09:31:30Z | `ev-005-ppt-rc4` | inspect | - | - |
| 2031-05-01T09:31:30Z | 2031-05-01T09:32:00Z | `ev-005-ppt-rc4` | seal | evidence-custodian | 5ffcca9c628d7906 |
| 2031-05-01T10:00:00Z | 2031-05-01T10:02:30Z | `ev-004-xls-rc4` | handover | evidence-custodian | 88d33c10ea845463 |
| 2031-05-01T11:00:00Z | 2031-05-01T11:01:30Z | `ev-006-xls-xor` | inspect | - | - |
| 2031-05-01T11:01:30Z | 2031-05-01T11:02:00Z | `ev-006-xls-xor` | seal | evidence-custodian | 9de39061f908447f |
| 2031-05-01T13:00:00Z | 2031-05-01T13:02:30Z | `ev-005-ppt-rc4` | handover | evidence-custodian | 5ffcca9c628d7906 |

## 需延期的位置

- `ev-003-doc-rc4:handover:evidence-custodian` / custodian_conflict：另一个移交占用了剩余窗口。
  - 阻塞来自：`ev-004-xls-rc4`
  - 请求延期：2031-05-01T10:02:30Z → 2031-05-01T10:05:00Z（150s）
  - 需要动作：在证据到期前延长保管员窗口
- `ev-006-xls-xor:handover:evidence-custodian` / custodian_window_after_expiry：下一个保管员窗口在证据到期后才开始。
  - 请求延期：2031-05-01T11:02:00Z → 2031-05-01T11:04:30Z（150s）
  - 需要动作：在证据到期前延长保管员窗口
- `ev-007-docx-payload:plan:-` / check_not_allowed：所需检查 ['payload_decrypt'] 无法被允许运行的检查 ['sealed_receipt', 'shell'] 覆盖。
  - 需要动作：为该职责启用一种允许运行的外壳检查

## 封存回执

- `bc202678208036af`：证物 `ev-003-doc-rc4`，回执摘要 `bc202678208036afc123753b0c965f2fe2f68bcba5a12f87dc14b11d3e8d289f`。
- `88d33c10ea845463`：证物 `ev-004-xls-rc4`，回执摘要 `88d33c10ea84546381618bd2f4d478a5dab7ed4631dfd92e7b88d69c7791ec13`。
- `5ffcca9c628d7906`：证物 `ev-005-ppt-rc4`，回执摘要 `5ffcca9c628d7906d2b8bc174cc9cbb2bba9f5c6197484253eaa15af51382584`。
- `9de39061f908447f`：证物 `ev-006-xls-xor`，回执摘要 `9de39061f908447f3e9213ac7dfaeaa3cac442f17ba8696aa28d25a3e4025420`。

## 重放方式

```bash
python -m msoffcrypto.handover plan.json --replay --format json
```

重放只使用计划中嵌入的证据摘要和虚拟时钟，不读取原文件，也不使用真实时间。
