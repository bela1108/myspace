# LEGAL-HOLD-WEEK-47-SAMPLE 离线处置解除清单

- 审查基准日：2026-11-27T02:00:00+00:00
- 清单生成时间：2026-11-26T19:23:08.750912+00:00
- 审查人：DFIR on-call
- 判定标准：SEC-EP-WIN-2026-11 endpoint security policy; offline plugin evidence TTL 7 days
- 设备数：**2**；可解除：**1**；明确保全：**1**；待补材料：**0**；跨设备重复值组：**3**

## 一、释放清单

| 设备 | 批次 | 策略/版本 | 批准依据位置 | 批准时间 | 证据到期 | 重复值组 |
| --- | --- | --- | --- | --- | --- | --- |
| PC-RELEASE-02 | first-batch | EP-WIN-2026-11 / 2026.11.2 | independent_approvals.sample.json#$.records[0]（sha256:72dc8d29d8f1）；记录 APR-RELEASE-002；independent-legal-register/2026-W47.md#APR-RELEASE-002 | 2026-11-24T01:40:00+00:00 | 2026-12-03T01:30:00+00:00 | DUP-001, DUP-002, DUP-003 |

## 二、逐台处置结论

### PC-RELEASE-02 — 可解除保全

- 批次：first-batch
- 处置决定：**解除保全**
- 判定事实：最终插件值均符合版本化基线，来回覆盖已按时间线还原到最终状态。
- 策略：EP-WIN-2026-11；所见版本：2026.11.2；最终版本：2026.11.2
- 批准依据：APR-RELEASE-002，independent_approvals.sample.json#$.records[0]（sha256:72dc8d29d8f1）
  - 条款/档案位置：independent-legal-register/2026-W47.md#APR-RELEASE-002
  - 同意时间：2026-11-24T01:40:00+00:00；批准人：Legal Custodian

| 事件 | 时间 | 类型 | 指标 | 版本 | 值 | 合规 | 来源 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| EVT-001 | 2026-11-21T01:00:00+00:00 | apply | execution_policy:ExecutionPolicy | 2026.11.2 | AllSigned | 是 | case_manifest.sample.json#$.devices[0].observations[0]（sha256:148aaadcab1d） |
| EVT-002 | 2026-11-22T02:00:00+00:00 | overwrite | execution_policy:ExecutionPolicy | 2026.11.2 | RemoteSigned | 否 | case_manifest.sample.json#$.devices[0].observations[1]（sha256:148aaadcab1d） |
| EVT-003 | 2026-11-23T07:00:00+00:00 | apply | execution_policy:ExecutionPolicy | 2026.11.2 | AllSigned | 是 | case_manifest.sample.json#$.devices[0].observations[2]（sha256:148aaadcab1d） |
| EVT-004 | 2026-11-23T07:05:00+00:00 | initial | baseline_hash | 2026.11.2 | sha256:9f2c7d41b7a8 | 是 | case_manifest.sample.json#$.devices[0].observations[3]（sha256:148aaadcab1d） |

### PC-ROLLBACK-01 — 继续保全（已有回滚/不合规证据）

- 批次：second-batch
- 处置决定：**继续保全**
- 判定事实：最后一次状态变更是回滚，且其后没有完整、合规的插件证据证明已重新落地。
- 判定事实：最后回滚事件 EVT-003 发生于 2026-11-26T12:15:00+00:00，回滚后缺少完整合规证据；来源 case_manifest.sample.json#$.devices[1].observations[2]。
- 原因代码：APPROVAL_BEFORE_LAST_CHANGE, APPROVAL_VERSION_MISMATCH, FINAL_STATE_NONCOMPLIANT, LAST_ROLLBACK_WITHOUT_RECOVERY, MISSING_VALID_RELEASE_APPROVAL
- 策略：EP-WIN-2026-11；所见版本：2026.11.1, 2026.11.2；最终版本：2026.11.1
- 最后回滚：EVT-003 / 2026-11-26T12:15:00+00:00 / 值 RemoteSigned；来源 case_manifest.sample.json#$.devices[1].observations[2]（sha256:148aaadcab1d）
- 批准依据：未找到可匹配最终版本和最后变更时间的有效独立批准。
- 已见但不能作为依据的批准/档案：
  - APR-STALE-001 independent_approvals.sample.json#$.records[1]（sha256:72dc8d29d8f1）；问题：APPROVAL_VERSION_MISMATCH, APPROVAL_BEFORE_LAST_CHANGE

| 事件 | 时间 | 类型 | 指标 | 版本 | 值 | 合规 | 来源 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| EVT-001 | 2026-11-24T01:00:00+00:00 | apply | execution_policy:ExecutionPolicy | 2026.11.2 | AllSigned | 是 | case_manifest.sample.json#$.devices[1].observations[0]（sha256:148aaadcab1d） |
| EVT-002 | 2026-11-24T01:05:00+00:00 | initial | baseline_hash | 2026.11.2 | sha256:9f2c7d41b7a8 | 是 | case_manifest.sample.json#$.devices[1].observations[1]（sha256:148aaadcab1d） |
| EVT-003 | 2026-11-26T12:15:00+00:00 | rollback | execution_policy:ExecutionPolicy | 2026.11.1 | RemoteSigned | 否 | case_manifest.sample.json#$.devices[1].observations[2]（sha256:148aaadcab1d） |

**需要补充的具体材料**

| 代码 | 材料 | 原因/验证点 | 建议命令 |
| --- | --- | --- | --- |
| MISSING_VALID_RELEASE_APPROVAL | 独立档案中设备、policy_id、policy_version、批准时间、生效时间、批准人和条款定位齐全的解除保全记录 | 未找到可匹配最终策略状态且在最后变更之后作出的有效批准。 已见档案问题：APPROVAL_BEFORE_LAST_CHANGE, APPROVAL_VERSION_MISMATCH | — |

## 三、不同设备间重复值

| 组 | 策略/指标 | 值摘要 | 值 SHA-256 | 设备 | 出现次数 | 说明 |
| --- | --- | --- | --- | --- | --- | --- |
| DUP-001 | EP-WIN-2026-11 / baseline_hash | sha256:9f2c7d41b7a8 | 4b7c54e820076b4ce2bafeff0a71b29626d23588a4f30b598481206cb29c859e | PC-RELEASE-02, PC-ROLLBACK-01 | 2 | 重复值只合并证据指纹，不合并设备结论或批准 |
| DUP-002 | EP-WIN-2026-11 / execution_policy:ExecutionPolicy | AllSigned | 3333b1b555215c4950f26b0c408d5b7e42ca4e1699cc3cd12e7d48d397934497 | PC-RELEASE-02, PC-ROLLBACK-01 | 3 | 重复值只合并证据指纹，不合并设备结论或批准 |
| DUP-003 | EP-WIN-2026-11 / execution_policy:ExecutionPolicy | RemoteSigned | 8ea2639de830d9f8d72b34ab8f82796465622e3903f05295ea73e31032eca206 | PC-RELEASE-02, PC-ROLLBACK-01 | 2 | 重复值只合并证据指纹，不合并设备结论或批准 |

## 四、来源文件完整性

| 文件 | SHA-256 |
| --- | --- |
| independent_approvals.sample.json | 72dc8d29d8f1e896e6f9368fb45d8c25bbbee58c8b719330c8b2318463819634 |
| case_manifest.sample.json | 148aaadcab1d8303c4346298488047f0b68e43560b0f49678e44e47028c06ddb |

> 本清单由 regipy.disposition 离线生成；注册表解析来自 regipy，批准档案仅作来源关联，不替代原件核验。