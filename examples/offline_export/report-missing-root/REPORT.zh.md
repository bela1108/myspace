# 离线角色导出报告

- 镜像：`/Users/bill/领域专项项目/state/ds-approved-20261124/myspace/workspaces/ds20261122-myspace-defpy-024/examples/offline_export/tiny-mirror`
- 证明级别：`full`
- 状态：**incomplete**（可合并=False，充分=False）
- 共用父角色段：`root` → `timestamp` → `snapshot` → `targets` → `parent`
- 最小角色集合：`root` → `timestamp` → `snapshot` → `targets` → `parent` → `update-a` → `update-b`

## 可交接角色文件清单

当前**不存在**充分的认证交接清单（`certified_handoff_files` 为空）；下列为物理上可传递但尚不足以完成证明的子集：

| 角色 | 文件 | 状态 | SHA256 | 请求 |
| --- | --- | --- | --- | --- |
| `root` | `metadata/root.json` | `not_transferable` | `a3a59ce8491e2416…` | repair-review-one, repair-review-two |
| `timestamp` | `metadata/timestamp.json` | `ready` | `972e1828b7085d80…` | repair-review-one, repair-review-two |
| `snapshot` | `metadata/snapshot.json` | `ready` | `5e3999437310c315…` | repair-review-one, repair-review-two |
| `targets` | `metadata/targets.json` | `ready` | `a1ff0b0af83bde22…` | repair-review-one, repair-review-two |
| `parent` | `metadata/parent.json` | `ready` | `c17474a5539448ab…` | repair-review-one, repair-review-two |
| `update-a` | `metadata/update-a.json` | `ready` | `bb71017f4e3cdca3…` | repair-review-one |
| `update-b` | `metadata/update-b.json` | `ready` | `579993fdbe857ca9…` | repair-review-two |

## 缺件（不得用别名/摘要掩盖）

- `not_transferable` 角色 `root` 材料 `metadata/root.json`：role file is not on the caller-provided transferability manifest（请求：repair-review-one, repair-review-two）

## 已拒绝的替代材料

- `rejected_unsigned_alias` `metadata/root.alias`（角色 `root`）：File 'root.alias' is an unsigned alias for 'root'; it carries no threshold signatures and cannot fill the missing material.
- `rejected_arbitrary_digest` `metadata/root.json.sha256`（角色 `root`）：Standalone digest file cannot substitute for the missing signed root role material.

## 无证明范围

- [`missing_material`] `trust_anchor`：root anchors authorized keys and thresholds；受阻材料 ['metadata/root.json']
- [`missing_material`] `key_authorization`：without root, authorization of every top-level role key is unanchored；受阻材料 ['metadata/root.json']
- [`missing_material`] `end_to_end_attestation` 目标 `approved/repair-target-one.bin`：target membership in an approved role cannot be independently re-verified with the delivered materials；受阻材料 ['metadata/root.json']
- [`out_of_material_scope`] `target_artifact_bytes`：target files themselves are outside the role-file export; only signed target metadata/hashes are handed off
- [`missing_material`] `end_to_end_attestation` 目标 `approved/repair-target-two.bin`：target membership in an approved role cannot be independently re-verified with the delivered materials；受阻材料 ['metadata/root.json']

## 已排除的镜像内无关角色

`nightly`
