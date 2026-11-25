# 离线角色导出报告

- 镜像：`/Users/bill/领域专项项目/state/ds-approved-20261124/myspace/workspaces/ds20261122-myspace-defpy-024/examples/offline_export/tiny-mirror`
- 证明级别：`full`
- 状态：**ready**（可合并=True，充分=True）
- 共用父角色段：`root` → `timestamp` → `snapshot` → `targets` → `parent`
- 最小角色集合：`root` → `timestamp` → `snapshot` → `targets` → `parent` → `update-a` → `update-b`

## 可交接角色文件清单

以下文件构成充分的最小复核材料（合并去重后）：

| 角色 | 文件 | 状态 | SHA256 | 请求 |
| --- | --- | --- | --- | --- |
| `root` | `metadata/root.json` | `ready` | `a3a59ce8491e2416…` | repair-review-one, repair-review-two |
| `timestamp` | `metadata/timestamp.json` | `ready` | `972e1828b7085d80…` | repair-review-one, repair-review-two |
| `snapshot` | `metadata/snapshot.json` | `ready` | `5e3999437310c315…` | repair-review-one, repair-review-two |
| `targets` | `metadata/targets.json` | `ready` | `a1ff0b0af83bde22…` | repair-review-one, repair-review-two |
| `parent` | `metadata/parent.json` | `ready` | `c17474a5539448ab…` | repair-review-one, repair-review-two |
| `update-a` | `metadata/update-a.json` | `ready` | `bb71017f4e3cdca3…` | repair-review-one |
| `update-b` | `metadata/update-b.json` | `ready` | `579993fdbe857ca9…` | repair-review-two |

## 无证明范围

- [`out_of_material_scope`] `target_artifact_bytes`：target files themselves are outside the role-file export; only signed target metadata/hashes are handed off

## 已排除的镜像内无关角色

`nightly`
