# TUF 仓库端离线最小角色导出计划

本文件是面向维修合同复核场景的**离线导出计划**，并由可执行实现与一个带真实签名的
“小镜像”演示支撑。合同只要求审查组确认两个目标属于已批准的更新角色，因此不应把整个
镜像的角色元数据都发给对方。

- 实现入口：`offline_export_plan.py`（无第三方依赖即可做结构规划；`--verify-crypto`
  时使用环境内的 `tuf` / `securesystemslib` 做真实签名校验）
- 兼容入口：`solution.py`、`export_plan.py`、`offline_export.py`
- 小镜像与双场景：`tiny_mirror_demo.py`
- 自动化测试：`tests/test_offline_export_plan.py`（17 个用例，`unittest`/`pytest` 均可）
- 可交接样例：`examples/offline_export/`

---

## 1. 问题边界

输入只有三类，全部在仓库端离线读取：

1. **现有角色元数据**：一个 TUF 镜像目录（标准布局 `<mirror>/metadata/*.json`）。
2. **目标命中条件**：一个或多个目标路径，按 TUF 委托顺序解析到实际签署它的角色。
3. **调用者提供的材料可传递清单**（transferability manifest）：明确哪些材料可以离开仓库。

输出只有两样：

- **可交接的角色文件清单**：足以复核的最小、去重后的签名角色文件（可直接复制成交接包）。
- **无证明范围**：因为缺件或证明级别选择而**无法证明**的事项，逐条说明受阻材料。

不可接受的“变通”：

- 用**未签别名**（委托里的角色名指针、任何无签名副本，如 `root.alias`）顶替签名角色；
- 用**任意摘要**（调用者给的十六进制串、独立 `.sha256` 文件，甚至快照里的哈希）顶替
  缺失的签名角色或签名材料。摘要只能校验“已经持有的字节”，既不是角色元数据，也不是
  阈值签名，更不是信任锚。

规划器会把这类材料登记到 `rejected_substitutes`，且永远不会放进交接清单。

## 2. 小镜像结构（两个请求共用父角色段）

`tiny_mirror_demo.py` 每次生成全新 ed25519 密钥并真实签名，角色图为：

```
root -> timestamp -> snapshot -> targets -> parent -> update-a -> 目标一
                                                  \-> update-b -> 目标二
```

- 两个请求分别命中 `approved/repair-target-one.bin`（`update-a`）与
  `approved/repair-target-two.bin`（`update-b`），且都要求命中角色属于
  `approved_roles`。
- 共用父角色段：`root -> (timestamp -> snapshot) -> targets -> parent`。
  - `full` 级别下共用 5 个角色：`root, timestamp, snapshot, targets, parent`；
  - `membership` 级别下共用 3 个角色：`root, targets, parent`。
- 镜像还包含 `nightly.json`（无关角色，证明“不会导出整个镜像”），以及两个诱饵：
  `root.alias`（未签别名）和 `root.json.sha256`（`root.json` 的**真实**摘要，
  用来说明即使摘要正确也不能替代缺失的签名材料）。

## 3. 离线算法

对每个请求执行（实现见 `offline_export_plan.py`）：

1. `Mirror.load()` 只读加载 `metadata/*.json`，兼容普通文件名与
   `N.<role>.json` 一致快照文件名；不访问网络、不更新元数据。
2. `resolve_target()` 从顶层 `targets` 开始，按 `delegations.roles` 声明顺序做
   深度优先命中：支持 TUF 的分段 glob（`*` 不跨 `/`）与 `path_hash_prefixes`，
   并遵守 `terminating`。返回最小见证链与委托边。
3. 按证明级别汇总**必需角色**（多目标取并集）：
   - `membership`（默认，最贴合合同最小范围）：`root + targets + 委托链 + 命中角色`，
     可验证“目标由哪个已批准角色签署、该角色如何被委托/锚定到 root”；
   - `consistent`：额外需要 `snapshot`，绑定各角色版本/哈希；
   - `full` / `update`：再额外需要 `timestamp`，具备新鲜度/防回滚复核能力。
4. 对每个必需角色做材料闸门判定：
   - `file_absent`：镜像中没有该签名角色文件；
   - `not_transferable`：文件不在可传递清单（或被 `denied_materials` 显式排除）；
   - `signature_material_blocked`：载荷可给，但清单声明其签名材料不可传递；
   - `insufficient_signatures`：现有授权 keyid 上的有效签名数低于阈值；
   - `invalid_signature`：仅 `verify_crypto=True` 时，用 `tuf` 模型做真实密码学校验失败；
   - `ready`：材料可交接且（可选）签名验证通过。
   结构阈值检查默认阻断（`enforce_signatures=True`）；只做角色选择分析时可传
   `enforce_signatures=False`，此时签名不足只写入记录的 `signature_status` 与
   `warnings`，不影响选择结果。`verify_crypto=True` 会同时强制阈值与密码学校验。
5. 缺件角色生成 `MissingMaterial`，并把对应证明域加入 `unattested_scope`；任何必需
   材料不就绪，该请求每个目标都有一条 `end_to_end_attestation`（端到端结论不可证明）。
6. `evaluate_substitutes()` 拒绝调用者显式提供或在缺件角色旁自动发现的未签别名/摘要。
7. `plan_export()` 合并多个请求：角色集合取并集并去重，计算最长公共前缀
   `shared_roles`（共用父角色段），汇总缺件与无证明范围。

### 何时可合并

所有请求在所选证明级别下 `complete`（全部必需角色 `ready`、目标命中且角色获批准、
可选密码学校验通过）时：

- `status="ready"`、`mergeable=True`、`sufficient=True`；
- `handoff_files == certified_handoff_files`，即合并去重后的最小充分清单；
- 共用父角色只出现一次，分支角色各自保留。

### 何时只能报缺件

任一必需材料不就绪时：

- `status="incomplete"`、`mergeable=False`；
- `certified_handoff_files=[]`：**不存在**可声称“充分复核”的认证交接清单；
- `handoff_files` 仍列出当前物理上可传递的必需文件子集，但报告明确其不构成证明；
- `missing` 给出缺件与责任请求，`unattested_scope` 给出精确无证明范围；
- 若缺的是共享上层（如 `root`），两个目标同时失去端到端证明；若只缺某个分支角色，
  无证明范围只覆盖该分支目标，另一请求仍可独立成立。

## 4. 无证明范围的分类（`cause`）

- `missing_material`：缺件导致的证明空洞，会使方案不充分。作用域包括
  `trust_anchor`、`key_authorization`、`freshness`、`snapshot_consistency`、
  `top_level_delegation`、`delegation_authorization`、`target_membership`、
  `end_to_end_attestation` 等。
- `assurance_level_excluded`：选择 `membership`/`consistent` 级别时主动不纳入
  snapshot/timestamp，因此新鲜度/一致性属于已知的、非缺件性的无证明范围。
- `out_of_material_scope`：合同只要角色文件，目标制品字节不在导出范围内；交接的是
  签名目标元数据及其哈希，不包含目标文件本身（除非另行决定）。

## 5. 材料可传递清单格式

清单可以是纯字符串数组，也可以是对象：

```json
{
  "transferable_materials": [
    "metadata/root.json",
    "metadata/timestamp.json",
    "*",
    { "path": "metadata/root.json", "signatures": false }
  ],
  "denied_materials": ["metadata/root.json"],
  "block_signatures_for": ["root"],
  "substitutes": [
    { "role": "root", "unsigned_alias": "metadata/root.alias",
      "digests": ["<hex>", { "ref": "metadata/root.json.sha256" }] }
  ]
}
```

- 路径支持仓库相对路径（`metadata/root.json`）、裸文件名（`root.json`）、
  `*` 与目录通配 `metadata/*`。
- `denied_materials` / `{"transferable": false}` 优先生效。
- `{"path": ..., "signatures": false}` 精确表达“载荷可给、签名材料不可给”。
- 默认最小权限：清单为空即什么都不可传递，全部必需角色会报缺件。

## 6. 返回结构（`ExportPlan`，可 `.to_json()`）

| 字段 | 含义 |
| --- | --- |
| `status` / `mergeable` / `sufficient` | `ready`/可合并/充分，或 `incomplete`/不可合并 |
| `minimal_roles` | 合并后的最小必需角色名（含暂时缺件者） |
| `shared_roles` | 各请求角色链的最长公共前缀（共用父角色段） |
| `role_records` | 每个必需角色的文件引用、状态、sha256、大小、所属请求 |
| `required_files` | 最小集合对应的全部文件引用（不考虑可传递性） |
| `handoff_files` | 其中当前 `ready`、可物理交接的文件引用 |
| `certified_handoff_files` | 充分时等于 `handoff_files`；不充分时为 `[]` |
| `missing` | 缺件：角色、引用、状态码、原因、责任请求/目标 |
| `unattested_scope` | 无证明范围条目（作用域、成因、受阻材料） |
| `rejected_substitutes` | 被拒绝的未签别名/任意摘要及原因 |
| `excluded_roles` | 镜像磁盘上存在但最小集合不需要的角色 |
| `requests` | 每请求的链、解析结果、记录与缺件明细 |

## 7. 实际演示结果

运行：

```bash
.venv/bin/python tiny_mirror_demo.py     # 重建 examples/offline_export 并跑断言
.venv/bin/python solution.py             # 等价：直接运行双场景演示
```

场景一（`manifest-merge.json`，`full`，真实签名校验通过）：

- `minimal_roles = [root, timestamp, snapshot, targets, parent, update-a, update-b]`
- `shared_roles = [root, timestamp, snapshot, targets, parent]`
- 7 个文件全部 `ready`，`certified_handoff_files` 即这 7 项；`nightly` 被排除。
- `membership` 级别进一步缩小为 5 个文件
  `[root, targets, parent, update-a, update-b]`，并显式保留
  snapshot/freshness 两项无证明范围。

场景二（`manifest-missing-root.json`：允许 `*` 但排除 `metadata/root.json`）：

- `root` 为 `not_transferable`，`mergeable=False`，`certified_handoff_files=[]`；
- 拒绝 `metadata/root.alias`（`rejected_unsigned_alias`）与
  `metadata/root.json.sha256`（`rejected_arbitrary_digest`）；
- 无证明范围：共享的 `trust_anchor`、`key_authorization` 各 1 条，
  以及两个目标各自的 `end_to_end_attestation`。

另有 `manifest-signature-blocked.json` 演示更精确的
`signature_material_blocked`（root 载荷可给、签名材料不可给），结论同样是不可合并。

生成的交接样例：

- `examples/offline_export/handoff-merged-full/`：充分的 7 文件交接包
  （`export-plan.json`、`REPORT.md`、`SHA256SUMS`、`role-files/metadata/*.json`）；
- `examples/offline_export/handoff-merged-membership/`：5 文件最小 membership 包；
- `examples/offline_export/report-missing-root/`：缺件报告包（含中文 `REPORT.zh.md`）。

## 8. CLI

```bash
python offline_export_plan.py plan \
  --mirror examples/offline_export/tiny-mirror \
  --requests examples/offline_export/requests.json \
  --manifest examples/offline_export/manifest-merge.json \
  --assurance full --verify-crypto \
  --out ./handoff-out --strict

python offline_export_plan.py demo     # 运行小镜像双场景
```

`--strict` 在方案不充分时以退出码 `3` 结束，便于仓库端流水线卡口。

## 9. 验证

```bash
python -m unittest tests.test_offline_export_plan -v
```

17 个用例覆盖：双请求合并与去重、membership/full 级别、无关角色排除、
root 缺件、签名材料阻断、未签别名/摘要拒绝、单分支缺件的精确范围、
上游 `tests/repository_data/repository` 真实 RSA/ed25519 夹具的密码学验证、
bundle 写出、字典式访问与 CLI strict 退出码。

两种运行器均已验证：`python -m unittest tests.test_offline_export_plan` 与
`.venv/bin/python -m pytest tests/test_offline_export_plan.py`（17 passed）。
根目录 `conftest.py` 仅在沙箱对工作区上级目录返回 `PermissionError` 时把
`Path.is_file()` 降级为 `False`，从而让 pytest 收集继续；在普通 CI/开发机上该垫片
完全惰性。仓库 `tox.ini` 原生使用 `python -m unittest`。注意环境若未安装
`requirements/test.txt` 中的 `freezegun`，既有的
`tests/test_updater_top_level_update.py` 会在导入期报错，与本改动无关。
