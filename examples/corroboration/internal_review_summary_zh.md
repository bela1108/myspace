# 内部复核结果（中文摘要）

**结论：`conflict`**

**分类：内部复核，不作为对外鉴定意见。**

## 一、复核结论

- `EXP-A`（`NTUSER.DAT`）与 `EXP-B`（`NTUSER_modified.DAT`）共享同一个 hive 创建 GUID，7 个内容锚点中有 6 个的键路径、最后写入时间和值摘要完全一致，包括 `Shell Folders` 与 `User Shell Folders`。
- `EXP-B` 的采样来源明确登记 `derived_from = EXP-A`，属于故障盘克隆/派生件。克隆复制出的相同内容不能作为独立佐证，因此 `EXP-A` 与 `EXP-B` 的判定是 `missing_evidence`，不是 `same_subject`。
- `EXP-C`（`NTUSER_with_winscp.DAT`）独立解析为 `tony` / `C:\Users\tony`，与 `EXP-A`、`EXP-B` 的 `vibranium` / `C:\Users\vibranium` 不同。因此 `EXP-A` 与 `EXP-C`、`EXP-B` 与 `EXP-C` 都是 `conflict`。
- `EXP-A/B` 与 `EXP-C` 的卷字段完全不同，按“不同卷”处理，不因卷不同本身判冲突；A-C、B-C 的冲突来自 `account_name` 与 `profile_path` 的实际取值不同。
- 调查记录声称三份导出由同一用户留下；按当前证据，这一整体结论为 `conflict`。可以支持的是 `EXP-A` 与 `EXP-B` 属于同一 `vibranium` 主体，但二者不是独立来源；`EXP-C` 指向另一主体。

## 二、证据分层

| 层级 | 本案例中的内容 | 复核作用 |
| --- | --- | --- |
| 采样来源 | `SRC-ORIGINAL`、`SRC-CLONE`（`derived_from=EXP-A`）、`SRC-INDEPENDENT` | 判断独立谱系；克隆/派生只算一个来源 |
| 卷身份 | `EXP-A/B` 同为 `1A2B3C4D` / `0xA1B2C3D4`；`EXP-C` 为 `5E6F7A8B` / `0xB2C3D4E5` | 把导出归到卷；卷相同不等于用户相同，克隆也会保留卷身份 |
| 可核验名称关联 | `profile_path` 与 `account_name`，由 regipy 读取 `Shell Folders` 并与声明值核对 | 作为主体身份的主证据 |
| 内容锚点 | 两个键路径/时间/值摘要一致 | 只证明内容相同/复制关系，不单独证明主体 |

`EXP-A` 与 `EXP-B` 的 `Shell Folders`、`User Shell Folders` 等锚点完全一致，正是故障盘克隆的预期表现；复核器会把这种一致性记录为内容锚点，并在克隆谱系下明确标注“不可作为独立佐证”。

## 三、插件证据边界

本次运行了 `typed_urls`、`typed_paths`、`user_assist`、`ntuser_persistence` 等分析插件。插件输出统一标记为：

- `origin = plugin`
- `role = supplemental`
- `used_as_source = false`
- `can_establish_identity = false`

`EXP-A` 与 `EXP-B` 的部分插件摘要相同，可以作为活动层面的补充证据；但它们没有被提升为原始来源，也没有把 `missing_evidence` 改成 `same_subject`。

## 四、替换克隆件身份记录后的失效关联

### 4.1 替换克隆件的卷身份记录

替换 `EXP-B:volume` 的 `volume_serial`、`disk_signature`、`disk_guid` 后：

- 失效：`link:volume:EXP-A:EXP-B`
- 保留：`link:source:EXP-A:EXP-B`、`link:clone:EXP-A:EXP-B`、`link:hive_identity:EXP-A:EXP-B`、两条名称关联、全部相同内容锚点
- 克隆对仍为 `missing_evidence`，因为独立性由采样来源/克隆谱系决定，不由卷身份记录单独决定

### 4.2 替换克隆件的名称关联记录

替换 `EXP-B:profile:c-users-vibranium` 后：

- 失效：`link:name:EXP-A:EXP-B:account-name-vibranium`、`link:name:EXP-A:EXP-B:profile-path-c-users-vibranium`
- 保留：卷身份、采样来源、克隆谱系、hive 身份和内容锚点
- `EXP-A|EXP-B` 从 `missing_evidence` 变为 `conflict`

这说明每条关联都显式依赖具体身份记录，替换一项记录后可以直接看出哪些关联失效、哪些仍然成立。

## 五、限制

- 本仓库样例中的采样来源和卷身份是带 `fixture=true` 的合成元数据，不是真实案卷事实；正式使用前必须替换为扣押/镜像/采集记录。
- hive 创建 GUID 不是卷序列号，不能单独用于认定使用者。
- 相同键路径和时间只证明内容一致；克隆场景下不能作为两次独立使用的证据。
- 插件值是派生观察，只能补充，不能替代原始来源。
- 缺少采样来源、卷身份或可核验名称关联时，结论应为 `missing_evidence`，不应推断为 `same_subject`。

## 六、对应产物

- `three_ntuser_case.json`：三份导出、采样来源、卷身份和名称关联的输入。
- `three_ntuser_review.json` / `three_ntuser_review.md`：机器可读与可读版内部复核。
- `clone_volume_replacement.json` / `.md`：替换克隆件卷身份记录后的失效/保留关联。
- `clone_name_replacement.json` / `.md`：替换克隆件名称关联记录后的失效/保留关联。
- `synthetic_same_subject_review.md`：非证据性的 `same_subject` 分支演示。
