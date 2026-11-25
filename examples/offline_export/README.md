# 离线最小角色导出：小镜像演示

这个目录由 `tiny_mirror_demo.py` 生成并校验，演示维修合同场景下两个请求何时可以
合并导出、何时只能上报缺件。完整设计见仓库根目录的 `OFFLINE_EXPORT_PLAN.md`。

## 重新生成与自检

```bash
python tiny_mirror_demo.py
# 或
python solution.py
```

脚本会重建 `tiny-mirror/`（全新 ed25519 密钥、真实签名），写入清单与请求，
运行两组断言，并刷新下面的交接产物。

## 角色图

```
root -> timestamp -> snapshot -> targets -> parent -> update-a -> approved/repair-target-one.bin
                                                  \-> update-b -> approved/repair-target-two.bin
```

- 两个请求共用 `root, timestamp, snapshot, targets, parent`（full 证明级别）。
- `nightly.json` 是无关角色，任何最小清单都不包含它。
- `tiny-mirror/metadata/root.alias` 是未签别名诱饵。
- `tiny-mirror/metadata/root.json.sha256` 是 `root.json` 的真实摘要诱饵：
  即使摘要正确，也不能替代缺失的签名 root 材料。

## 清单

- `requests.json`：两个目标命中条件与 `approved_roles`。
- `manifest-merge.json`：只放行 full 级别所需的 7 个角色文件。
- `manifest-allow-all.json`：放行 `*`，用于证明规划器仍会排除 `nightly`。
- `manifest-missing-root.json`：放行一切但排除 `metadata/root.json`。
- `manifest-signature-blocked.json`：root 载荷可给、签名材料不可给。

## 产物

- `handoff-merged-full/`：可合并场景的充分交接包（7 个角色文件 + 计划 JSON + 报告）。
- `handoff-merged-membership/`：最贴合合同最小范围的 membership 包（5 个角色文件）。
- `report-missing-root/`：缺件场景。`certified_handoff_files` 为空，
  `export-plan.json` / `REPORT.md` / `REPORT.zh.md` 给出缺件、被拒绝的别名/摘要与
  无证明范围；`role-files/` 只是物理可传递但不构成充分证明的子集。
