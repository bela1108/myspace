# evidence_chain — 离线托管制品的证据链审核

合规场景：供应商为一批**离线托管制品**（offline managed artifacts，.NET PE
文件）**补交只读元数据**。本工具对补交记录做只读审核，并交付可按**原发布单**
接续的**证物目录**。审核全程只读：归档内的任何文件都不会被写入。

## 术语映射

| 合规术语 | 实现 |
| --- | --- |
| 代际标识 | CLR 元数据 Module 表的 \`Mvid\`，用 dnfile 现有堆解析消费（\`Name\` 经 #Strings 堆、\`Mvid\` 经 #GUID 堆），见 \`evidence_chain/generation.py\` |
| 正常样本 | 能被 dnfile 正常解析并给出 Mvid 的 .NET 模块；否则记为 \`indeterminate\` |
| 外置封存链 | 原发布单（release manifest）及其认定的各组件代际，保存于二进制之外 |
| 已认定代际 | 原发布单中为某组件登记的 \`mvid\`（规范化为小写 UUID 后比较） |
| 证物目录 | 审核输出的 \`catalog\`，按原发布单顺序接续编号 |

## 输入

原发布单（JSON）：

\`\`\`json
{
  "release": "REL-2026-0042",
  "items": [
    {"seq": 1, "component": "Alpha.Core.dll",
     "location": "artifacts/Alpha.Core.dll", "mvid": "11111111-...", "note": "..."}
  ]
}
\`\`\`

补交记录（JSON，只读元数据）：

\`\`\`json
{
  "submissions": [
    {"record_id": "SUP-001", "component": "Alpha.Core.dll",
     "location": "incoming/Alpha.Core.dll", "note": "补充签名说明"}
  ]
}
\`\`\`

\`location\` 相对 \`--archive-root\` 解析（或使用绝对路径）。

## 审核规则

1. **旧记录审核**：逐条检查原发布单引用的外部文件是否仍对应原位置
   （\`location_status: intact|missing\`），并比对现存文件的代际是否仍为已认定
   代际（\`generation_status: confirmed|diverged|unreadable\`）。
2. **补交记录分类**（沿外置封存链）：
   - \`supplement\` — 在同一已认定代际上补齐说明：观测 Mvid 等于已认定代际，**接受**。
   - \`replacement\` — 跨代替换：观测 Mvid 与已认定代际不一致，**不接受**。
   - \`missing_witness\` — 仍缺关联见证：引用的外部文件不在原位置
     （\`artifact-absent\`），或组件在链上没有已认定代际可依附
     （\`no-recognized-generation\`），**不接受**。
   - \`indeterminate\` — 样本无法正常解析，代际无法认定，**不接受**。
   - \`duplicate\` — 同名组件已有在先的同代补齐被接受，本件被取代，**不接受**。
3. **同名去重**：两个新组件同名且分别附独立记录时，只接受确认代际接续
   （Mvid 与已认定代际一致）的那一件；同名跨代件判 \`replacement\`，同名的
   后续同代件判 \`duplicate\`。
4. **证物目录接续**：目录先按原发布单的 \`seq\` 顺序列出全部发布项（附审核
   状态），被接受的补交件按提交顺序追加，\`seq\` 从原发布单最大序号起接续。

## 用法

\`\`\`bash
python -m evidence_chain audit \\
    --manifest release_manifest.json \\
    --records supplements.json \\
    --archive-root /path/to/offline/archive \\
    --output evidence_catalog.json
\`\`\`

省略 \`--output\` 时目录 JSON 打印到标准输出。

## 测试与演示样本

\`evidence_chain/sample_builder.py\` 离线合成最小 .NET PE 样本（CLR 头 +
#~/#Strings/#US/#GUID/#Blob），供测试与演示生成"正常样本"，无需提交二进制
文件。运行测试：

\`\`\`bash
python -m pytest tests/test_evidence_chain.py
\`\`\`
