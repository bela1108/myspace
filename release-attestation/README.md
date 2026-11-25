# 发布包溯源派生说明（Release Attestation）

本目录回答客户问题：**发布包 `foo.tar.gz` 是由哪几份材料、经过哪些可披露
步骤装出来的，且该链路如何被独立复核。**

所有结论只来自已验证的 in-toto link 签名材料与 MATCH 规则证据；无法独立证明
的关系在报告中以边界（boundary）形式明确停下，不做断言。

## 目录结构

```
release-attestation/
+-- policy.json                  披露白名单（内部，定义可公开的产品/步骤/工件）
+-- public/                      可对外交付的自包含证据包
|   +-- attestation-report.json  派生报告（脱敏后的全部可公开结论）
|   +-- bundle-manifest.json     包内每个文件的 sha256 清单
|   +-- disclosed-keys.json      两个功能步骤的签名公钥（仅公钥）
|   +-- foo.tar.gz               发布包副本
|   +-- evidence/
|       +-- write-code.776a00e2.link   原始签名 link（逐字节复制）
|       +-- package.2f89b927.link      原始签名 link（逐字节复制）
+-- scripts/
|   +-- generate_report.py       从内部证据生成派生报告（内部运行）
|   +-- verify_report.py         客户侧独立复核器（只读 public/）
|   +-- fork_join_demo.py        分叉-汇合复核与断链定位演示
|   +-- upstream_crosscheck.py   参考实现全流程交叉核验（内部，不对外）
+-- internal-workdir/            内部交叉核验工作区与运行记录（不对外）
+-- demo-workdir/                分叉演示生成的隔离复核副本（演示产物）
```

## 可核验的链路（报告中的三条公开结论）

1. `create:write-code:foo.py` —— write-code 步骤产出 `foo.py`，
   sha256 = `74dc3727...02549`，该步骤未记录输入材料。
2. `match:package:foo.py` —— package 步骤消费的 `foo.py` 与 write-code
   步骤的产品 sha256 完全一致（由参考实现 `verify_match_rule` 重新推导）。
3. `create:package:foo.tar.gz` —— package 步骤产出发布包，
   sha256 = `52947cb7...4f355`，与交付的 `foo.tar.gz` 逐字节一致。

每条结论都带 `evidence` 字段，指向公开包内的具体 link 文件名；每份 link 在
`signed_materials` 中同时给出：

- `file_sha256`：签名文件整体摘要（可与包清单互验）；
- `canonical_payload_sha256`：被签名负载的规范 JSON 摘要；
- `signature_hex` 与 `signing_keyid`：原始签名材料的完整引用。

## 边界：在哪里停下

布局中的 `untar` 是 inspection（检查项），其规则只在验证者机器上当众执行，
签名材料中不存在它的 link。因此报告不主张任何关于 untar 结果的结论，只在
`boundaries` 中记录该项及其规则数量。GPG 与 DSSE 两个变体属于无关产品线/
包装通道，列入 `excluded_evidence`，绝不引用。内部路径、byproducts、
environment 等字段不出现在任何公开输出中。

## 客户如何复核（无需信任我方）

```bash
python scripts/verify_report.py public
```

复核器只读取 `public/` 与随包公钥，依次执行 11 项检查：包清单 tamper
evidence、link 签名验证、摘要比对、MATCH 引擎重放、发布包哈希核对。
退出码 0 表示全部通过；非 0 时输出逐项点名的失败位置。

也可用标准 CLI 单独核对本地发布包：

```bash
cd public && in-toto-match-products --link evidence/package.2f89b927.link --paths foo.tar.gz
```

## 分叉后再汇合的复核演示

```bash
python scripts/fork_join_demo.py
```

- 场景一（intact-bundle）：两个独立复核者各自拿到隔离的公开包副本，独立
  运行同一复核器（分叉），汇合后比对裁决，两边均为 PASS 且结论一致。
- 场景二（intermediate-link-removed）：从每个副本中拿掉中间证据
  `write-code.776a00e2.link`，两个复核者同时得到 FAIL，并精确报告链断在
  三处：清单缺失、link 缺失、MATCH 边 `write-code->package:foo.py` 无法
  重放。这说明拿掉中间证据后，链路断点可被独立定位，而不会被静默跳过。

## 内部前提的佐证

`scripts/upstream_crosscheck.py` 使用参考实现 `in_toto_verify` 对原始证据
跑完整流程（布局签名、link 阈值、CREATE/MATCH/ALLOW 规则、untar
inspection），结果为 PASS，运行记录保存在
`internal-workdir/run-records/`。该脚本与记录仅供内部留存，不属于公开包。
