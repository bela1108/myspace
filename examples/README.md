# 离线用章对账（基于 securesystemslib）

本目录提供一套完全离线的用章对账工具，面向纸面工单 + 电子归档的场景：

- 签发员各自持有授权签章编号段；请假时由同组代理接手上半段/下半段。
- 归档服务只保留签名，对账时用 securesystemslib 的 Ed25519 公钥离线验真。
- 编号在不同声明类别间允许重复；同一类别内一个已结算编号只能归到一次使用。

## 目录结构

- `seal_reconciliation/models.py`：授权区间、签章声明、来源定位与序列化。
- `seal_reconciliation/signing.py`：材料摘要（sha256）与离线签发声明。
- `seal_reconciliation/reconciler.py`：验签、去重、碰撞冻结、授权区间核对。
- `seal_reconciliation/report.py`：财务页、安全审核页与 JSON 报告渲染。
- `examples/offline_seal_reconciliation.py`：端到端演示，生成归档与报告。
- `tests/test_seal_reconciliation.py`：覆盖全部业务规则的 unittest。

## 对账规则

1. **先验签后入账**：公钥注册表中不存在的 keyid 或验签失败的声明进入
   `invalid_signatures`，不参与结算。
2. **备份不多算**：签名负载不含归档位置，同一份材料在备份中再次出现时，
   规范负载与材料摘要完全一致，合并为一次使用，但两处来源定位都保留。
3. **同编号不同内容即冻结**：同一类别内同一编号出现多个材料摘要时，
   编号列入 `freeze_candidates`，并附上每处原始签章定位与涉及密钥。
4. **跨类别编号可重复**：去重键是 `(category, seal_number)`，
   不同类别各自独立结算。
5. **授权区间核对**：入账编号必须落在该签发员（按 keyid 绑定）的区间内，
   否则进入 `out_of_range`；请假代理段通过相邻的两条授权表达。

## 运行方式

```bash
.venv/bin/python examples/offline_seal_reconciliation.py
```

生成物写入 `demo_output/`：

- `archive_bundle.json`：授权账本、公钥注册表、签章声明的离线归档包。
- `finance_page.md`：给财务的授权区间与已结算编号（含零消费区间）。
- `security_page.md`：给安全审核的待冻结编号、验签失败与区间外用章。
- `reconciliation_report.json`：供下游系统消费的机读报告。

运行测试：

```bash
.venv/bin/python -m unittest tests.test_seal_reconciliation -v
```
