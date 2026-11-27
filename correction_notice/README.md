# 部分签收驱动的更正通知（STIX 2.1）

## 场景

原通报（STIX report）针对同一个对象发布了两部分内容：

- section-a：后续发生改动、需要发更正单的部分。
- section-b：受禁止披露限制、必须继续留存限制的部分。

各接收方只签收了实际收到的段落。签收记录是本地伪造的
x-delivery-receipt 自定义 SDO，仅来自本地数据，不读取任何外部源。
随附的解释说明（note）带有 x_valid_until 到期时间；到期处理更正时：

1. 只有本地收单显示签收过 section-a 的接收方，才进入更正单投递范围。
2. 其余接收方不发更正单，并由同一份部分签收清单给出可追溯的原因。
3. section-b 的禁止披露限制（marking-definition 加 granular marking）原样保留。
4. 解释说明生成新版本，保留原到期时间并记录 x_explanation_state=extended
   的延期状态。

## 模块

- custom_types.py：注册 x-delivery-receipt（本地假收单）与
  x-recipient-decision（每个接收方的纳入/排除审计记录）。
- fixtures.py：确定性构造历史 bundle，含通报、Indicator（两部分内容）、
  限制标记、解释说明和三份本地假收单。
- processor.py：从 MemoryStore 读取 STIX 历史，按收单判定范围，
  用 new_version 生成更正后的 Indicator/Report/Note，并输出决策对象。
- cli.py：端到端入口，写出历史 bundle 与更正结果 bundle。

## 接收方判定规则

| 接收方 | 收单 x_signed_sections | 决定 | 原因 |
| --- | --- | --- | --- |
| Alpha | [section-a] | included | signed-changed-section |
| Bravo | [section-b] | excluded | missing-changed-section-signature |
| Charlie | [section:none]，x_signed=false | excluded | no-signature-on-file |

STIX 禁止空列表属性，因此“未签收任何段落”用哨兵值 section:none 显式表达。

## 运行

    python -m correction_notice.cli --history-out history.json --out correction.json
    python -m pytest correction_notice/tests/
