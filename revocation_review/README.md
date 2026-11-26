# 离线吊销证物审阅

这个目录用一个 281 B 的本地 CRL、一个外层 CMS 回执和两把 Ed25519 夹具密钥，演示如何把“外层封存覆盖了哪些字节”和“撤销对象自身由谁签发”分开。模型只读字节、只做离线验签，不执行任何夹具程序，也不联网。

## 核心区分

- 外层封存：CMS `SignedData` 的 `SignerInfo.signature` 直接覆盖 `signed_attrs` 的去标记 SET 编码；归档中看到的 `[0]` 隐式包装在验签前还原为 `SET(0x31)`。
- 附件：`adobe_revocation_info_archival` 是 signed attribute，`RevocationInfoArchival` 的 `crl`、`ocsp`、`other_rev_info` 三个分支分别承载不同对象；`AdobeArchiveRevInfo` 只有 `version`，不承载附件。
- 原发行证明：CRL 的 `CertificateList.signature` 只覆盖 `tbs_cert_list`，不覆盖外层 CMS，也不覆盖自身的 `signature_algorithm` 和 `signature` 值。
- 外层封存有效并不等于 CRL 有效：夹具里的 `tampered-attachment` 场景故意让外层签名覆盖被篡改的 CRL；外层仍然 `VALID`，内层发行签名必然 `INVALID`。

## 证据层级

| 层级 | 含义 |
| --- | --- |
| `T0` | 没有可用外层回执，也没有附件字节。 |
| `T1` | 外层回执有效，但没有实际对象字节；只能证明提交过某个摘要承诺。 |
| `T2` | 实际对象字节存在且与回执摘要一致；外层封存覆盖字节，但未完成原发行验签。 |
| `T3` | 对象字节存在，并由独立发行者密钥验证了对象自身签名。 |
| `S1` | 源码命题；引用行已离线核对，但不与归档层级互换。 |
| `S0` | 引用行或缺席检查失配。 |

## 场景

| 场景 | 附件状态 | 说明 |
| --- | --- | --- |
| `outer-only` | `outer_receipt_only` | 只有 `other_rev_info` 摘要承诺，没有对象字节，也不声明附件路径。 |
| `missing-attachment` | `missing` | 声明了 `attachments/revocation.crl.der`，但文件不存在；不能改写成“外层回执已确认附件”。 |
| `attachment-unverified` | `present` | CRL 在归档内且摘要一致，但未提供发行者公钥，最高到 `T2`。 |
| `tampered-attachment` | `present` | 外层签名覆盖被篡改的 CRL；摘要不一致且内层签名失败，保持 `T1`。 |
| `issuance-verified` | `present` | 外层封存、附件摘要和发行者 Ed25519 验签都通过，只有 `REV-001` 升到 `T3`。 |

## 产物

- `fixtures/`：确定性生成的密钥、CRL、外层归档和各场景 manifest；同一份源码重复构建应得到逐字节相同的 DER。
- `out/REVIEW_REPORT.md`：人工可读报告，含场景对照、字节偏移、补件前后差异、引用表和边界。
- `out/report.json`：机器可读报告，含每个场景的覆盖对象、层级和引用核对结果。
- `out/verification_ledger.json`：独立验签账；记录签名输入 SHA-256、归档偏移、密钥 ID/指纹和结果，可用 `verify-ledger` 重算。

## 复跑

```sh
.venv/bin/python -m revocation_review.review build-fixtures
.venv/bin/python -m revocation_review.review report
.venv/bin/python -m revocation_review.review verify-ledger
.venv/bin/python -m unittest tests.test_revocation_review -v
```

## 替换真实档案

manifest 的结构是：

```json
{
  "case": "issuance-verified",
  "archive": "archive-with-crl.der",
  "seal_key": "seal-public.pem",
  "issuer_key": "issuer-public.pem",
  "attachment_refs": [],
  "issuance_scope": ["REV-001"],
  "entries": [ ... ],
  "citations": { ... }
}
```

把 `archive` 换成真实 CMS `SignedData`、把 `seal_key`/`issuer_key` 换成离线保管的公钥，就能得到同样的覆盖表。`issuer_key` 为空时只到 `T2`；`attachment_refs` 指向不存在的路径时状态为 `missing`；两者都不能提升到 `T3`。

## 边界

- 本审阅器只实现 Ed25519 夹具验签；真实 RSA/ECDSA CRL 会标记 `UNSUPPORTED`，不会擅自升级。
- `asn1crypto/pdf.py` 不解析 PDF `/ByteRange`，也不执行密码学验证；本模型的外层封存是 CMS 层，不是 PDF 文件级签名。要证明 PDF 的字节范围，必须在 PDF 解析层另行核对 `/ByteRange` 与 `/Contents`。
- 外层签名对 `encap_content_info` 的 payload 只有 `message_digest` 间接绑定，不对 payload 字节做直接覆盖。
- 现有 `tests/fixtures/eid2011.crl` 有真实 CRL 字节，但仓库没有其发行者公钥/证书；审阅器只能标为 `MISSING_KEY`，不能凭外层摘要升到 `T3`。
