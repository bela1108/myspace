# asn1crypto 1.5.1 离线引用审阅：吊销记录的多层封存

本报告只基于本地仓库源码、生成的小型 ASN.1 夹具和独立验签账，不联网、不执行夹具中的任何程序。

## 结论

- 外层 CMS 封存的签名输入是 `SignerInfo.signed_attrs` 的去标记 SET 编码；归档中的 `[0]` 隐式包装在验签前被还原为 `SET(0x31)`。
- 嵌入 `adobe_revocation_info_archival` 的完整 CRL 字节直接落在外层签名范围内；但外层签名只冻结字节，不证明 CRL 的发行来源。
- 内层 CRL 签名只覆盖 `CertificateList.tbs_cert_list`，不覆盖 `signature_algorithm`、自身 `signature` 值、外层 CMS 包装，也不自动证明外层 payload 或 PDF `/ByteRange`。
- 只有外层回执（`outer_receipt_only`）时，`REV-001` 保持 `T1`；声明了附件但文件缺失（`missing`）是另一个状态，不能被改写成“仅有外层回执”。
- 本地夹具补上实际 CRL 字节、发行者公钥和原 CRL 签名后，只有 `REV-001` 从 `T1` 升到 `T3`；其他归档条目和源码引用条目保持原层级/原依据。
- asn1crypto `pdf.py` 只定义 ASN.1 类型，不解析 PDF 文件结构，也不执行密码学验签；本报告的“外层封存”是 CMS 层签名模型。

## 证据层级

| 层级 | 含义 |
| --- | --- |
| T0 | 无有效字节：没有可用外层回执，也没有附件字节。 |
| T1 | 外层回执：外层签名/回执有效，但没有实际对象字节；只能证明曾提交过某个摘要承诺。 |
| T2 | 附件字节：实际对象字节存在，且与回执摘要一致；外层封存覆盖这些字节，但尚未完成原发行验签。 |
| T3 | 原发行证明：对象字节存在，并由独立发行者密钥验证了对象自身签名。 |
| S1 | 源码引用：命题关于代码结构，引用行已离线核对；不改写也不升级归档层级。 |
| S0 | 源码引用失配：引用的文件或行片段无法核对。 |

`T` 是归档字节的可证层级；`S` 是源码引用域，二者不能互相替代。`T1` 的外层回执只能证明“提交过某个摘要承诺”，不能把摘要当作内容。

## 场景对照

| 场景 | 附件状态 | 外层验签 | 原发行验签 | REV-001 层级 | 判定 |
| --- | --- | --- | --- | --- | --- |
| outer-only | outer_receipt_only | VALID | NOT_ATTEMPTED | T1 | 只有外层回执/摘要承诺，没有对象字节。 |
| missing-attachment | missing | VALID | NOT_ATTEMPTED | T1 | 声明了附件路径但文件缺失；与“只有外层回执”是不同状态。 |
| attachment-unverified | present | VALID | MISSING_KEY | T2 | 附件字节在归档内且摘要一致；缺少独立发行者公钥，未做原发行验签。 |
| tampered-attachment | present | VALID | INVALID | T1 | 外层封存仍有效，但附件摘要与外层承诺不一致，内层签名也失败。 |
| issuance-verified | present | VALID | VALID | T3 | 附件字节 + 外层封存 + 原发行验签全部通过；仅提升范围条目。 |

关键区别：`outer-only` 没有声明具体附件路径；`missing-attachment` 声明了 `attachments/revocation.crl.der`，但该文件不存在。两者的 `REV-001` 都在 `T1`，但报告依据和缺件说明不同；不能把后者写成“外层回执已确认附件”。

## 字节覆盖（issuance-verified 夹具）

逻辑字节与归档偏移并列，因为 CMS 签名输入是去标记后的 SET 编码，而归档内实际存放的是 `[0]` 隐式标签包装；两者内容相同，标签不同。偏移均为 `[start, end)`。

| 对象 | 归档偏移 | 外层封存直接覆盖 | 内层 CRL 签名直接覆盖 | 逻辑字节 |
| --- | --- | --- | --- | --- |
| CMS SignedAttrs（逻辑 SET 编码；归档内为 [0] 隐式包装） | [200, 642) (442 B) | 是 | 否 | `outer_signed_attrs` (442 B, sha256 `16cf564f3d98a672…`) |
| 外层 CMS signature OCTET STRING 内容 | [651, 715) (64 B) | 否 | 否 | `outer_signature_value` (64 B, sha256 `baad7ee1ba703702…`) |
| encap_content_info 内容 | [60, 92) (32 B) | 仅摘要 | 否 | `payload` (32 B, sha256 `49945d0fa063c90c…`) |
| adobe_revocation_info_archival 值 | [298, 642) (344 B) | 是 | 否 | `archival_attribute` (344 B, sha256 `1d5533477a202cb4…`) |
| 内层 CertificateList（完整 CRL，含自身签名字段） | [310, 591) (281 B) | 是 | 否 | `crl_certificate_list` (281 B, sha256 `15438db21bd655c5…`) |
| CRL tbs_cert_list（被发行者签名的字节） | [314, 517) (203 B) | 是 | 是 | `crl_tbs_cert_list` (203 B, sha256 `22cf608294c26ab8…`) |
| revoked_certificates[0]（第一条吊销记录） | [438, 501) (63 B) | 是 | 是 | `revoked_certificate_entry` (63 B, sha256 `b3edff55247b76af…`) |
| CRL signature BIT STRING 内容 | [527, 591) (64 B) | 是 | 否 | `crl_signature_value` (64 B, sha256 `6f86dd6cfbcee7c0…`) |

由此可核：`crl_tbs_cert_list` 的偏移区间严格位于 `crl_certificate_list` 内；`revoked_certificate_entry` 又严格位于 `tbs_cert_list` 内；`outer_signed_attrs` 的范围包含 `archival_attribute` 和完整 CRL。

## 补件前后：只有对应条目升级

基线取 `outer-only` 场景，补件取 `issuance-verified` 场景。补件把实际 CRL 字节、本地发行者公钥和原 CRL 签名加入归档，不改变其他条目的命题或依据。

| 条目 | 补件前 | 补件后 | 是否变化 | 补件后依据 |
| --- | --- | --- | --- | --- |
| IDX-001 | T1 | T1 | 保持 | 外层回执 SIG-OUTER；摘要本身不提供附件字节。 |
| REV-001 | T1 | T3 | 是 | SIG-INNER（发行者密钥）+ SIG-OUTER + 附件摘要一致；字段读取自已验签的 tbs_cert_list。 |
| REV-002 | T1 | T1 | 保持 | 政策通知依据；不在本次 CRL 的 tbs_cert_list 签名覆盖范围。 |
| CODE-001 | S1 | S1 | 保持 | CIT-PDF-ARCH, CIT-PDF-RIA, CIT-PDF-OID |
| CODE-002 | S1 | S1 | 保持 | CIT-CMS-SIGNER, CIT-CMS-SIGNEDDATA |
| CODE-003 | S1 | S1 | 保持 | CIT-CRL-LIST |
| CODE-004 | S1 | S1 | 保持 | CIT-TSP-ATS |
| CODE-005 | S1 | S1 | 保持 | CIT-README-PARSE, CIT-README-SIG, ABS-NO-VERIFY |
| CODE-006 | S1 | S1 | 保持 | CIT-PDF-DOC, ABS-NO-BYTERANGE |

实际变化条目：`REV-001`。其余 8 个条目保持原依据；没有因 `REV-001` 的附件出现而整体抬高。

## 独立验签账

验签账单独写入 `out/verification_ledger.json`，记录每次签名使用的对象、输入 SHA-256、归档偏移、密钥 ID/指纹和结果；报告不把外层回执自己的文字当作“已验证”。

主场景（`issuance-verified`）的签名记录：

| 签名 | 覆盖对象 | 算法 | 密钥 | 结果 | 输入 SHA-256 |
| --- | --- | --- | --- | --- | --- |
| SIG-OUTER | CMS SignedAttrs (untagged SET OF) | ed25519 | KEY-03396219237F75A6 | VALID | 16cf564f3d98a672c91d21220066a0c09cf3121fe22d2d3278644f52c985fffd |
| SIG-INNER | CertificateList.tbs_cert_list | ed25519 | KEY-0A5B67549542C9A5 | VALID | 22cf608294c26ab8c091918395cf86712f77ca7034cc0e374fcc528b2209ad15 |

外层密钥 `KEY-03396219237F75A6`，指纹 `03396219237f75a64f12aeb7f39723ab…`；内层发行者密钥 `KEY-0A5B67549542C9A5`，指纹 `0a5b67549542c9a55ed6a80ba5c7646b…`。内层密钥来自本地夹具 `issuer-public.pem`，不是归档自带的证书字段。

## 引用审阅

引用逐条回到源码行核对片段；任何一行失配都会把对应代码条目降为 `S0`，但不会影响归档条目。

| 引用 | 位置 | 核对 | 说明 |
| --- | --- | --- | --- |
| CIT-CMS-SIGNEDDATA | `asn1crypto/cms.py:621-629` | OK | SignedData keeps top-level CRLs and signer infos as separate fields. |
| CIT-CMS-SIGNER | `asn1crypto/cms.py:605-614` | OK | SignerInfo separates signed attributes from the signature value. |
| CIT-CRL-LIST | `asn1crypto/crl.py:286-291` | OK | CertificateList separates the signed TBS bytes from algorithm and signature fields. |
| CIT-PDF-ARCH | `asn1crypto/pdf.py:31-34` | OK | AdobeArchiveRevInfo carries only a version; it does not carry attachment bytes. |
| CIT-PDF-DOC | `asn1crypto/pdf.py:3-6` | OK | pdf.py is an ASN.1 type module, not a PDF byte-range parser. |
| CIT-PDF-OID | `asn1crypto/pdf.py:82-84` | OK | The CMS attribute OID is mapped to SetOfRevocationInfoArchival. |
| CIT-PDF-RIA | `asn1crypto/pdf.py:64-69` | OK | The archival revocation attribute has distinct crl, ocsp and other_rev_info branches. |
| CIT-README-PARSE | `readme.md:1-4` | OK | The package describes itself as a parser/serializer. |
| CIT-README-SIG | `readme.md:90-95` | OK | Signatures are represented as byte strings; the package does not authenticate them. |
| CIT-TSP-ATS | `asn1crypto/tsp.py:202-212` | OK | Archive timestamp structures can chain preservation statements, but do not verify revocation status. |

代码条目 `CODE-001`…`CODE-006` 的 `S1` 只表示“源码行与命题相符”，不表示运行时已验签；`CODE-005` 明确区分了解析库与密码学验证器。

引用注记：`pdf.py:5` 的文档串写作 `asn1crypto.xms.CMSAttribute()`，而同文件实际从 `.cms` 导入；这是文档笔误，不影响 OID 映射与字节覆盖结论。

## 缺席检查

除“某行有什么”之外，还检查“库中没有什么”，避免把未实现的能力误读为已验证：

| 检查 | 说明 | 模式 | 结果 | 命中 |
| --- | --- | --- | --- | --- |
| ABS-NO-BYTERANGE | asn1crypto 内没有 PDF ByteRange 解析代码 | `ByteRange` | OK | 0 处命中 |
| ABS-NO-VERIFY | asn1crypto 内没有签名验证 API（只搜索 def verify/check_signature） | `def (?:verify\|verify_signature\|check_signature)\b` | OK | 0 处命中 |

`ABS-NO-VERIFY` 在 `asn1crypto/` 下没有命中 `def verify`/`check_signature`；`ABS-NO-BYTERANGE` 没有命中 PDF `ByteRange`。因此 `CODE-005` 与 `CODE-006` 的 `S1` 仍只是源码事实，不替代本报告外部的 Ed25519 验签。

## 现有语料复核

仓库内真实 CRL 语料 `tests/fixtures/eid2011.crl`（1181874 B，sha256 `136ad7a127f3bc195d8275c0c39ba8f4…`）可作为结构对照：

- 发行者：`Email Address: pki@sk.ee, Common Name: EID-SK 2011, Organization: AS Sertifitseerimiskeskus, Country: EE`；`this_update`：`2015-05-22T11:44:11+00:00`；吊销条目数：`15752`。
- TBS 长度 `1181593 B`，TBS SHA-256 `4523f4729c5cae05e41a139b16c1a45d1b863d9d3b6d3f29f2517f58a62759b1`；签名算法 `sha256_rsa`，签名长度 `256 B`。
- 仓库没有该 CRL 的发行者公钥/证书，因此状态为 `MISSING_KEY`；只能核对结构边界，不能提升到 `T3`，也不能用外层摘要代替发行者签名。

## 边界与不能证明的事

- 本模型的外层封存是 CMS `SignedData`；`pdf.py` 不解析 PDF `/ByteRange`，所以本报告不能证明某个 PDF 文件级签名的字节范围。若真实档案只有 PDF 外层回执而无附件，应保持 `T1`。
- 外层签名覆盖嵌入的 CRL 字节，但“覆盖”不等于“验证 CRL 发行”。`tampered-attachment` 场景中外层签名仍有效，而内层发行签名失败，证明外层封存可以冻结被篡改的字节。
- 外层对 payload 只有 `message_digest` 的间接绑定；payload 字节本身不在签名输入内。
- 本夹具的 `SignerInfo` 含 `signed_attrs`；若真实 CMS 采用无 signedAttrs 的分支，外层签名输入会变为 eContent，本模型不覆盖该分支，应另行核对。
- `AdobeArchiveRevInfo` 扩展只有 `version`，不能承载附件；如果档案只出现该扩展而没有 `RevocationInfoArchival` 的 `crl`/`ocsp`/`other_rev_info` 字节，仍应停在 `T1`。
- 本审阅器只实现 Ed25519 夹具验签；遇到其他算法标记 `UNSUPPORTED`，不擅自提升层级。
- `REV-002` 是政策通知，不在本次 CRL 签名覆盖范围；即使 `REV-001` 已升到 `T3`，它仍保持 `T1`。

## 复跑

```sh
python -m revocation_review.review build-fixtures
python -m revocation_review.review report
python -m revocation_review.review verify-ledger
python -m unittest tests.test_revocation_review
```

机器可读详情：`out/report.json`；独立验签账：`out/verification_ledger.json`。
