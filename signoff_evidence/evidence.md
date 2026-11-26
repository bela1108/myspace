# PE 签收材料离线结构证据

## 结论

- PE：`minimal-two-receipt-sections.exe`，2304 bytes，SHA-256 `08e4c8a4ee349ea8555ceed3df8349999e129a893975861d121c226e206957aa`。
- pefile：`2024.8.26`；结构核对：`通过`。
- PE 节表中有 2 个真实 `.rcp*` 签收区段；清单另有 1 个真实区段缺失项、1 个重复归档项。
- Windows 安全目录是数据目录第 4 项，文件偏移 `0x800`，长度 256 bytes，解析出 2 条 8 字节对齐的占位 `WIN_CERTIFICATE` 记录。
- 交换外部登记顺序后，批准保留材料仍定位到 `.rcp0`@`0x400`。
- 范围：仅离线结构、偏移、对齐和哈希引用；占位字节不是 PKCS#7/Authenticode 签名，不做信任结论。

## PE 头与对齐

| 项 | 值 |
| --- | --- |
| Machine | `0x8664` |
| Optional Magic | `0x20b` |
| NumberOfSections | `3` |
| SectionAlignment | `0x1000` |
| FileAlignment | `0x200` |
| ImageBase | `0x140000000` |
| AddressOfEntryPoint | `0x1000` |

## 真实 PE 区段与保留对齐

| 区段 | VA / VSize | Raw range | Raw size | 对齐余数 | 负载 SHA-256 | 保留填充 |
| --- | --- | --- | ---: | ---: | --- | --- |
| `.text` | `0x1000` / 1 B | `0x200–0x400` | 512 B | raw%FA=0, size%FA=0 | (code/无清单负载) | - |
| `.rcp0` | `0x2000` / 218 B | `0x400–0x600` | 512 B | raw%FA=0, size%FA=0 | `f0906f458a3cc357…` / 清单匹配 `True` | 294 B zero=True |
| `.rcp1` | `0x3000` / 219 B | `0x600–0x800` | 512 B | raw%FA=0, size%FA=0 | `27a6915c4fb0f916…` / 清单匹配 `True` | 293 B zero=True |

## 正常 PE 安全目录

- 目录引用：`OPTIONAL_HEADER.DATA_DIRECTORY[4]`；该目录的 `VirtualAddress` 按 PE 规范是原始文件偏移而非 RVA。
- 目录范围：`0x800`，256 bytes；8 字节对齐：offset=`True`, size=`True`；恰好覆盖记录=`True`。

| # | 头偏移 | dwLength | 对齐跨度 | Revision / Type | 负载范围 | SHA-256 | 对齐填充 |
| ---: | --- | ---: | ---: | --- | --- | --- | --- |
| 0 | `0x800` | 125 B | 128 B | `0x200` / `0x2` | `0x808–0x87d` | `051bf7510b56b628…` | 3 B zero=True |
| 1 | `0x880` | 125 B | 128 B | `0x200` / `0x2` | `0x888–0x8fd` | `0d3fd933ebe58f0f…` | 3 B zero=True |

## 项目签收清单核对

| 签收 ID | 来源 | 声称区段 | 主分类 | 物理证据引用 |
| --- | --- | --- | --- | --- |
| `RCPT-APPROVED-ALPHA` | `project_manifest` | `.rcp0` | `matched_real_section` | `.rcp0` @ `0x400`, `f0906f458a3cc357…` |
| `RCPT-COUNTERSIGN-BETA` | `project_manifest` | `.rcp1` | `matched_real_section` | `.rcp1` @ `0x600`, `27a6915c4fb0f916…` |
| `RCPT-GHOST-MISSING-SECTION` | `project_manifest` | `.rcp9` | `missing_real_section` | 无区段表记录、无原始范围 |
| `ARCHIVE-DUP-ALPHA` | `duplicate_archive` | `.rcp0` | `duplicate_archive` | `.rcp0` @ `0x400`, `f0906f458a3cc357…` |

## 外部登记顺序交换核对

### `external-registration-order-a.json`

| 位置 | 登记号 | 签收 ID | 哈希定位到的物理区段 | 批准保留 |
| ---: | --- | --- | --- | --- |
| 0 | `EXT-B-SECOND-IN-A` | `RCPT-COUNTERSIGN-BETA` | `.rcp1`@0x600 | `False` |
| 1 | `EXT-A-APPROVED-SECOND-IN-A` | `RCPT-APPROVED-ALPHA` | `.rcp0`@0x400 | `True` |

### `external-registration-order-b.json`

| 位置 | 登记号 | 签收 ID | 哈希定位到的物理区段 | 批准保留 |
| ---: | --- | --- | --- | --- |
| 0 | `EXT-A-APPROVED-SECOND-IN-A` | `RCPT-APPROVED-ALPHA` | `.rcp0`@0x400 | `True` |
| 1 | `EXT-B-SECOND-IN-A` | `RCPT-COUNTERSIGN-BETA` | `.rcp1`@0x600 | `False` |

## 证据边界

- `pefile` 负责解析 DOS/PE 头、数据目录和节表；`WIN_CERTIFICATE` 链由本脚本按偏移做结构解析。
- 所有定位均附文件偏移、范围或 SHA-256，可供离线复核；未联网、未调用证书链或时间戳验证。
- pefile 警告仅为解析启发式：["Byte 0x00 makes up 67.6649% of the file's contents. This may indicate truncation / malformation."]；本夹具保留大量零对齐填充，`objdump -p` 可正常识别。
- `missing_real_section` 表示清单声称的 `.rcp9` 在节表和原始范围中均不存在；`duplicate_archive` 是同一 SHA-256/同一物理区段的重复归档，不是第二段新材料。
