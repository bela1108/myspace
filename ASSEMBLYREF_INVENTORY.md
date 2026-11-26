# AssemblyRef 封存件配对清册

- 案卷：`FORENSIC-DNFILE-056`
- 方式：dnfile 只读解析 `AssemblyRef`/`Assembly` 表及 `#Strings`/`#Blob` 堆；不加载、不执行程序集。
- 清单说明：确定性合成案卷，用于验证只读 AssemblyRef 与独立封存清单配对。
- 汇总：引用 3 项；确定配对 1 项；候选配对 2 组；未匹配 0 项；涉及候选封存件 5 件。

## 一、确定配对

### `ForensicSample.Dispatch.dll:AssemblyRef:1` → `SEAL-WIDGETS-310`

- 引用身份：`Contoso.Widgets, Version=3.1.0.0, Culture=neutral, PublicKeyToken=15869992a418bb68`
- 确定封存件：`SEAL-WIDGETS-310`；清单登记封存路径：`sealed-archive/SEAL-WIDGETS-310/Contoso.Widgets_3.1.0.0.dll`
- 交付文件：`forensic_case/delivery/Contoso.Widgets_3.1.0.0.dll`
- SHA-256：`afe2a965a7a0a70b31ca3763dd2bda9b7a201ea4c9657dab9b99a2d5806cb499`（清单状态：`verified`）
- 表项证据：`AssemblyRef` 第 1 行，文件偏移 `760`，Name 堆索引 `53`，Culture 堆索引 `0`，PublicKey Blob 索引 `1`

## 二、只能提供候选的配对

### `ForensicSample.Dispatch.dll:AssemblyRef:2`

- 引用身份：`Regional.Resources, Version=1.0.0.0, Culture=<缺失>, PublicKeyToken=80ca8998c3eb0e0b`
- 结论：现有证据不足以唯一同一认定；以下每件均具体对应独立封存记录。
- 证据缺项：引用文化字段缺失；封存清单文化字段缺失；引用身份不完整，不能作唯一同一认定
- 候选封存件：
  - `SEAL-REGIONAL-EN` → `sealed-archive/SEAL-REGIONAL-EN/Regional.Resources_1.0.0.0_en-US.dll`；文件 `Regional.Resources_1.0.0.0_en-US.dll`；SHA-256 `dd0a3720dad1e5461425a4b093f32fa701f345e2f1ac8e5a467eac0a6858804f`；摘要状态 `verified`；候选身份 `Regional.Resources, Version=1.0.0.0, Culture=en-us, PublicKeyToken=80ca8998c3eb0e0b`
  - `SEAL-REGIONAL-FR` → `sealed-archive/SEAL-REGIONAL-FR/Regional.Resources_1.0.0.0_fr-FR.dll`；文件 `Regional.Resources_1.0.0.0_fr-FR.dll`；SHA-256 `74588e7dbb0ba3b6875bcd08b9c1b64bb45cbf46538c81c6d7b278a6572f98e3`；摘要状态 `verified`；候选身份 `Regional.Resources, Version=1.0.0.0, Culture=fr-fr, PublicKeyToken=80ca8998c3eb0e0b`
- 引用表项：`AssemblyRef` 第 2 行，文件偏移 `780`，Name 堆索引 `69`，Culture 堆索引 `65534`，PublicKey Blob 索引 `10`

### `ForensicSample.Dispatch.dll:AssemblyRef:3`

- 引用身份：`Imaging.Codec, Version=5.0.0.0, Culture=neutral, PublicKeyToken=<缺失>`
- 结论：现有证据不足以唯一同一认定；以下每件均具体对应独立封存记录。
- 证据缺项：公钥身份字段缺失；引用身份不完整，不能作唯一同一认定
- 候选封存件：
  - `SEAL-IMAGING-KEYA` → `sealed-archive/SEAL-IMAGING-KEYA/Imaging.Codec_5.0.0.0_keyA.dll`；文件 `Imaging.Codec_5.0.0.0_keyA.dll`；SHA-256 `a99dd381c9073a2decf02207177e046953de0157cf6a1076847c8183106ea54d`；摘要状态 `verified`；候选身份 `Imaging.Codec, Version=5.0.0.0, Culture=neutral, PublicKeyToken=665f91ab7ea87eff`
  - `SEAL-IMAGING-KEYB` → `sealed-archive/SEAL-IMAGING-KEYB/Imaging.Codec_5.0.0.0_keyB.dll`；文件 `Imaging.Codec_5.0.0.0_keyB.dll`；SHA-256 `a53fdeb852e16fca911b2d43bfc34127b26fafebf23f2423ecd55c9115defdf6`；摘要状态 `verified`；候选身份 `Imaging.Codec, Version=5.0.0.0, Culture=neutral, PublicKeyToken=96c697130e81bb75`
- 引用表项：`AssemblyRef` 第 3 行，文件偏移 `800`，Name 堆索引 `88`，Culture 堆索引 `0`，PublicKey Blob 索引 `0`

## 三、未匹配引用

无。

## 四、机读结果

完整表项偏移、堆索引、哈希和结构化缺项见同批输出的 JSON 清册。
