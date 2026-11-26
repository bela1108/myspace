# 离线 ELF 证物规划

这个目录用一个 736 字节的合法 ELF 夹具验证：两条只读表地址解释共享同一个符号，但不能共用或任选一条重定位记录。夹具只汇编、解析，不执行。

## 夹具事实

- 文件：`evidence_plan/table_refs.o`
- 源码：`evidence_plan/table_refs.s`
- 构建声明：`evidence_plan/build-declaration.json`
- SHA-256：`ad6c217c65ee2311a17296f6e5bb0a83e0ca69138a78f3750385ff5f0d683a93`
- 类别：`ELFCLASS64`、小端、`EM_X86_64`、`ET_REL`、`e_phnum=0`
- 构建命令：`clang --target=x86_64-unknown-elf -c table_refs.s -o table_refs.o`
- 同一命令已验证可逐字节重建该 `.o`

实际节和关系：

- `.rodata` 是节索引 4，`SHT_PROGBITS`，标志为 `SHF_ALLOC` 且无 `SHF_WRITE`。
- `.rela.rodata` 是节索引 5，`sh_info=4` 指向 `.rodata`，`sh_link=6` 指向 `.symtab`。
- `.symtab` 的 `sh_link=1` 指向 `.strtab`；`e_shstrndx=1`，所以节名和符号名共用该字符串表。
- 两条重定位都使用符号索引 2：`shared_symbol`；其 `st_name=7`、`st_shndx=3` 指向 `.text.shared`。

| 解释 | 表内位置 | 必需重定位片段 | 类型 | 链接期复算 |
| --- | --- | --- | --- | --- |
| 64 位绝对地址 | 文件偏移 `72`，8 字节 | 文件偏移 `168`，24 字节，条目 0 | `R_X86_64_64` (1)，`A=0x10` | `S + A = 0x10` |
| 32 位 PC 相对位移 | 文件偏移 `80`，4 字节 | 文件偏移 `192`，24 字节，条目 1 | `R_X86_64_PC32` (2)，`A=0x20` | `S + A - P = 0x18` |

这里 `S` 在 `ET_REL` 中为目标节基址加 `st_value`（本夹具均为 0），`P` 为 `.rodata` 基址加 `r_offset`。因此 `0x10`、`0x18` 是可离线复算的节内/链接期表达式，不是最终运行虚拟地址。若指定解释还要求最终 VA 或运行期只读页权限，必须追加链接后 ELF 的节地址、`PT_LOAD` 标志、链接脚本/加载基址或等价符号提供方记录。

## 最小输入闭包

每条解释都需要完整依赖链，不能只保留表字节或任选一段重定位：

`Ehdr -> 相关 Shdr -> .rela.rodata 条目 -> r_info_sym -> .symtab 条目 -> st_name -> .strtab 符号名`

同时还需要：

- `relocation Shdr.sh_info -> .rodata Shdr`，用于定位 `r_offset`、表标志和地址基址。
- `symbol.st_shndx -> 目标节 Shdr`，用于确认符号定义所在节并计算 `S`。
- `e_shstrndx -> 节名字符串`，用于把数字节索引核对回 `.rodata`、`.rela.rodata`、`.symtab` 等名称。
- `build-declaration.json`，用于核对 target triple、构建命令、不执行策略以及源码/夹具哈希。

精确原子和 SHA-256 见 `evidence_plan/out/plan-abs.json`、`evidence_plan/out/plan-pcrel.json` 和 `evidence_plan/out/plan-both.json`。汇总如下：

| 目标 | ELF 唯一区间 | 构建声明 | 物理输入合计 | 逻辑原子字节合计 |
| --- | ---: | ---: | ---: | ---: |
| 仅绝对解释 | 496 B | 725 B | 1221 B | 1229 B |
| 仅 PC 相对解释 | 492 B | 725 B | 1217 B | 1225 B |
| 两条解释都支持 | 524 B | 725 B | 1249 B | 1257 B |

逻辑原子合计有 8 B 重复，是因为 `.rodata` 字符串恰好是 `.rela.rodata` 字符串的后缀；按合并区间留存时只存一次。`target-symbol-bytes` 是可选内容佐证，不计入地址公式的最小闭包。

## 复跑命令

```sh
.venv/bin/python evidence_plan/elf_evidence_plan.py refresh-declaration
.venv/bin/python evidence_plan/elf_evidence_plan.py verify
.venv/bin/python evidence_plan/elf_evidence_plan.py plan --claims both \
  --out evidence_plan/out/plan-both.json
.venv/bin/python evidence_plan/elf_evidence_plan.py carve --claims both \
  --out evidence_plan/out/both
.venv/bin/python evidence_plan/elf_evidence_plan.py verify-package \
  --manifest evidence_plan/out/both/evidence-manifest.json
```

`carve` 生成按合并区间存储的 `ranges/`、构建声明原子、清单，以及可被 pyelftools 重新解析的稀疏回填文件 `table_refs.trimmed.elf`。`verify-package` 会按切片偏移和 SHA-256 复检 18 个必需原子，并重新解析两条重定位。

## 留存上限冲突

题面没有给出具体上限数值；规划器把上限作为参数。下面两个边界场景由实际大小复算得到，精简结果在 `evidence_plan/out/missing-parts.json`。

若上限 `1221 B`，恰好只够绝对解释闭包；要求两条解释时完整闭包为 `1249 B`，缺口 `28 B`。不能用绝对重定位条目代替 PC 相对条目，缺件为：

- `relocation:pcrel`：`table_refs.o` 偏移 `192`，`24 B`，SHA-256 `a620972924074aa82747d7ef0988fc780900a72ea5648c15df3411d0421ee780`
- `table-slot:pcrel`：`table_refs.o` 偏移 `80`，`4 B`，SHA-256 `df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119`

若上限 `1217 B`，恰好只够 PC 相对解释闭包；要求两条解释时缺口 `32 B`，缺件为：

- `relocation:abs`：`table_refs.o` 偏移 `168`，`24 B`，SHA-256 `83ff11ed64793470263b9ae44d81867b7654591db088ef747c51f236ae4f0e2f`
- `table-slot:abs`：`table_refs.o` 偏移 `72`，`8 B`，SHA-256 `af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc`

每个缺件都可用清单中的偏移和长度从原始证物中重新截取，例如：

```sh
dd if=evidence_plan/table_refs.o bs=1 skip=192 count=24 2>/dev/null | shasum -a 256
```

任意其他字节上限可用以下命令得到对应缺件：

```sh
.venv/bin/python evidence_plan/elf_evidence_plan.py plan \
  --claims both --budget <BYTES> --priority abs \
  --out evidence_plan/out/conflict.json
```
