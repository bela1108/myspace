# IFUNC 分派证据工具

ifunc_evidence.py 是只读的 x86-64 GNU IFUNC 分派证据清单工具。它使用
pyelftools 解析 ELF，不调用外部 readelf/objdump，也不会修改输入文件。

## 运行

在仓库根目录执行：

~~~ sh
python ifunc_evidence.py device.elf --format markdown -o acceptance.md
python ifunc_evidence.py device.elf --format json
python ifunc_evidence.py device.elf --format csv
~~~

运行测试：

~~~ sh
python -m unittest test.test_ifunc_evidence -v
python test/run_all_unittests.py
~~~

## 两列验收口径

验收 Markdown 和 CSV 都包含两个独立字段：

- selector_column / 定位到选择器：动态符号类型为 STT_GNU_IFUNC
  （pyelftools 可能显示为同值的 STT_LOOS=10），或
  R_X86_64_IRELATIVE 的 r_addend 指向该地址。
- implementation_column / 有证据确认实际实现：只有从选择器字节中解析出
  唯一、直接的返回目标，且该目标通过 PT_LOAD/可分配节映射到一致、非零、
  可执行的文件字节时，才标记为确认。

第一列成功不蕴含第二列成功。常见未确认状态包括：

- multiple_dispatch_targets：选择器中有多个 LEA RAX,[RIP+disp32]; RET
  或绝对地址 MOV RAX,imm64; RET 目标；静态文件不能决定旧型号或新型号
  设备实际走哪条 CPU 分派路径。
- direct_return_not_decoded：选择器使用间接跳转、外部解析例程或本工具
  未建模的控制流。
- target_not_verified：目标地址没有一致的可读/可执行文件映射。
- contradictory_mapping：Program header、section header 或多个加载映射
  对同一 VA 给出冲突字节。

## RELA 定位线索

工具分别从 DT_RELA/DT_JMPREL 和 SHT_RELA 节枚举 RELA 记录。相同
(r_offset, r_info, r_addend) 的记录合并为一条证据，同时保留：

- dynamic_occurrences：动态标签名、表内下标、表 VA/文件偏移和表项偏移；
- section_occurrences：节名、节下标、节内下标和表项文件偏移。

无节头交付仍可通过 PT_DYNAMIC、DT_SYMTAB、DT_HASH 和 DT_RELA
工作；此时 section_occurrences 为空。

## 可定位保留意见

保留意见包含稳定的英文 code 和结构化 where 字段，JSON 输出不会丢失
定位信息：

- symbol_aliases：多个动态符号共用选择器地址。
- zero_filled_address：选择器、实现目标或 IRELATIVE 的 r_offset 存储
  位于零填充/全零字节；重定位前 GOT 为零是常见情况，不能拿来识别实现。
- mapping_contradiction：两处映射的偏移或字节不一致，where.left 和
  where.right 保留两侧来源。
- manifest_selector_only：版本清单只命中选择器地址；这不等于实现命中。

## 可选版本清单

清单格式是普通 JSON。地址可用十六进制字符串：

~~~ json
{
  "selector_addresses": [
    {"address": "0x200", "version": "selector-build"}
  ],
  "implementations": [
    {
      "implementation_va": "0x220",
      "size": 16,
      "sha256": "implementation-bytes-sha256",
      "version": "patched-build",
      "status": "patched"
    }
  ]
}
~~~

sha256 默认核对 size 指定的函数字节数；未给 size 时核对工具读取的固定
探测窗口。清单中的选择器地址只产生 manifest_selector_only 保留意见，
不会设置 implementation_confirmed=true。

## 测试夹具

test/test_ifunc_evidence.py 用 struct 生成小型 ELF64 x86-64 字节夹具，
覆盖节头存在、e_shoff=0、RELA 双来源合并、别名、零填充地址、映射冲突、
多目标选择器、清单匹配和非 x86-64 拒绝。所有结论均来自这些字节和
pyelftools 解析结果，不依赖编译器、外部 ELF 工具或网络。
