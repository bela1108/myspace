# 离线交付验收包

这个目录用两份不同架构的良性空 PE 程序演示核对流程：

- artifacts/empty_x86.exe：PE32 / IMAGE_FILE_MACHINE_I386
- artifacts/empty_x64.exe：PE32+ / IMAGE_FILE_MACHINE_AMD64

LOT-X64-B 与 LOT-X64-C 取自不同封存批次，但 PE 头值和 sha256 相同；报告不会把它们合并成一个出处。窄签收单 narrow-receipt.json 只覆盖 LOT-X86-A 和 LOT-X64-B。

## 重新生成与核对

    .venv/bin/python delivery_audit.py --build-fixtures
    .venv/bin/python delivery_audit.py

也可以替换下列输入后传入自有路径：

- offline-delivery-contract.json：合同机器、子系统、映像版本和外部证据条款
- inventory.csv：产品名与产品版本库存
- sealed-batches.json：封存批次、封存哈希和 PE 文件路径
- narrow-receipt.json：范围更窄的签收单

输出为：

- delivery-audit-report.json：机器可读完整结果与出处分组
- DELIVERY_REPORT.md：人工签收报告

## 当前验收结论

- 暂停收货：LOT-X64-C。PE 头和封存哈希均通过 CL-4.1 至 CL-4.3，但该批次不在窄签收单内；相同头部值不能替代该批次的独立签收。
- 无法核到：CL-5.2（目标工控子系统资产绑定）。该信息不在 PE 头中，当前离线包也没有 asset_subsystem_bindings 证据。
- linker_version、time_date_stamp、checksum、dll_characteristics、对齐值等属于旧合同 ODC-ICS-AUX-2024-018 未覆盖字段；本次只观察、留出处，不把它们误报成旧合同违约。
