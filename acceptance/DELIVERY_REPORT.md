# 离线交付 PE 头部核对报告

- 交付合同：`ODC-ICS-AUX-2026-055`
- 旧合同：`ODC-ICS-AUX-2024-018`
- 签收单：`RCPT-NARROW-055`
- 批次结论：2 批可签收，1 批暂停；1 条合同外部证据无法核到。

**暂停收货：`LOT-X64-C`。**
- `LOT-X64-C` 原因：`not_listed_in_narrow_receipt`
**无法核到的合同条款：`CL-5.2` 目标工控子系统资产绑定。**

## 库存筛选

| 库存 ID | 产品 | 版本 | 门槛 | 结论 | 原因 |
| --- | --- | ---: | ---: | --- | --- |
| `INV-BENCH-100` | ICS Bench Helper | 1.0.0 | 1.0.0 | eligible | — |
| `INV-BENCH-200` | ICS Bench Helper | 1.0.0 | 1.0.0 | eligible | — |
| `INV-BENCH-300` | ICS Bench Helper | 1.0.1 | 1.0.0 | eligible | — |
| `INV-BENCH-090` | ICS Bench Helper | 0.9.4 | 1.0.0 | excluded | below_version_floor |
| `INV-CABLE-001` | Serial Cable Catalog | 3.2.0 | — | excluded | product_name_not_in_contract |

## 批次与 PE 头部确认

| 批次 | 封存号 | 库存行 | 机器类型 | 子系统 | 子系统版本 | 映像 | 结论 |
| --- | --- | --- | --- | --- | ---: | --- | --- |
| `LOT-X86-A` | `SEAL-20261127-A1` | `INV-BENCH-100` | IMAGE_FILE_MACHINE_I386 (0x014C) | IMAGE_SUBSYSTEM_WINDOWS_CUI | 6.1 | 1.0 / PE32 | `ready_to_accept` |
| `LOT-X64-B` | `SEAL-20261127-B2` | `INV-BENCH-200` | IMAGE_FILE_MACHINE_AMD64 (0x8664) | IMAGE_SUBSYSTEM_WINDOWS_CUI | 6.1 | 1.0 / PE32+ | `ready_to_accept` |
| `LOT-X64-C` | `SEAL-20261127-C3` | `INV-BENCH-300` | IMAGE_FILE_MACHINE_AMD64 (0x8664) | IMAGE_SUBSYSTEM_WINDOWS_CUI | 6.1 | 1.0 / PE32+ | `hold` |

### 逐项合同检查

- `LOT-X86-A`
  - 窄签收单 `RCPT-NARROW-055` 誊写范围：machine, subsystem, subsystem_version；未誊写的映像声明仍以 pefile 直接观察为准。
  - [PASS] 封存哈希: actual=`"518ceeea95b1472719d5095a8e894bde9ba6317a448e2193b6412f7ca23137c7"`
  - [PASS] 机器类型（CL-4.1）: actual=`"IMAGE_FILE_MACHINE_I386"`
  - [PASS] 子系统与版本（CL-4.2）: actual=`{"subsystem": "IMAGE_SUBSYSTEM_WINDOWS_CUI", "version": "6.1"}`
  - [PASS] 映像声明（CL-4.3）: actual=`{"magic": "PE32", "image_version": "1.0", "executable_image": true, "characteristics": ["IMAGE_FILE_EXECUTABLE_IMAGE", "IMAGE_FILE_32BIT_MACHINE"]}`
  - [PASS] 签收单记录值 machine: actual=`"IMAGE_FILE_MACHINE_I386"`
  - [PASS] 签收单记录值 subsystem: actual=`"IMAGE_SUBSYSTEM_WINDOWS_CUI"`
  - [PASS] 签收单记录值 subsystem_version: actual=`"6.1"`
- `LOT-X64-B`
  - 窄签收单 `RCPT-NARROW-055` 誊写范围：machine, subsystem, subsystem_version；未誊写的映像声明仍以 pefile 直接观察为准。
  - [PASS] 封存哈希: actual=`"c395900125a664c84c8fd74347383ba2f19e9601cc8f1e0919f2267ceda90bbd"`
  - [PASS] 机器类型（CL-4.1）: actual=`"IMAGE_FILE_MACHINE_AMD64"`
  - [PASS] 子系统与版本（CL-4.2）: actual=`{"subsystem": "IMAGE_SUBSYSTEM_WINDOWS_CUI", "version": "6.1"}`
  - [PASS] 映像声明（CL-4.3）: actual=`{"magic": "PE32+", "image_version": "1.0", "executable_image": true, "characteristics": ["IMAGE_FILE_EXECUTABLE_IMAGE", "IMAGE_FILE_LARGE_ADDRESS_AWARE"]}`
  - [PASS] 签收单记录值 machine: actual=`"IMAGE_FILE_MACHINE_AMD64"`
  - [PASS] 签收单记录值 subsystem: actual=`"IMAGE_SUBSYSTEM_WINDOWS_CUI"`
  - [PASS] 签收单记录值 subsystem_version: actual=`"6.1"`
- `LOT-X64-C`
  - 窄签收单中没有该批次行，不能用同值批次的签收替代。
  - [PASS] 封存哈希: actual=`"c395900125a664c84c8fd74347383ba2f19e9601cc8f1e0919f2267ceda90bbd"`
  - [PASS] 机器类型（CL-4.1）: actual=`"IMAGE_FILE_MACHINE_AMD64"`
  - [PASS] 子系统与版本（CL-4.2）: actual=`{"subsystem": "IMAGE_SUBSYSTEM_WINDOWS_CUI", "version": "6.1"}`
  - [PASS] 映像声明（CL-4.3）: actual=`{"magic": "PE32+", "image_version": "1.0", "executable_image": true, "characteristics": ["IMAGE_FILE_EXECUTABLE_IMAGE", "IMAGE_FILE_LARGE_ADDRESS_AWARE"]}`

## 不同封存批次的出处保留

- 一致头部值组 1：signature=`57bf2f4521ba6a81…`
  - 批次 `LOT-X86-A` / 封存 `SEAL-20261127-A1` / 库存 `INV-BENCH-100`
  - 文件 `empty_x86.exe` sha256=`518ceeea95b1472719d5095a8e894bde9ba6317a448e2193b6412f7ca23137c7`
- 一致头部值组 2：signature=`f8951f544c9e26f5…`
  - 批次 `LOT-X64-B` / 封存 `SEAL-20261127-B2` / 库存 `INV-BENCH-200`
  - 批次 `LOT-X64-C` / 封存 `SEAL-20261127-C3` / 库存 `INV-BENCH-300`
  - 文件 `empty_x64.exe` sha256=`c395900125a664c84c8fd74347383ba2f19e9601cc8f1e0919f2267ceda90bbd`
  - 文件 `empty_x64.exe` sha256=`c395900125a664c84c8fd74347383ba2f19e9601cc8f1e0919f2267ceda90bbd`

### 同值字段的跨批次出处

- `Machine`=`IMAGE_FILE_MACHINE_AMD64` ← LOT-X64-B/SEAL-20261127-B2、LOT-X64-C/SEAL-20261127-C3
- `Magic`=`PE32+` ← LOT-X64-B/SEAL-20261127-B2、LOT-X64-C/SEAL-20261127-C3
- `Architecture`=`x64` ← LOT-X64-B/SEAL-20261127-B2、LOT-X64-C/SEAL-20261127-C3
- `NumberOfSections`=`1` ← LOT-X86-A/SEAL-20261127-A1、LOT-X64-B/SEAL-20261127-B2、LOT-X64-C/SEAL-20261127-C3
- `TimeDateStamp`=`0` ← LOT-X86-A/SEAL-20261127-A1、LOT-X64-B/SEAL-20261127-B2、LOT-X64-C/SEAL-20261127-C3
- `Characteristics`=`["IMAGE_FILE_EXECUTABLE_IMAGE", "IMAGE_FILE_LARGE_ADDRESS_AWARE"]` ← LOT-X64-B/SEAL-20261127-B2、LOT-X64-C/SEAL-20261127-C3
- `Subsystem`=`IMAGE_SUBSYSTEM_WINDOWS_CUI` ← LOT-X86-A/SEAL-20261127-A1、LOT-X64-B/SEAL-20261127-B2、LOT-X64-C/SEAL-20261127-C3
- `SubsystemVersion`=`6.1` ← LOT-X86-A/SEAL-20261127-A1、LOT-X64-B/SEAL-20261127-B2、LOT-X64-C/SEAL-20261127-C3
- `ImageVersion`=`1.0` ← LOT-X86-A/SEAL-20261127-A1、LOT-X64-B/SEAL-20261127-B2、LOT-X64-C/SEAL-20261127-C3
- `OperatingSystemVersion`=`6.1` ← LOT-X86-A/SEAL-20261127-A1、LOT-X64-B/SEAL-20261127-B2、LOT-X64-C/SEAL-20261127-C3
- `LinkerVersion`=`14.0` ← LOT-X86-A/SEAL-20261127-A1、LOT-X64-B/SEAL-20261127-B2、LOT-X64-C/SEAL-20261127-C3
- `Win32VersionValue`=`0` ← LOT-X86-A/SEAL-20261127-A1、LOT-X64-B/SEAL-20261127-B2、LOT-X64-C/SEAL-20261127-C3
- `SizeOfImage`=`8192` ← LOT-X86-A/SEAL-20261127-A1、LOT-X64-B/SEAL-20261127-B2、LOT-X64-C/SEAL-20261127-C3
- `SizeOfHeaders`=`512` ← LOT-X86-A/SEAL-20261127-A1、LOT-X64-B/SEAL-20261127-B2、LOT-X64-C/SEAL-20261127-C3
- `CheckSum`=`47911` ← LOT-X64-B/SEAL-20261127-B2、LOT-X64-C/SEAL-20261127-C3
- `SectionAlignment`=`4096` ← LOT-X86-A/SEAL-20261127-A1、LOT-X64-B/SEAL-20261127-B2、LOT-X64-C/SEAL-20261127-C3
- `FileAlignment`=`512` ← LOT-X86-A/SEAL-20261127-A1、LOT-X64-B/SEAL-20261127-B2、LOT-X64-C/SEAL-20261127-C3
- `DllCharacteristics`=`["IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE", "IMAGE_DLLCHARACTERISTICS_NX_COMPAT", "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE"]` ← LOT-X86-A/SEAL-20261127-A1、LOT-X64-B/SEAL-20261127-B2、LOT-X64-C/SEAL-20261127-C3
- `LoaderFlags`=`0` ← LOT-X86-A/SEAL-20261127-A1、LOT-X64-B/SEAL-20261127-B2、LOT-X64-C/SEAL-20261127-C3

## 旧合同未覆盖、本次仅留证的字段

- `LOT-X86-A`：
  - `linker_version` = `14.0`
  - `time_date_stamp` = `0`
  - `number_of_sections` = `1`
  - `checksum` = `49672`
  - `dll_characteristics` = `["IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE", "IMAGE_DLLCHARACTERISTICS_NX_COMPAT", "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE"]`
  - `section_alignment` = `4096`
  - `file_alignment` = `512`
  - `size_of_image` = `8192`
  - `loader_flags` = `0`
- `LOT-X64-B`：
  - `linker_version` = `14.0`
  - `time_date_stamp` = `0`
  - `number_of_sections` = `1`
  - `checksum` = `47911`
  - `dll_characteristics` = `["IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE", "IMAGE_DLLCHARACTERISTICS_NX_COMPAT", "IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE"]`
  - `section_alignment` = `4096`
  - `file_alignment` = `512`
  - `size_of_image` = `8192`
  - `loader_flags` = `0`
- `LOT-X64-C` 与前述批次值一致，但出处仍独立保留。

## 合同外部证据

- `CL-5.2` 目标工控子系统资产绑定: `unverifiable`
