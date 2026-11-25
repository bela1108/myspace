# 离线 ABI 核对（基于 pefile）

当一个 Windows 扩展 DLL 换版后导出“名称看起来差不多”，但老组件里有一部分
只按序号（ordinal）绑定时，本工具用 pefile 在离线环境核对新旧两个版本的
导出声明，回答：哪个符号身份在旧系统上仍然可用。

## 核对输入

调用方被明确拆成两类合成调用者，各自用 JSON 清单枚举：

- fixtures/manifests/by_name.json：按名调用，经导出名称表绑定；
- fixtures/manifests/by_ordinal.json：按序号调用，只经导出地址表序号绑定。

每条引用包含 caller、binding（name/ordinal）、target 与说明。

## 覆盖的四类核对点

1. 导出声明差异：稳定、序号保留但改名、删除、新增；
2. 重名别名：同一名称映射到多个序号，按名解析有歧义；
3. 显式前转：模块.符号 或 模块.#序号，并判断前转目标模块是否在本次
   离线模块集合内（在集合内为“已确认”，否则为“目标未确认”）；
4. 未确认的目标引用：调用方引用的名称/序号在对应版本根本不存在，或前转
   目标模块缺失，离线无法继续追踪。

## 短夹具的关键设计

fixtures/fixture.py 中，序号 4 在新旧两版都保留，但名称由
WidgetCompute 改为 WidgetComputeV2。因此读取两套调用条件会得到相反结论：

- 按名调用 WidgetCompute → RENAMED_ORDINAL_KEPT，新版按名不可解析，
  在旧系统按名不可用；
- 按序号调用 #4 → ORDINAL_STABLE，序号槽位仍在，旧系统按序号仍可用。

夹具同时包含重名别名（序号 2、3 同名 WidgetAlias）、纯序号导出（序号 7，
无名称表项）、已确认前转（legacy.OldFunc，离线提供 legacy.dll）、未确认
前转（extmissing.#9，离线无该模块）、删除项（序号 8）、新增项（序号 9）。

## 用法

生成夹具 DLL（纯 Python 构造的最小 PE32，无需编译器、无需联网）：

    python -m abi_check.cli generate-fixtures

核对（--extra-module 提供用于确认前转目标的离线模块）：

    python -m abi_check.cli check \
        abi_check/fixtures/generated/widget_v1.dll \
        abi_check/fixtures/generated/widget_v2.dll \
        abi_check/fixtures/manifests/by_name.json \
        --extra-module abi_check/fixtures/generated/legacy.dll

    python -m abi_check.cli check \
        abi_check/fixtures/generated/widget_v1.dll \
        abi_check/fixtures/generated/widget_v2.dll \
        abi_check/fixtures/manifests/by_ordinal.json \
        --extra-module abi_check/fixtures/generated/legacy.dll \
        --json report.json

## 模块说明

- pe_builder.py：最小 PE32 DLL 生成器，支持普通命名导出、重名别名、
  纯序号导出、显式前转与导出地址表空洞；
- checker.py：装载两版导出、按名/按序号分别判定、前转确认、报告渲染；
- fixtures/：夹具定义、合成调用者清单与生成产物（产物不入库）；
- cli.py：命令行入口；
- 状态码与中文文案见 statuses.py。
