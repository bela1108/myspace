# .NET 自定义特性归属核对

- 样本: `tests/security_fixture.py (generated fixture; original sample/report files were not present)`
- 方式: dnfile 只读解析; 未执行样本代码
- 偏移: `blob` 为相对 CA 值负载起点, `file` 为原始文件绝对偏移

## 1. 标记挂在程序集上

### `Acme.Security.SecurityMarkerAttribute`

- 程序集/作用域: `Shared.Security, Version=1.0.0.0, Culture=neutral, PublicKeyToken=1122334455667788`

- 属性行: `CustomAttribute[1]` token `0x0c000001` file `0x356`
- 作用对象: `Assembly[1]` token `0x20000001` file `0x36a` AttributionFixture, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
- 结论: Parent 解析到 Assembly，标记作用于整个程序集。
- 构造器: `MemberRef[1]` token `0x0a000001` file `0x344` signature file `0x469`
- 类型身份: `Acme.Security.SecurityMarkerAttribute` scope `Shared.Security, Version=1.0.0.0, Culture=neutral, PublicKeyToken=1122334455667788`
- 引用链: `TypeRef[1] Acme.Security.SecurityMarkerAttribute` -> `AssemblyRef[1] Shared.Security, Version=1.0.0.0, Culture=neutral, PublicKeyToken=1122334455667788`
- 可解释参数:
  - `fixed` `System.String` = `'assembly'`; blob `[0x2,0xb)`; file `[0x476, 0x47f)`
  - `fixed` `System.Boolean` = `True`; blob `[0xb,0xc)`; file `[0x47f, 0x480)`
  - `named-property Level` `System.Int32` = `7`; blob `[0xe,0x1a)`; file `[0x482, 0x48e)`


## 2. 只挂在成员上

### `Acme.Security.SecurityMarkerAttribute`

- 程序集/作用域: `Vendor.Security, Version=1.0.0.0, Culture=neutral, PublicKeyToken=aabbccddeeff0011`

- 属性行: `CustomAttribute[2]` token `0x0c000002` file `0x35c`
- 作用对象: `MethodDef[1]` token `0x06000001` file `0x328` Guarded
- 结论: Parent 不是 Assembly，只覆盖当前成员。
- 成员所有者: `Fixture.MarkerHost` (AttributionFixture, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null)
- 构造器: `MemberRef[2]` token `0x0a000002` file `0x34a` signature file `0x469`
- 类型身份: `Acme.Security.SecurityMarkerAttribute` scope `Vendor.Security, Version=1.0.0.0, Culture=neutral, PublicKeyToken=aabbccddeeff0011`
- 引用链: `TypeRef[2] Acme.Security.SecurityMarkerAttribute` -> `AssemblyRef[2] Vendor.Security, Version=1.0.0.0, Culture=neutral, PublicKeyToken=aabbccddeeff0011`
- 可解释参数:
  - `fixed` `System.String` = `'member'`; blob `[0x2,0x9)`; file `[0x491, 0x498)`
  - `fixed` `System.Boolean` = `False`; blob `[0x9,0xa)`; file `[0x498, 0x499)`
  - `named-property Scope` `System.String` = `'method'`; blob `[0xc,0x1b)`; file `[0x49b, 0x4aa)`


## 3. 一条引用不足以证明归属

### `Acme.Security.SecurityMarkerAttribute`

- 程序集/作用域: `module-ref:peer.netmodule:TypeRef#3`

- 属性行: `CustomAttribute[3]` token `0x0c000003` file `0x362`
- 作用对象: `MethodDef[2]` token `0x06000002` file `0x336` MaybeGuarded
- 结论: 引用链不足以确定构造器所属程序集，不能证明归属。
- 成员所有者: `Fixture.MarkerHost` (AttributionFixture, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null)
- 构造器: `MemberRef[3]` token `0x0a000003` file `0x350` signature file `0x469`
- 类型身份: `Acme.Security.SecurityMarkerAttribute` scope `peer.netmodule`
- 引用链: `TypeRef[3] Acme.Security.SecurityMarkerAttribute` -> `ModuleRef[1] peer.netmodule`
- 备注: ModuleRef identifies a netmodule, not the owning assembly; value blob is partial; verified arguments and raw offsets are retained
- 可解释参数:
  - `fixed` `System.String` = `'maybe'`; blob `[0x2,0x8)`; file `[0x4ad, 0x4b3)`
- 未解部分: `unexpected end of blob at offset 8` 起始 blob offset `0x8` file `0x4b3`

