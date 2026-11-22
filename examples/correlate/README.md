# Offline metadata entity correlator

这个目录演示如何在不信任旧 token 的前提下，对比同一个程序集的两个编译版本。

## 两个小样本

- `samples/old/Correlate.Sample.dll`
- `samples/new/Correlate.Sample.dll`

样本只包含元数据和一个 `ret` 方法体，但具有完整的 PE/CLR 头和元数据流，dnfile 可以像解析普通程序集一样解析它们。样本刻意包含：

- `StableService` 和 `Compute`：语义不变，但 TypeDef/MethodDef/Field/Property token 全部发生变化，应输出 `renumbered_only`。
- `Outer+GenericBox`：嵌套类型被重新排序，泛型参数、约束行和 TypeRef token 也被重排，仍应按名字和结构对应。
- `LegacyApi.Process`：参数类型、返回类型和局部变量真实变化，应输出 `signature_changed`。
- `Ambiguous.Handle`：两个同名、同签名、同局部声明的方法，无法仅凭结构区分，必须保留多选并标记 `ambiguous_same_name`。

重新生成样本：

```sh
python examples/correlate/build_samples.py
```

## 导出实体对应表

```sh
PYTHONPATH=src python -m dnfile.correlate \
  examples/correlate/samples/old/Correlate.Sample.dll \
  examples/correlate/samples/new/Correlate.Sample.dll \
  -o examples/correlate/entity-map.csv
```

也可以使用对象接口：

```python
from dnfile.correlate import EntityCorrelator

correlator = EntityCorrelator("old.dll", "new.dll")
result = correlator.correlate()
correlator.export("entity-map.json")
```

`result.matches` 中每条记录都带有 `comparisons`：

- `namespace_equal`
- `signature_equal`
- `locals_equal`
- `generic_constraints_equal`
- `semantic_equal`
- `projection_equal`
- `token_equal`

CSV 是长表：一个歧义组会为每个候选写一行，使用相同 `group_id`，`candidate_count` 大于 1，`target_token` 不同。JSON 则把候选放在 `candidates` 数组中。

## 状态含义

| status | 含义 |
| --- | --- |
| `unchanged` | token 与结构都没有变化 |
| `renumbered_only` | token 改变，但命名空间、签名、局部声明、泛型约束和结构投影一致 |
| `metadata_changed` | 语义签名一致，但名字、可见性等元数据有变化 |
| `signature_changed` | 同名实体仍然存在，但签名或局部声明真实变化 |
| `ambiguous_same_name` | 多个候选证据等价，保留多选，需要人工判断 |
| `unmatched_old` | 旧版本实体在新版本没有同名候选 |
| `unmatched_new` | 新版本实体在旧版本没有同名候选 |

## 为什么不使用旧 token

匹配前会分别构建两版视图。签名里的 TypeDefOrRef、TypeSpec、嵌套类型和 GenericParam 约束都在各自版本内解析成结构名，例如：

```text
class System.Collections.Generic.List<valuetype System.Int32>
```

因此旧版本 token 只作为“token 是否变化”的证据，不参与跨版本查找。嵌套类型通过 NestedClass 关系还原为 `Namespace.Outer+Inner`，泛型约束通过约束所有者、参数位置、参数名和约束类型名投影，而不是通过 GenericParam/TypeDefOrRef 的旧编号。
