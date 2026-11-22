# 案卷证词依赖核对 (STIX 本地数据源)

针对早期观察记录日期写错、后被更正的场景，对依赖它的上层证词做
更正前 / 更正后两阶段的依赖图复核。

## 文件

- `testimony.py` — 自定义 STIX 对象 `x-testimony`:证词声明自己需要的
  独立来源数量 (`required_independent_sources`),引用通过
  `citations[].source_ref + version` 绑定到具体观察版本。
- `build_casefile.py` — 生成 `casefile.json`(更正前案卷)与
  `correction.json`(E_A 的更正版 v2)。
- `audit.py` — 把案卷装入本地 `MemoryStore`,按版本解析引用、构建
  依赖图,输出 `audit_report.md`。

## 核对规则

- 引用只在所绑定的版本存在、未撤销、且未被更正取代时有效。
- 证词的独立支撑 = 经有效引用可达的不同证物叶节点
  (`observed-data`)数量;来源互相引用不产生新的证物叶,不能凭空
  凑足所需证物。
- 更正(E_A 发 v2)后,绑定 v1 的引用断链,下游有备用证物的证词
  只掉一路。

## 运行

```sh
../.venv/bin/python build_casefile.py
../.venv/bin/python audit.py
```

结论见 `audit_report.md`:T1 该重审、T2 仍有独立支撑、T3 仍差材料,
三条均可追到具体证物节点。
