# 合成演练告警摘要核对报告

核对方法：以 pySigma 公开 API 加载两代处理配置（gen1 换版前 / gen2 现行），
对每个分组字段与记录字段构造合成 Sigma 规则并应用处理管线，
解析结果取自管线的 FieldMappingTracking 跟踪（pipeline.field_mappings）。

## 一、已有摘要分组核对

| 摘要 | 接收组 | 分组字段 | 核对结论 |
| --- | --- | --- | --- |
| SUM-01 登录失败源地址聚类 | 安全组 | src_ip | `src_ip` -> 允许字段 `src_ip`，支持配置：上一代配置(gen1)+现行配置(gen2) |
| SUM-02 外部连接源聚类 | 安全组 | source_ip | `source_ip` -> 允许字段 `src_ip`，支持配置：上一代配置(gen1)+现行配置(gen2) |
| SUM-03 主机负载异常分组 | 运维组 | client | `client` -> 允许字段 `host`，支持配置：上一代配置(gen1) |
| SUM-04 外部节点告警聚合 | 安全组 | origin | `origin` -> 候选：`dst_ip`（现行配置(gen2)）；`src_ip`（上一代配置(gen1)） |
| SUM-05 对端通信聚类 | 安全组 | peer | `peer` -> 候选：`dst_ip`（现行配置(gen2)）；`src_ip`（现行配置(gen2)） |
| SUM-06 工作站离线分组 | 运维组 | workstation_id | `workstation_id` -> 来源丢失：两代配置均无此别名，且非规范允许字段 |
| SUM-07 服务重启分组 | 运维组 | host, service | `host` -> 允许字段 `host`，支持配置：上一代配置(gen1)+现行配置(gen2)<br>`service` -> 允许字段 `service`，支持配置：上一代配置(gen1)+现行配置(gen2) |

## 二、待确认记录核对

### REC-101（运维组，换版后采集器直报）

- `client_host` -> 允许字段 `host`，支持配置：现行配置(gen2)
- `svc` -> 允许字段 `service`，支持配置：上一代配置(gen1)+现行配置(gen2)
- 记录结论：已确认

### REC-102（运维组，换版前遗留格式）

- `client` -> 允许字段 `host`，支持配置：上一代配置(gen1)
- `result` -> 允许字段 `status`，支持配置：上一代配置(gen1)
- 记录结论：已确认

### REC-103（安全组，别名 origin 在两代配置中含义不同）

- `origin` -> 候选：`dst_ip`（现行配置(gen2)）；`src_ip`（上一代配置(gen1)）
- `account_name` -> 允许字段 `user`，支持配置：上一代配置(gen1)+现行配置(gen2)
- 记录结论：候选（待核验）

### REC-104（安全组，peer 在现行配置下为一对多映射）

- `peer` -> 候选：`dst_ip`（现行配置(gen2)）；`src_ip`（现行配置(gen2)）
- `proc` -> 允许字段 `process_name`，支持配置：上一代配置(gen1)+现行配置(gen2)
- 记录结论：候选（待核验）

### REC-105（运维组，workstation_id 来源待查）

- `workstation_id` -> 来源丢失：两代配置均无此别名，且非规范允许字段
- `event_status` -> 允许字段 `status`，支持配置：现行配置(gen2)
- 记录结论：来源丢失（待核验）

### REC-106（安全组，规范字段与两代别名混用）

- `user` -> 允许字段 `user`，支持配置：上一代配置(gen1)+现行配置(gen2)
- `source_ip` -> 允许字段 `src_ip`，支持配置：上一代配置(gen1)+现行配置(gen2)
- 记录结论：已确认

## 三、保留结果：多种别名导致的候选

- SUM-04：`origin` -> 候选：`dst_ip`（现行配置(gen2)）；`src_ip`（上一代配置(gen1)）
- SUM-05：`peer` -> 候选：`dst_ip`（现行配置(gen2)）；`src_ip`（现行配置(gen2)）
- REC-103：`origin` -> 候选：`dst_ip`（现行配置(gen2)）；`src_ip`（上一代配置(gen1)）
- REC-104：`peer` -> 候选：`dst_ip`（现行配置(gen2)）；`src_ip`（现行配置(gen2)）

## 四、保留结果：来源丢失

- SUM-06：`workstation_id` -> 来源丢失：两代配置均无此别名，且非规范允许字段
- REC-105：`workstation_id` -> 来源丢失：两代配置均无此别名，且非规范允许字段

## 五、待核验清单

- SUM-04：候选（待核验）
- SUM-05：候选（待核验）
- SUM-06：来源丢失（待核验）
- REC-103：候选（待核验）
- REC-104：候选（待核验）
- REC-105：来源丢失（待核验）
