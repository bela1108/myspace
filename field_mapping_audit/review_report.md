# Field mapping review for merged log source

## Static mapping classification

- SourceIp -> newlog.ip [merge-ip-fields] | guard: Logsource(product=newlog)
- DestinationIp -> newlog.ip [merge-ip-fields] | guard: Logsource(product=newlog)
- ClientIp -> newlog.ip [merge-ip-fields] | guard: Logsource(product=newlog)
- Image -> newlog.path [merge-path-fields] | guard: Logsource(product=newlog)
- TargetFilename -> newlog.path [merge-path-fields] | guard: Logsource(product=newlog)
- UserName -> newlog.user [rename-user] | guard: Logsource(product=newlog)
- CommandLine -> newlog.cmd -> newlog.cmd_raw [fanout-commandline] | guard: Logsource(product=newlog)
- ComputerName -> newlog.host [conditional-computername-tag] | guard: Logsource(product=newlog) AND ContainsWildcard(cond=any)

### Reversible (target uniquely identifies source)
- newlog.host <- ComputerName
- newlog.user <- UserName

### Many-to-one collisions (source identity lost)
- newlog.ip <- ClientIp, DestinationIp, SourceIp
- newlog.path <- Image, TargetFilename

### Fan-out (one source expands to several targets)
- CommandLine -> newlog.cmd, newlog.cmd_raw
## Backend trace (source condition -> converted field)

| rule | selector | branch | source field | target field | value | processing items |
| --- | --- | --- | --- | --- | --- | --- |
| Network Lateral Movement Over SMB | selection | OR > AND > AND | SourceIp | newlog.ip | 10.0.0.1 | merge-ip-fields |
| Network Lateral Movement Over SMB | selection | OR > AND > AND | SourceIp | newlog.ip | 10.0.0.2 | merge-ip-fields |
| Network Lateral Movement Over SMB | selection | AND > AND | DestinationIp | newlog.ip | 192.168.10.7 | merge-ip-fields |
| Network Lateral Movement Over SMB | selection | AND > AND | DestinationPort | DestinationPort | 445 | - |
| Network Lateral Movement Over SMB | filter_local | AND | DestinationIp | newlog.ip | 127.0.0.0/8 | merge-ip-fields |
| Outbound SSH From Server | selection | AND | SourceIp | newlog.ip | 198.51.100.9 | merge-ip-fields |
| Outbound SSH From Server | selection | AND | DestinationIp | newlog.ip | 203.0.113.4 | merge-ip-fields |
| Outbound SSH From Server | selection | AND | DestinationPort | DestinationPort | 22 | - |
| File Drop By Authenticated User | selection | AND > AND | UserName | newlog.user | svc_deploy | rename-user |
| File Drop By Authenticated User | selection | AND > AND | ComputerName | ComputerName | build-host-01 | - |
| File Drop By Authenticated User | selection | AND > AND | TargetFilename | newlog.path | /var/tmp/agent.sh | merge-path-fields |
| File Drop By Authenticated User | host_pattern | AND | ComputerName | newlog.host | build-* | conditional-computername-tag |
| Client IP Login Without User Context | selection | AND | ClientIp | newlog.ip | 203.0.113.9 | merge-ip-fields |
| Client IP Login Without User Context | selection | AND | ComputerName | ComputerName | edge-gateway | - |
| Suspicious Command Execution By Lateral Tooling | selection | OR > OR > AND > AND | CommandLine | newlog.cmd | *psexec* | fanout-commandline |
| Suspicious Command Execution By Lateral Tooling | selection | OR > OR > AND > AND | CommandLine | newlog.cmd | *wmiprvse* | fanout-commandline |
| Suspicious Command Execution By Lateral Tooling | selection | OR > OR > AND > AND | CommandLine | newlog.cmd_raw | *psexec* | fanout-commandline |
| Suspicious Command Execution By Lateral Tooling | selection | OR > OR > AND > AND | CommandLine | newlog.cmd_raw | *wmiprvse* | fanout-commandline |
| Suspicious Command Execution By Lateral Tooling | selection | AND > AND | Image | newlog.path | *\cmd.exe | merge-path-fields |
| Suspicious Command Execution By Lateral Tooling | filter_null | OR > AND | CommandLine | newlog.cmd | null | fanout-commandline |
| Suspicious Command Execution By Lateral Tooling | filter_null | OR > AND | CommandLine | newlog.cmd_raw | null | fanout-commandline |

## Minimal collision evidence

### target `newlog.ip` (many-to-one target)
colliding source fields: ClientIp, DestinationIp, SourceIp
- witness: rule `Network Lateral Movement Over SMB` selector `selection` branch `OR > AND > AND` source `SourceIp` value `10.0.0.1` items `merge-ip-fields`
- witness: rule `Network Lateral Movement Over SMB` selector `selection` branch `AND > AND` source `DestinationIp` value `192.168.10.7` items `merge-ip-fields`
- witness: rule `Client IP Login Without User Context` selector `selection` branch `AND` source `ClientIp` value `203.0.113.9` items `merge-ip-fields`

### target `newlog.path` (many-to-one target)
colliding source fields: Image, TargetFilename
- witness: rule `File Drop By Authenticated User` selector `selection` branch `AND > AND` source `TargetFilename` value `/var/tmp/agent.sh` items `merge-path-fields`
- witness: rule `Suspicious Command Execution By Lateral Tooling` selector `selection` branch `AND > AND` source `Image` value `*\cmd.exe` items `merge-path-fields`


## Conditional transformation firing paths

- processing item `conditional-computername-tag` (fired)
  - edge ComputerName -> newlog.host (guard: Logsource(product=newlog) AND ContainsWildcard(cond=any))
  - fired on rules: File Drop By Authenticated User
  - selectors touched: host_pattern
  - boolean branches: AND
  - skipped source paths (guard not satisfied, field kept):
    * rule `File Drop By Authenticated User` selector `selection` source `ComputerName` stays `ComputerName` value `build-host-01`
    * rule `Client IP Login Without User Context` selector `selection` source `ComputerName` stays `ComputerName` value `edge-gateway`
- processing item `fanout-commandline` (fired)
  - edge CommandLine -> newlog.cmd, newlog.cmd_raw (guard: Logsource(product=newlog))
  - fired on rules: Suspicious Command Execution By Lateral Tooling
  - selectors touched: filter_null, selection
  - boolean branches: OR > AND, OR > OR > AND > AND
- processing item `merge-ip-fields` (fired)
  - edge SourceIp -> newlog.ip (guard: Logsource(product=newlog))
  - edge DestinationIp -> newlog.ip (guard: Logsource(product=newlog))
  - edge ClientIp -> newlog.ip (guard: Logsource(product=newlog))
  - fired on rules: Client IP Login Without User Context, Network Lateral Movement Over SMB, Outbound SSH From Server
  - selectors touched: filter_local, selection
  - boolean branches: AND, AND > AND, OR > AND > AND
- processing item `merge-path-fields` (fired)
  - edge Image -> newlog.path (guard: Logsource(product=newlog))
  - edge TargetFilename -> newlog.path (guard: Logsource(product=newlog))
  - fired on rules: File Drop By Authenticated User, Suspicious Command Execution By Lateral Tooling
  - selectors touched: selection
  - boolean branches: AND > AND
- processing item `rename-user` (fired)
  - edge UserName -> newlog.user (guard: Logsource(product=newlog))
  - fired on rules: File Drop By Authenticated User
  - selectors touched: selection
  - boolean branches: AND > AND
## Converted queries (fake backend output)

1. ('newlog.ip' in ("10.0.0.1", "10.0.0.2")) and 'newlog.ip'="192.168.10.7" and DestinationPort=445 and not cidrmatch('newlog.ip', "127.0.0.0/8")
2. 'newlog.ip'="198.51.100.9" and 'newlog.ip'="203.0.113.4" and DestinationPort=22
3. 'newlog.user'="svc_deploy" and ComputerName="build-host-01" and 'newlog.path'="/var/tmp/agent.sh" and 'newlog.host' startswith "build-"
4. 'newlog.ip'="203.0.113.9" and ComputerName="edge-gateway"
5. ('newlog.cmd' in ("*psexec*", "*wmiprvse*") or 'newlog.cmd_raw' in ("*psexec*", "*wmiprvse*")) and 'newlog.path' endswith "\cmd.exe" and not ('newlog.cmd' is null or 'newlog.cmd_raw' is null)