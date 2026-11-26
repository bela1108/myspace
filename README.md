# Python 后端安全项目题集

20 道题，分别基于 20 个项目在本仓库的固定提交。每题的起始代码可从快照打开。基线命令从对应项目根目录运行，使用已装好该项目测试依赖的 Python 环境。

## 01　策略刷新之后，哪条配置还受管

地狱 · 安全风控与治理策略 · Python, python-registry

域策略撤掉一项保密配置后，终端留下了旧值。究竟是策略又写了回来，还是那次刷新根本没管到它？给 python-registry 做离线对账。输入一份起始 hive、一次刷新后的 hive 和按实际应用顺序登记的 Registry.pol 文件，只支持普通赋值、删除指定值和清空某键下的值。保留值类型及原字节，分别处理机器与用户作用域；对照政策已经撤出但会保留的本地值，别把所有未声明项都算漂移。每个判断都应落到最后一条有效指令，缺一个中间策略文件时仍要算出哪些值被后续明确赋值重新确定。用先清空再回填与相反次序的两组结果验收。

[项目起始快照](https://github.com/bela1108/myspace/commit/bac6a5d56f1f1e89281c809da063bea8a958fd0c)

基线验证

```sh
python -m pytest -q tests/test_parse.py tests/test_parse_timestamp.py tests/test_unicode_names.py
```

## 02　广告快捷方式对应哪一份安装登记

困难 · 数字取证 · Python, LnkParse3

这个快捷方式究竟指向已安装的组件，还是只登记了以后可以安装的功能？请在 LnkParse 的 Python 读取接口旁加一项离线核对，吃进 .lnk 和随案提供的 MSI 登记摘录，摘录按计算机、用户、产品、功能及组件分层。保留 Darwin 块两种编码各自的主张，用现有解码器处理带或不带功能名和组件号的四种形式。遇到用户级与机器级同产品不同登记、两种编码指向不同组件，结果里要能分别点回原块和登记行。做一份同机双用户的小案卷，其中只登记广告功能的那位应当查不到已安装路径。

[项目起始快照](https://github.com/bela1108/myspace/commit/9b0d80ed7e0cecd069ee417737be925faa267675)

基线验证

```sh
python -m pytest -q tests/test_samples.py
```

## 03　从 Outlook 原件还原回复关系

地狱 · 数字取证 · Python, olefile

法务交来一摞 Outlook 的 .msg，两封邮件主题一样，导出时又把一封原信作为附件塞进了回复。想从 olefile 的 storage/stream 入口重建哪些回复关系有原件支持。分别读取每个消息 storage 的 ConversationIndex、Message-ID 和引用头，区分索引的一层子段、只见到祖先前缀，以及纯文本引用的主张。缺一封中间邮件时保留空位，遇到复制件或同一 Message-ID 配不同索引时保留矛盾双方，附件里的属性只归附件那封。交付时给一棵四封信的小树，抽走父件再放回，原有的独立分支和取证定位都应保持稳定。

[项目起始快照](https://github.com/bela1108/myspace/commit/8fb8ad7b5624f7ca5c5adbe5e19adde83f5aea1f)

基线验证

```sh
python -m pytest -q tests/test_olefile.py
```

## 04　从通话证物中扣留电话按键帧

地狱 · 数字取证 · Python, dpkt

录音交付前要扣下电话按键相关的帧，以前只认一种 RTP payload type，换了一次媒体配置就对不上了。请在 dpkt 的离线读取层接入一份受限的 SIP/SDP 核对：只收已保存的 INVITE、最终应答、ACK 和单路音频，按 dialog、方向、媒体端点建立动态类型映射。支持一次重新协商和一次分叉应答；题目测试会提供各采集段的有效切换边界，边界有重叠或缺应答时保守扣留。输出只列可交付或须扣留的帧号及相应信令出处。两条对话把同一个 PT 分别给普通音频和 telephone-event，调换输入文件枚举顺序后，结论应照旧，报告里不出现载荷和按键值。

[项目起始快照](https://github.com/bela1108/myspace/commit/ab564f0dc949ede2b4d2d164468a8d1c1a5d078b)

基线验证

```sh
python -m pytest -q -o addopts= dpkt/sip.py dpkt/rtp.py dpkt/pcap.py::test_pcap_endian
```

## 05　检查设备状态变更的审计凭据

地狱 · 漏洞利用与缓解 · Python, pycparser

一段设备配置 C 代码把十几处失败都跳到同一个 cleanup，人工审查已经数不清哪一次写入留下了审计凭据。约定每次受保护写入成功须恰好记账一次，写入失败或被回滚须零次，操作按配置中的资源参数配对。基于 pycparser 做个能被后端调用的静态检查，输入预处理后的短函数和标出“变更、撤回、提交凭据”的函数合同。每次生效变更必须恰好配一张凭据，已撤回变更不得再算成功。检查条件跳转、循环的零次及多次迭代、提前返回，以及一层本地辅助函数；外部调用缺合同就注明证明到哪里中断。请用正常的合成配置代码演示漏记、重复记、回滚干净和无法判定四种结论，每个有问题的出口附一条能沿源码读通的路径。

[项目起始快照](https://github.com/bela1108/myspace/commit/cb1f9fdd99d30e69fc0f407013861be2b32df369)

基线验证

```sh
python -m pytest -q tests/test_c_lexer.py tests/test_c_parser.py tests/test_c_ast.py
```

## 06　找出 dataclass 日志中实际可见的敏感字段

困难 · 漏洞利用与缓解 · Python, Bandit, AST

把业务对象直接交给日志记录器后，团队才发现父类藏好的字段被一个 dataclass 子类重新声明出来了。请在 Bandit 的正常扫描里加一条可配置规则，检查合成项目中标成敏感的字段何时进入 %r 或 !r 形式的日志。从真实的 dataclass 导入及别名出发，处理继承覆盖、字段和类两级 repr 设置、嵌套对象与显式 __repr__；遇到分析范围之外的自定义实现，给出依据不足的原因。验收时会把日志点保持不动，只替换父类声明或嵌套字段设置。报告应能指回最终起作用的那一行，安全替换后同一个日志点应该安静。

[项目起始快照](https://github.com/bela1108/myspace/commit/7d75bb8abd09532e9d983568001da8b7f7755816)

基线验证

```sh
python -m pytest -q tests/unit/core/test_blacklisting.py tests/unit/core/test_manager.py tests/unit/core/test_context.py tests/unit/core/test_issue.py tests/functional/test_functional.py
```

## 07　静态检查缓存键中的租户隔离

地狱 · 漏洞利用与缓解 · Python, DLint, AST

同事说“租户号已经传给查询函数了”，可缓存装在它外面，只收一个订单号。请让 dlint 静态复核这类 Python 后端代码。用小配置声明按租户隔离的数据读取入口，覆盖 functools.cache、lru_cache 和一个显式声明键形状的本地包装器。沿参数绑定和一层辅助调用核对，每个会改变读出内容的租户维度是否真的参与了对应缓存的键；还要分清实例绑定、关键字默认值和内部二次缓存。对于能判定的漏项，正常 flake8 输出应标出缓存位置，并举出会共用键的两组符号调用。测试只用虚构租户，不连接缓存服务。

[项目起始快照](https://github.com/bela1108/myspace/commit/120e19b5baaec5c54199b9ffff474ff597ca9d93)

基线验证

```sh
python -m pytest -q tests/test_bad_eval_use.py tests/test_bad_exec_use.py tests/test_bad_input_use.py tests/test_bad_cryptography_module_attribute_use.py tests/test_bad_defusedxml_use.py
```

## 08　密钥托管设备退役前的恢复预演

困难 · 安全风控与治理策略 · Python, pycose

准备撤下两台密钥托管设备，库房盘点却只报了“每份档案都有两个 recipient”。在 pycose 加一个供归档服务调用的退役预演，读已经登记的 COSE_Encrypt 收件树以及调用方给的 key id、密钥版本、托管域对应表。解释嵌套包装的依赖和并列收件人的替代关系，碰到表中明确共用硬件的两个别名只能算一个失效域。针对指定退役集合，列出仍有登记恢复路径的档案，求出能让每份档案失去全部已知路径的最小域集合；有未识别算法时保留未知项。只读消息头，用四个虚构域的所有下线组合校对结果。

[项目起始快照](https://github.com/bela1108/myspace/commit/14e93de3e650a89e87edb11d709e1e9c1f276dfc)

基线验证

```sh
python -m pytest -q tests/test_attributes.py tests/test_cosemessage.py tests/test_enc0message.py
```

## 09　从 SBOM 核查受限数据是否跨区

地狱 · 安全风控与治理策略 · Python, CycloneDX

供应商在 SBOM 里勾了服务跨信任边界，隐私组追问的是客户地址究竟会不会从库房一路传到外部理赔方。请给 cyclonedx-python-lib 的 BOM 消费端加一项审查，读取 Service.data 的方向和类别，再接收一份本地路由合同，列明接口两端、信任区和允许的数据转换。只在发送、接收与合同吻合时延伸路径，缺一端声明单列待补证；循环调用要能终止，两类数据共线时，一类获准降级不能替另一类放行。让审核员从结果反查第一处跨区及上游依据。JSON 导出读回后重算，应能逐条复查同一份违规见证。

[项目起始快照](https://github.com/bela1108/myspace/commit/4b61ef1ddf53dec82d00f646aeb75a226ec153f2)

基线验证

```sh
python -m pytest -q tests/test_model_bom.py tests/test_output_json.py tests/test_deserialize_json.py
```

## 10　PDF 摘页后的专栏阅读顺序

困难 · 数字取证 · Python, pypdf

第 3 页有两篇专栏各占半页，摘出去作证后，阅读器把第二篇的下半截接到了第一篇。沿 pypdf 已有的 threads 和摘页接口做一份文章线索核对单。按原文的首 bead 与前后链接取阅读顺序，同时核对每一段指向的页、矩形及页侧 /B 登记；合法的首尾相接、提前绕回中间、只有单边引用要分别交代。对指定摘页序列重新打开写出的 PDF，指出每篇保留了哪些原段、哪里发生断档。拿两篇共页、其中一篇跨页的内存 PDF 验证，调换物理页序后仍要能读出各自的原文顺序。

[项目起始快照](https://github.com/bela1108/myspace/commit/a49e5664e98c5eef5173bca2d301769ffe176fde)

基线验证

```sh
python -c 'from io import BytesIO; from pypdf import PdfReader, PdfWriter; f=BytesIO(); w=PdfWriter(); w.add_blank_page(72, 72); w.add_attachment("evidence.txt", b"test"); w.write(f); f.seek(0); r=PdfReader(f); assert len(r.pages)==1 and r.attachments["evidence.txt"]==[b"test"]; print("in-memory PDF round trip passed")'
```

## 11　鉴定固件中 COMDAT 代码的来源

地狱 · 二进制/固件逆向 · Python, pyelftools

两家代工厂都说固件里那段校准代码来自自己的 .o，两份对象的 COMDAT 签名甚至一样。请用 pyelftools 做离线来源鉴定。输入限定为同架构的可重定位 ELF、已发布 ELF 和一张只给出部分成员输出区间的链接摘录。结合组成员、节内字节和已知重定位槽比较，忽略的字节要说明由哪条重定位覆盖；同名成员不得按出现顺序硬配。给出目前能排除谁、尚有哪几种成员对应及理由。一组样件只在重定位槽不同，另一组在槽外差一个字节，这两组的结论必须能让审查人看出区别，全程只读文件。

[项目起始快照](https://github.com/bela1108/myspace/commit/35e6d47a1258d09774c5341f74f61d653b879f76)

基线验证

```sh
python -m unittest discover -s test -p test_gnuversions.py
```

## 12　核对双语 PE 文件的版本标签

困难 · 数字取证 · Python, pefile

供应商交过来一个 PE 文件，资产系统抄的是英文产品版本，现场人员拍到的却是另一种语言的文件版本。想请 pefile 给取证后端提供一个版本标签查证接口。从所有 RT_VERSION 资源读固定数值、StringFileInfo 和 VarFileInfo 的 Translation，保留资源语种与字符串表语言、代码页这两个层次；调用方能指定语言偏好、允许的回退、要查的是文件还是产品。重号表、缺少 Translation、两个资源对同一标签说法不一都应带候选出处。拿一个双语样件换两套偏好查，把“标签来自哪里”和“固定字段是否支持它”分栏返回。

[项目起始快照](https://github.com/bela1108/myspace/commit/a413ee450664922afd55ba5f216c292dbfc11817)

基线验证

```sh
python -m pytest -q tests/import_test.py tests/export_test.py tests/signature_matching_test.py tests/test_section_names.py
```

## 13　托管诊断字段的存储重叠

地狱 · 二进制/固件逆向 · Python, dnfile

固件附带一个托管诊断组件，采集单批准读取 Status 字段，安全组怀疑它与另一个未授权字段共用了存储。把 dnfile 的元数据读取接成一个静态范围核对接口，支持标量、固定大小的嵌套显式布局值类型和按目标指针宽度变化的字段。用 FieldLayout、ClassLayout 及字段签名找出批准读取的每段字节还可能属于谁；缺类型或碰到本题未支持的自动布局，标明不确定范围及来源，不能用本机位数补齐。验收用一个含嵌套联合布局的合成程序集，分别按 32 位、64 位出图，两个视图应在指出差异的同时保留完全相同的字段令牌。

[项目起始快照](https://github.com/bela1108/myspace/commit/82720b14a5c788e25b92812520b9cf66c6b487af)

基线验证

```sh
python -m pytest -q tests/test_utils.py
```

## 14　交班时谁在目录组里

地狱 · 数字取证 · Python, python-evtx

我需要复核某天交班时 AD 组里到底有哪些成员。手头只有两台域控的 EVTX 摘录和前后两份独立盘点。沿 python-evtx 的记录读取及 XML 视图处理 5136 的加值、删值，按对象 GUID、属性、域控和操作关联号整理，保留没有凑成一对的事件。限定在盘点和事件里出现过的成员，对指定时点区分一定存在、可能存在和已能排除；缺采区间可以发生未观察到的变更，副本上的两条相似事件不能擅自当作全局有序。用三个成员做可穷举的小案子，一个在目标时点有分歧，另一个在两种解释中都在组里，结论都得能追到原记录。

[项目起始快照](https://github.com/bela1108/myspace/commit/05412e997c3546cf105647e51e769613a767a758)

基线验证

```sh
python -m pytest -q tests/test_header.py tests/test_chunks.py tests/test_records.py::test_parse_record tests/test_records.py::test_render_record
```

## 15　两份告警汇总能否推知个人记录

地狱 · 安全风控与治理策略 · Python, pySigma

昨天给甲组发了规则命中总数，今天乙组要看“相同范围但去掉夜班”的数。两份报表单看人数都够，一相减却可能暴露某一名值班员是否触发告警。在 pySigma 的离线匹配结果上做发布前审查。限定一个小型固定人员全集、每人是否命中这一位，以及版本固定的分组，接收已经公开的精确计数和候选计数。若联立后能把原本仍有两种取值的某人唯一确定，就拒发并指出必要的一组旧报表；可发时才记入账本，重复请求沿用旧回执。用六名虚构人员的全部赋值做独立对照，也试一次分组改名但成员已换的情况。

[项目起始快照](https://github.com/bela1108/myspace/commit/a604cd61d918be62e593057b1d1893447a0fe28e)

基线验证

```sh
python -m pytest -q tests/test_conditions.py tests/test_processing_tracking.py tests/test_correlations.py
```

## 16　门限密钥的销毁声明能否成立

地狱 · 安全风控与治理策略 · Python, signedjson

旧备份卷的销毁报告写着“三把钥匙已经销掉两把”，但其中一份以前复制给过异地库房。我们用 signedjson 签收托管清册，想让后台能复核这种门限销毁声明。材料只含虚构份额编号、拆分批次、恢复门限、带父回执的复制或转移记录和销毁回执，不读任何密钥。销毁一份副本只影响那个保管位置；同一份额的镜像只算一个编号，换代前后的份额不能拼用。按指定截止点和清册完整性，求仍能恢复的最小保管域组合，区分已证不可恢复和回执不足；签名有效却引用错误副本或互相冲突的回执要留给复核。用两代三取二的小清册，分别撤掉原件、镜像和一条交接回执，三个结论应能逐份举证。

[项目起始快照](https://github.com/bela1108/myspace/commit/68f8ff3ef39b1dc62a4deb82ce6b97dfe830b1f8)

基线验证

```sh
python -m pytest -q tests
```

## 17　并行构建记录能否还原为一条发布历史

地狱 · 安全风控与治理策略 · Python, in-toto

发布复盘会上有人问，三个平行构建步骤的 link 都签得对，能不能证明它们读到的是同一条发布历史？在 in-toto 验证通过之后加一项一致性核对。输入初始路径摘要、材料和产物齐全的有限步骤集、已知先后限制及最终摘要。每个步骤的材料要在它执行前同时成立，产物在步骤末一并生效；同一路径可以改回旧摘要。求至少一种完整次序，能有多种时标明，实在排不出来则给一份能逐步重放的无解说明，列出每个可达前缀接下来卡在哪项材料或最终摘要。用不超过六步的样例同全排列对照，包含两步各读到对方旧值、单看签名和摘要都无误的那组。

[项目起始快照](https://github.com/bela1108/myspace/commit/f75249c7f8a65ab2662f7a4d508fdda20a52226e)

基线验证

```sh
python -m pytest -q tests/models/test_metadata.py tests/test_param_substitution.py tests/test_rulelib.py
```

## 18　阴性扫描结果中漏检文件数的上界

困难 · 安全风控与治理策略 · Python, detect-secrets

审计员问的是“这批被扫成阴性的文件里最多还可能漏掉多少份”，现有候选复核率答不了。给 detect-secrets 写一条离线验收链，把冻结版文件清单、扫描完成凭据、分层无放回抽样记录和独立盲审结果对齐，以文件为单位。调用方为各层分配显著性水平，总和不得超过整批预算；用精确超几何尾概率给出可复算的单侧上界。区分抽到多处问题的同一文件、漏扫文件、被抽中却缺复核结论的文件。缺盲审结果的抽中项按可能漏检处理，漏扫项在置信界外单报。用十个虚构文件全枚举校对覆盖率与边界取整，给审计方的结果只含分层计数和上界，不带样本文本。

[项目起始快照](https://github.com/bela1108/myspace/commit/9f15942878c0c204ffbf54f2fdb01c870d27e2c8)

基线验证

```sh
python -m pytest -q tests/core/scan_test.py tests/core/potential_secret_test.py tests/plugins/jwt_test.py tests/filters/regex_filter_test.py
```

## 19　跨签发域的代码发布策略复核

地狱 · 安全风控与治理策略 · Python, asn1crypto

旧厂和新厂给同一项代码发布资质用了不同的策略 OID，审计人把叶证书里出现任意一个编号都当成过审。请基于 asn1crypto 做一个离线的证书政策回放接口，输入调用方已经验证签名和有效期的有序路径、起始可接受策略以及初始计数，只审 RFC 5280 的证书策略处理。需要解释 policyMappings、anyPolicy、显式策略要求和自签发中间证书对计数推进的影响，保存被剪掉的分支和它最后的证书位置。给两条能到达同一叶子的短路径，一条允许编号映射，另一条提前抑制；再插入一个自签发但非自签名的中间证书，应看得出哪个计数该保持。审核员要能沿结果还原一条真正成立的策略链。

[项目起始快照](https://github.com/bela1108/myspace/commit/70035a5fc87e9bc4cf062523d407a411072071c4)

基线验证

```sh
python -m pytest -q tests/test_core.py tests/test_parser.py tests/test_x509.py
```

## 20　离线安全更新的分片恢复与原子交付

地狱 · 顺带涉及上下游链路 · Python, python-tuf

边远站点靠离线介质装安全更新，三盒里总有一盒晚到。给 python-tuf 的目标下载流程加一种可选交付格式：已经受信的 target 自定义元数据列出数据块的顺序、长度、摘要，以及每组一个按最长块零填充生成的 XOR 校验块。允许乱序送达和断点续交，单组少一片时恢复并核对片摘要；仍须通过现有目标长度和整包摘要验证才可替换旧件。题目只要求本地内存 fetcher。演示一个末片较短的包，在恢复后、发布前模拟掉电，再换入同路径不同摘要的元数据继续启动；旧包何时可读、新包何时可见，两点要能从测试里看清楚。

[项目起始快照](https://github.com/bela1108/myspace/commit/1fc7faa8f52827e61648f7e46c0471d76627a7d1)

基线验证

```sh
python -m pytest -q tests/test_metadata_serialization.py tests/test_trusted_metadata_set.py tests/test_updater_fetch_target.py tests/test_updater_delegation_graphs.py
```
