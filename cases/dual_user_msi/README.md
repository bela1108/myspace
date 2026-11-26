# 同机双用户 MSI 核对案卷

这是一份虚构但可复算的小案卷。

## 结论

- Alice 的 alice-installed.lnk 在 ANSI 与 Unicode 两个 Darwin 字段中都指向组件 BBBBBBBB-2222-3333-4444-555555555555，登记行 MSI-registration.txt:12 给出已安装路径。
- Bob 的 bob-advertised-feature.lnk 只有功能名 BobAdvertisedFeature，没有组件号；Bob 的登记停在 MSI-registration.txt:16，状态为 Advertised，没有 installed_path。
- conflicting-encodings-user-vs-machine.lnk 保留冲突：ANSI 形式1指向机器级 AAAAAAAA-1111-2222-3333-444444444444，对应 MSI-registration.txt:7；Unicode 形式2指向 Alice 用户级 BBBBBBBB-2222-3333-4444-555555555555，对应 MSI-registration.txt:12。

## 四种形式

lnk/darwin_forms 下分别放置形式1（功能名+组件号）、形式2（仅组件号）、形式3（仅功能名）和形式4（两者均无）。form3 与 form4 的结论都是 advertised_feature_only，installed_paths 为空。

## 回溯位置

Darwin 块位于最小 LNK 头之后，块偏移为 0x4c；DarwinDataAnsi 字段偏移为 0x54，DarwinDataUnicode 字段偏移为 0x158。JSON 结果中的 source.locator 会给出具体 .lnk 文件、块偏移和字段名；registration_locators 会给回 MSI-registration.txt 的行号。

## 复算

在仓库根目录运行：

    python cases/dual_user_msi/build_case.py
    python -m LnkParse3.offline_check cases/dual_user_msi/lnk/bob-advertised-feature.lnk cases/dual_user_msi/msi_registration_excerpt.json --user bob
    python -m LnkParse3.offline_check cases/dual_user_msi/lnk/conflicting-encodings-user-vs-machine.lnk cases/dual_user_msi/msi_registration_excerpt.json --user alice

verification-report.json 保存七个案卷样例的精简结论与行号。
