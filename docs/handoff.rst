本地交接计划
============

``msoffcrypto.handoff`` 把 msoffcrypto-tool 的格式识别能力接入本地交接流程。它只读取 OLE/OOXML 容器和加密元数据，不调用 ``load_key``、``decrypt`` 或任何口令验证逻辑，因此不会实际解密。

识别范围
--------

识别器输出 ``ProtectionProfile``，包含 Office 容器格式、保护类型、是否加密和允许的密钥类型。

``ecma376_agile``
    加密 OOXML，对应 Agile Encryption，可出现 password、private_key 或 secret_key。
``ecma376_standard``
    加密 OOXML，对应 Standard Encryption，列出 password 和 secret_key。
``rc4``
    Office 97-2003 二进制文档的 RC4 保护。
``rc4_cryptoapi``
    Office 97-2003 二进制文档的 RC4 CryptoAPI 保护。
``xor_obfuscation``
    旧版 XLS 的 XOR 混淆；它不是强加密，仍按证物保护类型单独登记。
``plain``
    未加密文档，只需核验格式和队列状态。

授权阶段
--------

每个部门和每份证物授权都使用明确阶段描述：

``verify_protection``
    仅核验并固定保护类型、容器格式和密钥类型，不转换内容。
``convert``
    允许在满足核验前置条件后执行转换。

备份组只应持有 ``verify_protection``。即使证物授权包含 ``convert``，规划器也不会把转换动作分配给备份组。

队列规则
--------

``transferable``
    证物同时具有核验和转换授权，并且至少一个接收部门具备对应保护类型的 ``convert`` 能力。所有同等符合条件的部门都会生成独立计划，可任选其一交付。
``verifiable``
    备份组可以完成保护核验，但转换授权或可转换部门缺失。系统保留核验计划，并输出必须补签的条件。
``signature_required``
    核验本身缺少证物级授权，或格式无法识别；在补签前不得转交转换。

不可替代条件
------------

规划器只输出不能由其他部门能力替代的条件：

``CASE_VERIFY_AUTH``
    缺少证物级保护核验授权。部门通用权限不能替代该证物授权。
``CASE_PROTECTION_MISMATCH``
    授权表声明的保护类型与实际识别结果不一致，须重新核对并补签。
``CASE_CONVERT_AUTH``
    缺少证物级转换授权。任何部门能力都不能替代该证物授权。
``DEPARTMENT_CAPABILITY``
    缺少具备对应保护类型转换能力且获授权的部门。
``UNRECOGNIZED_FORMAT``
    格式或加密容器无法识别，需要专门鉴定授权。

同类型不同队列示例
------------------

仓库提供虚构授权表演示：

.. code-block:: console

   .venv/bin/python examples/handoff_demo.py

演示把同一个合法示例 ``tests/inputs/rc4cryptoapi_password.doc`` 登记为两份证物：

* ``EX-DOC-701`` 同时具备核验和转换授权，进入 ``transferable``，并生成两个同等可交付的旧 Office 处理部门计划。
* ``EX-DOC-702`` 只具备核验授权，进入 ``verifiable``，备份组可以核验，但输出 ``CASE_CONVERT_AUTH``，等待转换补签。

最小调用示例：

.. code-block:: python

   from msoffcrypto.handoff import (
       ExhibitAuthorization,
       HandoffPlanner,
       HandoffStage,
       Recipient,
       inspect_protection_file,
   )

   profile = inspect_protection_file("evidence.doc")
   backup = Recipient(
       department_id="backup-verify",
       department_name="备份核验组",
       protection_types=frozenset({profile.protection_type}),
       stages=frozenset({HandoffStage.VERIFY_PROTECTION}),
   )
   planner = HandoffPlanner(
       recipients=[],
       backup_team=backup,
       authorizations=[
           ExhibitAuthorization(
               exhibit_id="EX-001",
               protection_type=profile.protection_type,
               stages=frozenset({HandoffStage.VERIFY_PROTECTION}),
           )
       ],
   )
   decision = planner.plan("EX-001", "evidence.doc", profile)
