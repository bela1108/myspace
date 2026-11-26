# 纯转写/记法说明

以下各项的原始记法不同，但规范化后的保护属性相同；只需转写说明，不触发补签。

| 包 | 参数 | 规范值 | 各来源原始记录值 | 接受规则 |
|---|---|---|---|---|
| ARCH-001 | block_size_bytes | 16 | msoffcrypto-live-6.1.0: 16<br>AP-2024-018: "16 字节"<br>msoffcrypto-tool-6.1.0: 16<br>archive-desk-scanner-3.4-historical: "16 字节" | length.bytes_identity |
| ARCH-001 | cipher_chaining | "CBC" | msoffcrypto-live-6.1.0: "ChainingModeCBC"<br>AP-2024-018: "CBC"<br>msoffcrypto-tool-6.1.0: "ChainingModeCBC" | enum.chaining_mode |
| ARCH-001 | encryption_suite | "AES-128-CBC" | msoffcrypto-live-6.1.0: {"cipher_algorithm": "AES", "cipher_chaining": "ChainingModeCBC", "key_length_bits": 128}<br>AP-2024-018: "AES-128-CBC"<br>msoffcrypto-tool-6.1.0: {"cipher_algorithm": "AES", "cipher_chaining": "ChainingModeCBC", "key_length_bits": 128}<br>archive-desk-scanner-3.4-historical: "AES-128-CBC" | suite.aes_description<br>suite.compose_office_attributes |
| ARCH-001 | hash_algorithm | "SHA-1" | msoffcrypto-live-6.1.0: "SHA1"<br>AP-2024-018: "SHA-1"<br>msoffcrypto-tool-6.1.0: "SHA1"<br>archive-desk-scanner-3.4-historical: "SHA-1 摘要算法" | hash.archival_hyphen_identity<br>hash.description_to_archival_hyphen<br>hash.office_to_archival_hyphen |
| ARCH-001 | hash_size_bytes | 20 | msoffcrypto-live-6.1.0: 20<br>AP-2024-018: 20<br>msoffcrypto-tool-6.1.0: 20<br>archive-desk-scanner-3.4-historical: "20 字节" | length.bytes_identity |
| ARCH-001 | key_length_bits | 128 | msoffcrypto-live-6.1.0: 128<br>AP-2024-018: "128 位"<br>msoffcrypto-tool-6.1.0: 128<br>archive-desk-scanner-3.4-historical: {"unit": "字节", "value": 16} | length.bits_identity<br>length.bytes_to_bits |
| ARCH-001 | protection_kind | "agile" | msoffcrypto-live-6.1.0: "agile"<br>AP-2024-018: "Agile"<br>msoffcrypto-tool-6.1.0: "agile"<br>archive-desk-scanner-3.4-historical: "Agile 密码加密" | enum.protection_kind_alias |
| ARCH-001 | salt_length_bytes | 16 | msoffcrypto-live-6.1.0: 16<br>AP-2024-018: "16 字节"<br>msoffcrypto-tool-6.1.0: 16<br>archive-desk-scanner-3.4-historical: "16 字节" | length.bytes_identity |
| ARCH-001 | spin_count | 100000 | msoffcrypto-live-6.1.0: 100000<br>AP-2024-018: 100000<br>msoffcrypto-tool-6.1.0: 100000<br>archive-desk-scanner-3.4-historical: "100000 轮 PBKDF2" | count.decorated_integer<br>count.integer_identity |
| ARCH-002 | block_size_bytes | 16 | msoffcrypto-live-6.1.0: 16<br>AP-2024-019: 16<br>msoffcrypto-tool-6.1.0: 16<br>archive-desk-scanner-3.4-historical: "16 字节" | length.bytes_identity |
| ARCH-002 | cipher_chaining | "CBC" | msoffcrypto-live-6.1.0: "ChainingModeCBC"<br>AP-2024-019: "CBC"<br>msoffcrypto-tool-6.1.0: "ChainingModeCBC" | enum.chaining_mode |
| ARCH-002 | encryption_suite | "AES-256-CBC" | msoffcrypto-live-6.1.0: {"cipher_algorithm": "AES", "cipher_chaining": "ChainingModeCBC", "key_length_bits": 256}<br>AP-2024-019: "AES-256-CBC"<br>msoffcrypto-tool-6.1.0: {"cipher_algorithm": "AES", "cipher_chaining": "ChainingModeCBC", "key_length_bits": 256}<br>archive-desk-scanner-3.4-historical: "AES-256-CBC" | suite.aes_description<br>suite.compose_office_attributes |
| ARCH-002 | hash_algorithm | "SHA-512" | msoffcrypto-live-6.1.0: "SHA512"<br>AP-2024-019: "SHA-512"<br>msoffcrypto-tool-6.1.0: "SHA512"<br>archive-desk-scanner-3.4-historical: "SHA-512 摘要算法" | hash.archival_hyphen_identity<br>hash.description_to_archival_hyphen<br>hash.office_to_archival_hyphen |
| ARCH-002 | hash_size_bytes | 64 | msoffcrypto-live-6.1.0: 64<br>AP-2024-019: 64<br>msoffcrypto-tool-6.1.0: 64<br>archive-desk-scanner-3.4-historical: "64 字节" | length.bytes_identity |
| ARCH-002 | key_length_bits | 256 | msoffcrypto-live-6.1.0: 256<br>AP-2024-019: 256<br>msoffcrypto-tool-6.1.0: 256<br>archive-desk-scanner-3.4-historical: {"unit": "字节", "value": 32} | length.bits_identity<br>length.bytes_to_bits |
| ARCH-002 | protection_kind | "agile" | msoffcrypto-live-6.1.0: "agile"<br>AP-2024-019: "agile"<br>msoffcrypto-tool-6.1.0: "agile"<br>archive-desk-scanner-3.4-historical: "Agile 密码加密" | enum.protection_kind_alias |
| ARCH-002 | salt_length_bytes | 16 | msoffcrypto-live-6.1.0: 16<br>AP-2024-019: 16<br>msoffcrypto-tool-6.1.0: 16<br>archive-desk-scanner-3.4-historical: "16 字节" | length.bytes_identity |
| ARCH-003 | block_size_bytes | 16 | msoffcrypto-live-6.1.0: 16<br>AP-2024-020: 16<br>msoffcrypto-tool-6.1.0: 16<br>archive-desk-scanner-3.4-historical: "16 字节" | length.bytes_identity |
| ARCH-003 | cipher_chaining | "CBC" | msoffcrypto-live-6.1.0: "ChainingModeCBC"<br>AP-2024-020: "CBC"<br>msoffcrypto-tool-6.1.0: "ChainingModeCBC" | enum.chaining_mode |
| ARCH-003 | encryption_suite | "AES-256-CBC" | msoffcrypto-live-6.1.0: {"cipher_algorithm": "AES", "cipher_chaining": "ChainingModeCBC", "key_length_bits": 256}<br>AP-2024-020: "AES-256-CBC"<br>msoffcrypto-tool-6.1.0: {"cipher_algorithm": "AES", "cipher_chaining": "ChainingModeCBC", "key_length_bits": 256}<br>archive-desk-scanner-3.4-historical: "AES-256-CBC" | suite.aes_description<br>suite.compose_office_attributes |
| ARCH-003 | hash_algorithm | "SHA-512" | msoffcrypto-live-6.1.0: "SHA512"<br>AP-2024-020: "SHA-512"<br>msoffcrypto-tool-6.1.0: "SHA512"<br>archive-desk-scanner-3.4-historical: "SHA-512 摘要算法" | hash.archival_hyphen_identity<br>hash.description_to_archival_hyphen<br>hash.office_to_archival_hyphen |
| ARCH-003 | hash_size_bytes | 64 | msoffcrypto-live-6.1.0: 64<br>AP-2024-020: 64<br>msoffcrypto-tool-6.1.0: 64<br>archive-desk-scanner-3.4-historical: "64 字节" | length.bytes_identity |
| ARCH-003 | key_length_bits | 256 | msoffcrypto-live-6.1.0: 256<br>AP-2024-020: 256<br>msoffcrypto-tool-6.1.0: 256<br>archive-desk-scanner-3.4-historical: {"unit": "字节", "value": 32} | length.bits_identity<br>length.bytes_to_bits |
| ARCH-003 | protection_kind | "agile" | msoffcrypto-live-6.1.0: "agile"<br>AP-2024-020: "agile"<br>msoffcrypto-tool-6.1.0: "agile"<br>archive-desk-scanner-3.4-historical: "Agile 密码加密" | enum.protection_kind_alias |
| ARCH-003 | salt_length_bytes | 16 | msoffcrypto-live-6.1.0: 16<br>AP-2024-020: 16<br>msoffcrypto-tool-6.1.0: 16<br>archive-desk-scanner-3.4-historical: "16 字节" | length.bytes_identity |
| ARCH-003 | spin_count | 100000 | msoffcrypto-live-6.1.0: 100000<br>AP-2024-020: 100000<br>msoffcrypto-tool-6.1.0: 100000<br>archive-desk-scanner-3.4-historical: "100000 轮 PBKDF2" | count.decorated_integer<br>count.integer_identity |
