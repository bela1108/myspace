# coding: utf-8
"""
Builds the paired PKCS#12 inventory fixtures.

The two archives deliberately share the same outer encrypted ContentInfo and
the same PKCS#12 integrity MAC. They differ only in the publicly visible
encryption algorithm of the inner pkcs8ShroudedKeyBag.
"""

from __future__ import unicode_literals, division, absolute_import, print_function

import os

from asn1crypto import cms, keys, pkcs12


HERE = os.path.dirname(os.path.abspath(__file__))

INNER_SALT = b"inner-salt-000001"
OUTER_SALT = b"outer-salt-000001"
OUTER_IV = b"outer-iv-0000001"
CIPHER_IV = b"cipher-iv-000001"
MAC_SALT = b"mac-salt-0000001"
MAC_VALUE = b"\x00" * 32


def _pbkdf2_params(salt, iterations):
    return {
        "algorithm": "pbkdf2",
        "parameters": {
            "salt": {"specified": salt},
            "iteration_count": iterations,
            "key_length": 32,
            "prf": {"algorithm": "sha256"},
        },
    }


def _pbes2(cipher, iv):
    return {
        "algorithm": "pbes2",
        "parameters": {
            "key_derivation_func": _pbkdf2_params(OUTER_SALT, 120000),
            "encryption_scheme": {
                "algorithm": cipher,
                "parameters": iv,
            },
        },
    }


def _legacy_pkcs12(cipher, salt, iterations):
    return {
        "algorithm": cipher,
        "parameters": {
            "salt": salt,
            "iterations": iterations,
        },
    }


def _attributes(label, key_id):
    return [
        {"type": "friendly_name", "values": [label]},
        {"type": "local_key_id", "values": [key_id]},
    ]


def _safe_contents(inner_algorithm, label, key_id):
    shrouded_key = keys.EncryptedPrivateKeyInfo({
        "encryption_algorithm": inner_algorithm,
        "encrypted_data": b"sealed-private-key-material",
    })
    bag = pkcs12.SafeBag({
        "bag_id": "pkcs8_shrouded_key_bag",
        "bag_value": shrouded_key,
        "bag_attributes": _attributes(label, key_id),
    })
    return pkcs12.SafeContents([bag])


def build(inner_algorithm, label, key_id):
    sealed = cms.ContentInfo({
        "content_type": "encrypted_data",
        "content": {
            "version": "v0",
            "encrypted_content_info": {
                "content_type": "data",
                "content_encryption_algorithm": _pbes2("aes256_cbc", OUTER_IV),
                "encrypted_content": b"sealed-authenticated-safe-entry",
            },
        },
    })

    readable_safe_contents = _safe_contents(inner_algorithm, label, key_id)
    readable = cms.ContentInfo({
        "content_type": "data",
        "content": readable_safe_contents.dump(),
    })

    authenticated_safe = pkcs12.AuthenticatedSafe([sealed, readable])
    auth_safe = cms.ContentInfo({
        "content_type": "data",
        "content": authenticated_safe.dump(),
    })

    return pkcs12.Pfx({
        "version": "v3",
        "auth_safe": auth_safe,
        "mac_data": {
            "mac": {
                "digest_algorithm": {"algorithm": "sha256"},
                "digest": MAC_VALUE,
            },
            "mac_salt": MAC_SALT,
            "iterations": 120000,
        },
    })


def main():
    weak = build(
        _legacy_pkcs12("pkcs12_sha1_rc2_40", INNER_SALT, 2048),
        "shared outer - weak inner",
        b"weak-inner-key-id"
    )
    strong = build(
        _pbes2("aes256_cbc", CIPHER_IV),
        "shared outer - strong inner",
        b"strong-inner-key-id"
    )

    for name, pfx in (
        ("shared-outer-weak-inner.p12", weak),
        ("shared-outer-strong-inner.p12", strong),
    ):
        path = os.path.join(HERE, name)
        with open(path, "wb") as f:
            f.write(pfx.dump())


if __name__ == "__main__":
    main()
