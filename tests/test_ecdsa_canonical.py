from typing import Any

import pytest

from jwt.algorithms import has_crypto
from jwt.exceptions import InvalidSignatureError
from jwt.utils import base64url_decode, base64url_encode

from .utils import crypto_required, key_path

if has_crypto:
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePrivateKey,
        EllipticCurvePublicKey,
    )
    from cryptography.hazmat.primitives.asymmetric.utils import (
        encode_dss_signature,
    )

    from jwt.algorithms import ECAlgorithm, get_default_algorithms
    from jwt.api_jws import PyJWS


P256_ORDER = int(
    "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551",
    16,
)
SECP256K1_ORDER = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
    16,
)
P384_ORDER = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "C7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
    16,
)
P521_ORDER = int(
    "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
    "FFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB7"
    "1E91386409",
    16,
)

CURVES = [
    pytest.param(
        "ES256",
        "jwk_ec_key_P-256.json",
        "jwk_ec_pub_P-256.json",
        P256_ORDER,
        id="ES256-P-256",
    ),
    pytest.param(
        "ES256K",
        "jwk_ec_key_secp256k1.json",
        "jwk_ec_pub_secp256k1.json",
        SECP256K1_ORDER,
        id="ES256K-secp256k1",
    ),
    pytest.param(
        "ES384",
        "jwk_ec_key_P-384.json",
        "jwk_ec_pub_P-384.json",
        P384_ORDER,
        id="ES384-P-384",
    ),
    pytest.param(
        "ES512",
        "jwk_ec_key_P-521.json",
        "jwk_ec_pub_P-521.json",
        P521_ORDER,
        id="ES512-P-521",
    ),
]


def load_ec_key(filename: str) -> Any:
    with open(key_path(filename)) as keyfile:
        return ECAlgorithm.from_jwk(keyfile.read())


def split_signature(signature: bytes) -> tuple[int, int, int]:
    num_bytes = len(signature) // 2
    r = int.from_bytes(signature[:num_bytes], "big")
    s = int.from_bytes(signature[num_bytes:], "big")
    return r, s, num_bytes


@crypto_required
@pytest.mark.parametrize(
    "algorithm, private_file, public_file, order",
    CURVES,
)
class TestCanonicalECDSA:
    def test_sign_emits_fixed_width_low_s(
        self,
        algorithm: str,
        private_file: str,
        public_file: str,
        order: int,
    ) -> None:
        private_key = load_ec_key(private_file)
        public_key = load_ec_key(public_file)

        assert isinstance(private_key, EllipticCurvePrivateKey)
        assert isinstance(public_key, EllipticCurvePublicKey)

        algorithm_obj = get_default_algorithms()[algorithm]

        for _ in range(4):
            signature = algorithm_obj.sign(b"canonical message", private_key)
            r, s, num_bytes = split_signature(signature)

            assert len(signature) == 2 * num_bytes
            assert 0 < r < order
            assert 0 < s <= order // 2
            assert algorithm_obj.verify(b"canonical message", public_key, signature)

    def test_high_s_counterpart_is_rejected(
        self,
        algorithm: str,
        private_file: str,
        public_file: str,
        order: int,
    ) -> None:
        private_key = load_ec_key(private_file)
        public_key = load_ec_key(public_file)
        algorithm_obj = get_default_algorithms()[algorithm]

        signature = algorithm_obj.sign(b"canonical message", private_key)
        r, s, num_bytes = split_signature(signature)
        high_s = order - s
        high_signature = r.to_bytes(num_bytes, "big") + high_s.to_bytes(
            num_bytes, "big"
        )

        assert high_signature != signature
        assert not algorithm_obj.verify(
            b"canonical message", public_key, high_signature
        )
        assert (
            algorithm_obj.verify(b"canonical message", public_key, signature)
            + algorithm_obj.verify(b"canonical message", public_key, high_signature)
            == 1
        )

    def test_der_and_non_compact_forms_are_rejected(
        self,
        algorithm: str,
        private_file: str,
        public_file: str,
        order: int,
    ) -> None:
        private_key = load_ec_key(private_file)
        public_key = load_ec_key(public_file)
        algorithm_obj = get_default_algorithms()[algorithm]

        signature = algorithm_obj.sign(b"canonical message", private_key)
        r, s, num_bytes = split_signature(signature)
        der_signature = encode_dss_signature(r, s)
        point_like = b"\x02" + signature[:num_bytes]
        uncompressed_point_like = b"\x04" + signature + signature

        for invalid_signature in (
            der_signature,
            signature + b"\x00",
            signature[:-1],
            point_like,
            uncompressed_point_like,
        ):
            assert not algorithm_obj.verify(
                b"canonical message", public_key, invalid_signature
            )

    def test_out_of_range_and_zero_scalars_are_rejected(
        self,
        algorithm: str,
        private_file: str,
        public_file: str,
        order: int,
    ) -> None:
        private_key = load_ec_key(private_file)
        public_key = load_ec_key(public_file)
        algorithm_obj = get_default_algorithms()[algorithm]

        signature = algorithm_obj.sign(b"canonical message", private_key)
        r, s, num_bytes = split_signature(signature)
        zero = b"\x00" * num_bytes
        order_bytes = order.to_bytes(num_bytes, "big")

        invalid_signatures = (
            zero + signature[num_bytes:],
            signature[:num_bytes] + zero,
            order_bytes + signature[num_bytes:],
            signature[:num_bytes] + order_bytes,
            signature[:num_bytes] + (order // 2 + 1).to_bytes(num_bytes, "big"),
        )
        for invalid_signature in invalid_signatures:
            assert not algorithm_obj.verify(
                b"canonical message", public_key, invalid_signature
            )


@crypto_required
def test_jws_uses_one_error_for_all_malformed_ecdsa_signatures() -> None:
    with open(key_path("jwk_ec_key_P-256.json")) as keyfile:
        private_key = ECAlgorithm.from_jwk(keyfile.read())
    with open(key_path("jwk_ec_pub_P-256.json")) as keyfile:
        public_key = ECAlgorithm.from_jwk(keyfile.read())

    jws = PyJWS()
    token = jws.encode(b"canonical message", private_key, algorithm="ES256")
    header, payload, encoded_signature = token.split(".")
    signature = base64url_decode(encoded_signature)
    r, s, num_bytes = split_signature(signature)
    high_signature = r.to_bytes(num_bytes, "big") + (P256_ORDER - s).to_bytes(
        num_bytes, "big"
    )

    invalid_signatures = (
        high_signature,
        encode_dss_signature(r, s),
        signature + b"\x00",
        b"\x00" * num_bytes + signature[num_bytes:],
        P256_ORDER.to_bytes(num_bytes, "big") + signature[num_bytes:],
    )

    for invalid_signature in invalid_signatures:
        mutated = ".".join(
            (header, payload, base64url_encode(invalid_signature).decode())
        )
        with pytest.raises(InvalidSignatureError) as exc_info:
            jws.decode(mutated, public_key, algorithms=["ES256"])
        assert str(exc_info.value) == "Signature verification failed"

    assert jws.decode(token, public_key, algorithms=["ES256"]) == b"canonical message"
