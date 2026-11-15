import hashlib
import json
from typing import Any

import pytest

import jwt as pyjwt
from jwt.algorithms import get_default_algorithms
from jwt.api_jws import PyJWS
from jwt.exceptions import (
    DPoPError,
    DPoPExpiredError,
    DPoPInvalidAlgorithmError,
    DPoPInvalidATHError,
    DPoPInvalidHTMError,
    DPoPInvalidHTUError,
    DPoPInvalidIATError,
    DPoPInvalidJTIError,
    DPoPInvalidJWKError,
    DPoPInvalidSignatureError,
    DPoPInvalidTypeError,
    DPoPJtiConsumptionError,
    DPoPJtiReplayError,
    DPoPMalformedProofError,
    InvalidSignatureError,
)
from jwt.dpop import (
    DPoPValidator,
    compute_ath,
    normalize_htu,
    validate_dpop_proof,
)
from jwt.utils import base64url_decode, base64url_encode

from .utils import crypto_required, key_path

BASE_URI = "https://api.example.com/resource"
ACCESS_TOKEN = "access-token-a"
OTHER_ACCESS_TOKEN = "access-token-b"
NOW = 1_700_000_000


def _load_private_key(jwk_name: str, algorithm: str) -> Any:
    with open(key_path(jwk_name), encoding="utf-8") as key_file:
        private_jwk = json.load(key_file)
    return get_default_algorithms()[algorithm].from_jwk(private_jwk)


def _public_jwk(private_jwk: dict[str, Any], algorithm: str) -> dict[str, Any]:
    private_key = get_default_algorithms()[algorithm].from_jwk(private_jwk)
    public_key = private_key.public_key()
    return get_default_algorithms()[algorithm].to_jwk(public_key, as_dict=True)


def _default_claims(
    *,
    method: str = "GET",
    uri: str = BASE_URI,
    access_token: str | bytes = ACCESS_TOKEN,
    jti: str = "proof-id-1",
    iat: float = NOW,
) -> dict[str, Any]:
    return {
        "jti": jti,
        "htm": method,
        "htu": uri,
        "iat": iat,
        "ath": compute_ath(access_token),
    }


def _make_proof(
    private_key: Any,
    *,
    algorithm: str = "ES256",
    jwk: dict[str, Any] | None = None,
    method: str = "GET",
    uri: str = BASE_URI,
    access_token: str | bytes = ACCESS_TOKEN,
    jti: str = "proof-id-1",
    iat: float = NOW,
    typ: str = "dpop+jwt",
    claims: dict[str, Any] | None = None,
    extra_headers: dict[str, Any] | None = None,
) -> str:
    if jwk is None:
        raise AssertionError("A public JWK is required for a DPoP proof")

    payload = (
        _default_claims(
            method=method,
            uri=uri,
            access_token=access_token,
            jti=jti,
            iat=iat,
        )
        if claims is None
        else claims
    )
    headers = {"typ": typ, "jwk": jwk}
    if extra_headers is not None:
        headers.update(extra_headers)

    return PyJWS().encode(
        json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        private_key,
        algorithm=algorithm,
        headers=headers,
    )


@pytest.fixture(scope="module")
def ec_private_jwk() -> dict[str, Any]:
    with open(key_path("jwk_ec_key_P-256.json"), encoding="utf-8") as key_file:
        return json.load(key_file)


@pytest.fixture(scope="module")
def ec_private_key(ec_private_jwk: dict[str, Any]) -> Any:
    return get_default_algorithms()["ES256"].from_jwk(ec_private_jwk)


@pytest.fixture(scope="module")
def ec_public_jwk(ec_private_jwk: dict[str, Any]) -> dict[str, Any]:
    return _public_jwk(ec_private_jwk, "ES256")


@pytest.fixture(scope="module")
def rsa_private_jwk() -> dict[str, Any]:
    with open(key_path("jwk_rsa_key.json"), encoding="utf-8") as key_file:
        return json.load(key_file)


@pytest.fixture(scope="module")
def rsa_public_jwk(rsa_private_jwk: dict[str, Any]) -> dict[str, Any]:
    return _public_jwk(rsa_private_jwk, "RS256")


class TestDPoP:
    pytestmark = crypto_required

    def test_valid_proof_and_query_is_not_part_of_htu(
        self, ec_private_key: Any, ec_public_jwk: dict[str, Any]
    ) -> None:
        proof = _make_proof(ec_private_key, jwk=ec_public_jwk)

        payload = validate_dpop_proof(
            proof,
            "GET",
            BASE_URI + "?page=2&sort=asc",
            ACCESS_TOKEN,
            now=NOW,
        )

        assert payload["jti"] == "proof-id-1"
        assert payload["htm"] == "GET"
        assert payload["htu"] == BASE_URI
        assert payload["ath"] == compute_ath(ACCESS_TOKEN)

    def test_validator_class_and_keyword_aliases(
        self, ec_private_key: Any, ec_public_jwk: dict[str, Any]
    ) -> None:
        proof = _make_proof(ec_private_key, jwk=ec_public_jwk)
        validator = DPoPValidator(leeway=0, max_age=300)

        payload = validator.validate(
            proof,
            method="GET",
            uri=BASE_URI,
            access_token=ACCESS_TOKEN,
            now=NOW,
        )
        alias_payload = validate_dpop_proof(
            proof,
            http_method="GET",
            http_uri=BASE_URI,
            token=ACCESS_TOKEN,
            now=NOW,
        )

        assert payload == alias_payload

    def test_htu_is_normalized_by_scheme_host_and_path(
        self, ec_private_key: Any, ec_public_jwk: dict[str, Any]
    ) -> None:
        proof = _make_proof(
            ec_private_key,
            jwk=ec_public_jwk,
            uri="https://API.EXAMPLE.COM:443/~alice/./files/../resource?ignored=1",
        )

        validate_dpop_proof(
            proof,
            "GET",
            "HTTPS://api.example.com:443/%7ealice/resource",
            ACCESS_TOKEN,
            now=NOW,
        )

    def test_normalize_htu_empty_path_and_default_port(self) -> None:
        assert (
            normalize_htu("HTTPS://API.EXAMPLE.COM:443")
            == "https://api.example.com/"
        )
        assert normalize_htu("http://EXAMPLE.com:80/a") == "http://example.com/a"
        assert normalize_htu("https://api.example.com/a?x=1") == (
            "https://api.example.com/a"
        )

    def test_cross_domain_replay_has_htu_failure_code(
        self, ec_private_key: Any, ec_public_jwk: dict[str, Any]
    ) -> None:
        proof = _make_proof(ec_private_key, jwk=ec_public_jwk)

        with pytest.raises(DPoPInvalidHTUError) as exc_info:
            validate_dpop_proof(
                proof,
                "GET",
                "https://other.example.com/resource",
                ACCESS_TOKEN,
                now=NOW,
            )

        assert exc_info.value.code == "invalid_dpop_htu"
        assert "htu" in str(exc_info.value)

    def test_token_swap_has_ath_failure_code(
        self, ec_private_key: Any, ec_public_jwk: dict[str, Any]
    ) -> None:
        proof = _make_proof(ec_private_key, jwk=ec_public_jwk)

        with pytest.raises(DPoPInvalidATHError) as exc_info:
            validate_dpop_proof(
                proof,
                "GET",
                BASE_URI,
                OTHER_ACCESS_TOKEN,
                now=NOW,
            )

        assert exc_info.value.code == "invalid_dpop_ath"
        assert "ath" in str(exc_info.value)

    def test_replayed_jti_has_independent_replay_failure_code(
        self, ec_private_key: Any, ec_public_jwk: dict[str, Any]
    ) -> None:
        proof = _make_proof(ec_private_key, jwk=ec_public_jwk)
        consumed: set[str] = set()

        def consume(jti: str) -> bool:
            if jti in consumed:
                return False
            consumed.add(jti)
            return True

        validate_dpop_proof(
            proof,
            "GET",
            BASE_URI,
            ACCESS_TOKEN,
            consume,
            now=NOW,
        )

        with pytest.raises(DPoPJtiReplayError) as exc_info:
            validate_dpop_proof(
                proof,
                "GET",
                BASE_URI,
                ACCESS_TOKEN,
                consume,
                now=NOW,
            )

        assert exc_info.value.code == "dpop_jti_replayed"
        assert not isinstance(exc_info.value, DPoPInvalidSignatureError)
        assert not isinstance(exc_info.value, InvalidSignatureError)

    def test_replay_failure_codes_are_distinct(
        self, ec_private_key: Any, ec_public_jwk: dict[str, Any]
    ) -> None:
        proof = _make_proof(ec_private_key, jwk=ec_public_jwk)
        codes: set[str] = set()

        with pytest.raises(DPoPError) as htu_error:
            validate_dpop_proof(
                proof,
                "GET",
                "https://other.example.com/resource",
                ACCESS_TOKEN,
                now=NOW,
            )
        codes.add(htu_error.value.code)

        with pytest.raises(DPoPError) as ath_error:
            validate_dpop_proof(
                proof,
                "GET",
                BASE_URI,
                OTHER_ACCESS_TOKEN,
                now=NOW,
            )
        codes.add(ath_error.value.code)

        consumed = {"proof-id-1"}
        with pytest.raises(DPoPError) as replay_error:
            validate_dpop_proof(
                proof,
                "GET",
                BASE_URI,
                ACCESS_TOKEN,
                lambda jti: jti not in consumed,
                now=NOW,
            )
        codes.add(replay_error.value.code)

        assert codes == {
            "invalid_dpop_htu",
            "invalid_dpop_ath",
            "dpop_jti_replayed",
        }

    def test_jti_consumer_failure_is_not_a_signature_failure(
        self, ec_private_key: Any, ec_public_jwk: dict[str, Any]
    ) -> None:
        proof = _make_proof(ec_private_key, jwk=ec_public_jwk)

        def consume(jti: str) -> None:
            raise RuntimeError("jti storage is unavailable")

        with pytest.raises(DPoPJtiConsumptionError) as exc_info:
            validate_dpop_proof(
                proof,
                "GET",
                BASE_URI,
                ACCESS_TOKEN,
                consume,
                now=NOW,
            )

        assert exc_info.value.code == "dpop_jti_consumption_failed"
        assert isinstance(exc_info.value.__cause__, RuntimeError)
        assert not isinstance(exc_info.value, InvalidSignatureError)
        assert not isinstance(exc_info.value, DPoPInvalidSignatureError)

    def test_jti_is_not_consumed_until_all_other_checks_pass(
        self, ec_private_key: Any, ec_public_jwk: dict[str, Any]
    ) -> None:
        proof = _make_proof(ec_private_key, jwk=ec_public_jwk)
        consumed: list[str] = []

        with pytest.raises(DPoPInvalidHTUError):
            validate_dpop_proof(
                proof,
                "GET",
                "https://other.example.com/resource",
                ACCESS_TOKEN,
                consumed.append,
                now=NOW,
            )

        assert consumed == []

    def test_htm_mismatch(
        self, ec_private_key: Any, ec_public_jwk: dict[str, Any]
    ) -> None:
        proof = _make_proof(ec_private_key, jwk=ec_public_jwk, method="GET")

        with pytest.raises(DPoPInvalidHTMError) as exc_info:
            validate_dpop_proof(
                proof, "POST", BASE_URI, ACCESS_TOKEN, now=NOW
            )

        assert exc_info.value.code == "invalid_dpop_htm"

    def test_iat_must_be_recent_and_not_in_the_future(
        self, ec_private_key: Any, ec_public_jwk: dict[str, Any]
    ) -> None:
        stale_proof = _make_proof(
            ec_private_key, jwk=ec_public_jwk, iat=NOW - 301
        )
        future_proof = _make_proof(
            ec_private_key, jwk=ec_public_jwk, iat=NOW + 1
        )
        invalid_proof = _make_proof(
            ec_private_key,
            jwk=ec_public_jwk,
            claims={
                **_default_claims(),
                "iat": "not-a-number",
            },
        )

        with pytest.raises(DPoPInvalidIATError) as stale_error:
            validate_dpop_proof(
                stale_proof,
                "GET",
                BASE_URI,
                ACCESS_TOKEN,
                leeway=0,
                now=NOW,
            )
        assert stale_error.value.code == "invalid_dpop_iat"

        with pytest.raises(DPoPInvalidIATError):
            validate_dpop_proof(
                future_proof,
                "GET",
                BASE_URI,
                ACCESS_TOKEN,
                leeway=0,
                now=NOW,
            )

        with pytest.raises(DPoPInvalidIATError):
            validate_dpop_proof(
                invalid_proof,
                "GET",
                BASE_URI,
                ACCESS_TOKEN,
                now=NOW,
            )

    def test_expired_proof_is_rejected(
        self, ec_private_key: Any, ec_public_jwk: dict[str, Any]
    ) -> None:
        proof = _make_proof(
            ec_private_key,
            jwk=ec_public_jwk,
            claims={
                **_default_claims(),
                "exp": NOW - 1,
            },
        )

        with pytest.raises(DPoPExpiredError) as exc_info:
            validate_dpop_proof(
                proof,
                "GET",
                BASE_URI,
                ACCESS_TOKEN,
                leeway=0,
                now=NOW,
            )

        assert exc_info.value.code == "invalid_dpop_exp"

    @pytest.mark.parametrize(
        ("claim", "error_type", "code"),
        [
            ("htm", DPoPInvalidHTMError, "invalid_dpop_htm"),
            ("htu", DPoPInvalidHTUError, "invalid_dpop_htu"),
            ("iat", DPoPInvalidIATError, "invalid_dpop_iat"),
            ("ath", DPoPInvalidATHError, "invalid_dpop_ath"),
            ("jti", DPoPInvalidJTIError, "invalid_dpop_jti"),
        ],
    )
    def test_missing_required_claim(
        self,
        ec_private_key: Any,
        ec_public_jwk: dict[str, Any],
        claim: str,
        error_type: type[DPoPError],
        code: str,
    ) -> None:
        claims = _default_claims()
        del claims[claim]
        proof = _make_proof(
            ec_private_key,
            jwk=ec_public_jwk,
            claims=claims,
        )

        with pytest.raises(error_type) as exc_info:
            validate_dpop_proof(
                proof, "GET", BASE_URI, ACCESS_TOKEN, now=NOW
            )

        assert exc_info.value.code == code
        assert claim in str(exc_info.value)

    def test_private_key_material_in_jwk_is_rejected(
        self,
        ec_private_key: Any,
        ec_private_jwk: dict[str, Any],
    ) -> None:
        proof = _make_proof(ec_private_key, jwk=ec_private_jwk)

        with pytest.raises(DPoPInvalidJWKError) as exc_info:
            validate_dpop_proof(
                proof, "GET", BASE_URI, ACCESS_TOKEN, now=NOW
            )

        assert exc_info.value.code == "invalid_dpop_jwk"
        assert "public" in str(exc_info.value)

    def test_symmetric_algorithm_is_rejected(
        self, ec_public_jwk: dict[str, Any]
    ) -> None:
        proof = _make_proof(
            "a" * 32,
            algorithm="HS256",
            jwk={"kty": "oct", "k": base64url_encode(b"secret").decode("ascii")},
        )

        with pytest.raises(DPoPInvalidAlgorithmError) as exc_info:
            validate_dpop_proof(
                proof, "GET", BASE_URI, ACCESS_TOKEN, now=NOW
            )

        assert exc_info.value.code == "invalid_dpop_alg"

    def test_algorithm_must_match_jwk_key_family(
        self,
        ec_private_key: Any,
        rsa_public_jwk: dict[str, Any],
    ) -> None:
        proof = _make_proof(
            ec_private_key,
            algorithm="ES256",
            jwk=rsa_public_jwk,
        )

        with pytest.raises(DPoPInvalidAlgorithmError) as exc_info:
            validate_dpop_proof(
                proof, "GET", BASE_URI, ACCESS_TOKEN, now=NOW
            )

        assert exc_info.value.code == "invalid_dpop_alg"
        assert "RSA" in str(exc_info.value)

    def test_jwk_alg_must_match_header_alg(
        self, ec_private_key: Any, ec_public_jwk: dict[str, Any]
    ) -> None:
        jwk = {**ec_public_jwk, "alg": "RS256"}
        proof = _make_proof(ec_private_key, jwk=jwk)

        with pytest.raises(DPoPInvalidAlgorithmError) as exc_info:
            validate_dpop_proof(
                proof, "GET", BASE_URI, ACCESS_TOKEN, now=NOW
            )

        assert exc_info.value.code == "invalid_dpop_alg"

    def test_ec_curve_must_match_algorithm(
        self, ec_private_key: Any, ec_public_jwk: dict[str, Any]
    ) -> None:
        jwk = {**ec_public_jwk, "crv": "P-384"}
        proof = _make_proof(ec_private_key, jwk=jwk)

        with pytest.raises(DPoPInvalidAlgorithmError) as exc_info:
            validate_dpop_proof(
                proof, "GET", BASE_URI, ACCESS_TOKEN, now=NOW
            )

        assert exc_info.value.code == "invalid_dpop_alg"
        assert "P-256" in str(exc_info.value)

    def test_wrong_typ_is_rejected(
        self, ec_private_key: Any, ec_public_jwk: dict[str, Any]
    ) -> None:
        proof = _make_proof(
            ec_private_key,
            jwk=ec_public_jwk,
            typ="JWT",
        )

        with pytest.raises(DPoPInvalidTypeError) as exc_info:
            validate_dpop_proof(
                proof, "GET", BASE_URI, ACCESS_TOKEN, now=NOW
            )

        assert exc_info.value.code == "invalid_dpop_typ"

    def test_jwk_indirection_headers_are_rejected(
        self, ec_private_key: Any, ec_public_jwk: dict[str, Any]
    ) -> None:
        proof = _make_proof(
            ec_private_key,
            jwk=ec_public_jwk,
            extra_headers={"jku": "https://attacker.example/jwks.json"},
        )

        with pytest.raises(DPoPInvalidJWKError) as exc_info:
            validate_dpop_proof(
                proof, "GET", BASE_URI, ACCESS_TOKEN, now=NOW
            )

        assert exc_info.value.code == "invalid_dpop_jwk"
        assert "jku" in str(exc_info.value)

    @pytest.mark.parametrize(
        "uri",
        [
            "https://user:password@api.example.com/resource",
            "https://api.example.com/resource#fragment",
            "https://api.example.com/resource#",
        ],
    )
    def test_userinfo_and_fragments_are_rejected(
        self,
        ec_private_key: Any,
        ec_public_jwk: dict[str, Any],
        uri: str,
    ) -> None:
        proof = _make_proof(ec_private_key, jwk=ec_public_jwk)

        with pytest.raises(DPoPInvalidHTUError) as exc_info:
            validate_dpop_proof(
                proof, "GET", uri, ACCESS_TOKEN, now=NOW
            )

        assert exc_info.value.code == "invalid_dpop_htu"

    @pytest.mark.parametrize(
        "htu",
        [
            "https://user:password@api.example.com/resource",
            "https://api.example.com/resource#fragment",
        ],
    )
    def test_userinfo_and_fragments_in_claimed_htu_are_rejected(
        self,
        ec_private_key: Any,
        ec_public_jwk: dict[str, Any],
        htu: str,
    ) -> None:
        proof = _make_proof(ec_private_key, jwk=ec_public_jwk, uri=htu)

        with pytest.raises(DPoPInvalidHTUError) as exc_info:
            validate_dpop_proof(
                proof, "GET", BASE_URI, ACCESS_TOKEN, now=NOW
            )

        assert exc_info.value.code == "invalid_dpop_htu"

    def test_tampered_signature_is_rejected(
        self, ec_private_key: Any, ec_public_jwk: dict[str, Any]
    ) -> None:
        proof = _make_proof(ec_private_key, jwk=ec_public_jwk)
        header_segment, _, signature_segment = proof.split(".")
        other_proof = _make_proof(
            ec_private_key,
            jwk=ec_public_jwk,
            jti="proof-id-2",
        )
        _, other_payload_segment, _ = other_proof.split(".")

        tampered = ".".join(
            [header_segment, other_payload_segment, signature_segment]
        )

        with pytest.raises(DPoPInvalidSignatureError) as exc_info:
            validate_dpop_proof(
                tampered, "GET", BASE_URI, ACCESS_TOKEN, now=NOW
            )

        assert exc_info.value.code == "invalid_dpop_signature"

    def test_malformed_proof_is_rejected(
        self, ec_public_jwk: dict[str, Any]
    ) -> None:
        with pytest.raises(DPoPMalformedProofError) as exc_info:
            validate_dpop_proof(
                "not-a-compact-jws",
                "GET",
                BASE_URI,
                ACCESS_TOKEN,
                now=NOW,
            )

        assert exc_info.value.code == "invalid_dpop_proof"

    def test_compute_ath_matches_sha256(self) -> None:
        expected = base64url_encode(
            hashlib.sha256(ACCESS_TOKEN.encode("ascii")).digest()
        ).decode("ascii")

        assert compute_ath(ACCESS_TOKEN) == expected
        assert base64url_decode(expected) == hashlib.sha256(
            ACCESS_TOKEN.encode("ascii")
        ).digest()


def test_plain_jwt_decode_is_unaffected() -> None:
    token = pyjwt.encode({"sub": "user-1"}, "a" * 32, algorithm="HS256")

    assert pyjwt.decode(token, "a" * 32, algorithms=["HS256"]) == {
        "sub": "user-1"
    }
    assert pyjwt.get_unverified_header(token)["typ"] == "JWT"
