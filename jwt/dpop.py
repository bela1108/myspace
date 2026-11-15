from __future__ import annotations

import hashlib
import hmac
import inspect
import json
import math
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from .api_jwk import PyJWK
from .api_jws import PyJWS
from .exceptions import (
    DecodeError,
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
    DPoPJtiReuseError,
    DPoPMalformedProofError,
    DPoPProofError,
    DPoPReplayError,
    DPoPValidationError,
    InvalidDPoPError,
    InvalidDPoPProofError,
    InvalidAlgorithmError,
    InvalidKeyError,
    InvalidSignatureError,
    InvalidTokenError,
    PyJWKError,
)
from .utils import base64url_encode

JtiConsumer = Callable[[str], Any]

# DPoP proofs must use an asymmetric signature algorithm.  The value is the
# expected key type and, for EC/OKP keys, the expected curve (or set of curves).
_ALGORITHM_KEY_FAMILIES: dict[str, tuple[str, str | frozenset[str] | None]] = {
    "RS256": ("RSA", None),
    "RS384": ("RSA", None),
    "RS512": ("RSA", None),
    "PS256": ("RSA", None),
    "PS384": ("RSA", None),
    "PS512": ("RSA", None),
    "ES256": ("EC", "P-256"),
    "ES256K": ("EC", "secp256k1"),
    "ES384": ("EC", "P-384"),
    "ES512": ("EC", "P-521"),
    "ES521": ("EC", "P-521"),
    "EdDSA": ("OKP", frozenset({"Ed25519", "Ed448"})),
}

# Any of these members means that the JWK contains private or symmetric key
# material.  A DPoP proof is self-signed, so accepting a private key in the
# header would let a caller supply material that should never leave the client.
_PRIVATE_JWK_MEMBERS = frozenset(
    {
        "d",  # EC, OKP and RSA private exponent
        "p",
        "q",
        "dp",
        "dq",
        "qi",
        "oth",  # RSA private parameters
        "k",  # symmetric key
    }
)

_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
)
_HEXDIGITS = frozenset("0123456789abcdefABCDEF")


def compute_ath(access_token: str | bytes) -> str:
    """Return the RFC 9449 ``ath`` value for an access token.

    ``ath`` is the base64url encoding (without padding) of the SHA-256 digest
    of the ASCII representation of the access token.
    """
    if isinstance(access_token, str):
        token_bytes = access_token.encode("utf-8")
    elif isinstance(access_token, (bytes, bytearray, memoryview)):
        token_bytes = bytes(access_token)
    else:
        raise TypeError("access_token must be a string or bytes")

    return base64url_encode(hashlib.sha256(token_bytes).digest()).decode("ascii")


def _normalize_percent_encoding(value: str) -> str:
    """Normalize percent-encoded octets in a URI component.

    Unreserved characters are decoded and all other escapes use uppercase hex,
    as required by RFC 3986 section 6.2.2.2.  Non-ASCII input is converted to
    UTF-8 percent-encoding so equivalent Unicode and encoded forms compare
    consistently.
    """
    result: list[str] = []
    index = 0
    length = len(value)

    while index < length:
        character = value[index]
        if character == "%":
            if index + 2 >= length:
                raise DPoPInvalidHTUError("Invalid percent-encoding in htu URI")

            escaped = value[index + 1 : index + 3]
            if len(escaped) != 2 or any(c not in _HEXDIGITS for c in escaped):
                raise DPoPInvalidHTUError("Invalid percent-encoding in htu URI")

            decoded = chr(int(escaped, 16))
            if decoded in _UNRESERVED:
                result.append(decoded)
            else:
                result.append(f"%{escaped.upper()}")
            index += 3
            continue

        if ord(character) > 0x7F:
            result.extend(f"%{byte:02X}" for byte in character.encode("utf-8"))
        else:
            result.append(character)
        index += 1

    return "".join(result)


def _remove_dot_segments(path: str) -> str:
    """Apply the RFC 3986 section 5.2.4 remove_dot_segments algorithm."""
    input_buffer = path
    output: list[str] = []

    while input_buffer:
        if input_buffer.startswith("../"):
            input_buffer = input_buffer[3:]
        elif input_buffer.startswith("./"):
            input_buffer = input_buffer[2:]
        elif input_buffer.startswith("/./"):
            input_buffer = "/" + input_buffer[3:]
        elif input_buffer == "/.":
            input_buffer = "/"
        elif input_buffer.startswith("/../"):
            input_buffer = "/" + input_buffer[4:]
            if output:
                output.pop()
        elif input_buffer == "/..":
            input_buffer = "/"
            if output:
                output.pop()
        elif input_buffer in (".", ".."):
            input_buffer = ""
        else:
            if input_buffer.startswith("/"):
                slash = input_buffer.find("/", 1)
            else:
                slash = input_buffer.find("/")

            if slash == -1:
                output.append(input_buffer)
                input_buffer = ""
            else:
                output.append(input_buffer[:slash])
                input_buffer = input_buffer[slash:]

    return "".join(output) or "/"


def normalize_htu(uri: str) -> str:
    """Normalize an HTTP URI for DPoP ``htu`` comparison.

    The result contains only a lower-case scheme, a normalized host (including
    default-port removal), and the normalized path.  Userinfo and fragment
    components are rejected rather than silently discarded, and query strings
    are not part of the resulting comparison value.
    """
    if not isinstance(uri, str):
        raise DPoPInvalidHTUError("htu must be a string")

    if not uri:
        raise DPoPInvalidHTUError("htu must not be empty")

    if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in uri):
        raise DPoPInvalidHTUError("htu must not contain whitespace or control characters")

    if "#" in uri:
        raise DPoPInvalidHTUError("htu must not contain a fragment")

    try:
        parts = urlsplit(uri)
    except ValueError as error:
        raise DPoPInvalidHTUError(f"Invalid htu URI: {error}") from error

    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise DPoPInvalidHTUError("htu must use the http or https scheme")

    if "@" in parts.netloc:
        raise DPoPInvalidHTUError("htu must not contain userinfo")

    host = parts.hostname
    if not host:
        raise DPoPInvalidHTUError("htu must contain a host")

    try:
        port = parts.port
    except ValueError as error:
        raise DPoPInvalidHTUError(f"Invalid port in htu URI: {error}") from error

    if parts.netloc.endswith(":"):
        raise DPoPInvalidHTUError("Invalid empty port in htu URI")

    host = _normalize_percent_encoding(host.lower())
    host_for_uri = f"[{host}]" if ":" in host else host

    default_port = 443 if scheme == "https" else 80
    if port is not None and port != default_port:
        authority = f"{host_for_uri}:{port}"
    else:
        authority = host_for_uri

    path = parts.path or "/"
    if not path.startswith("/"):
        raise DPoPInvalidHTUError("htu path must be absolute")

    path = _remove_dot_segments(_normalize_percent_encoding(path))
    return f"{scheme}://{authority}{path}"


def _require_string_claim(
    payload: dict[str, Any],
    claim: str,
    error_type: type[DPoPError],
) -> str:
    if claim not in payload:
        raise error_type(f'DPoP proof is missing the "{claim}" claim')

    value = payload[claim]
    if not isinstance(value, str) or not value:
        raise error_type(f'DPoP proof "{claim}" claim must be a non-empty string')
    return value


def _require_numeric_date(
    payload: dict[str, Any],
    claim: str,
    error_type: type[DPoPError],
) -> float:
    if claim not in payload:
        raise error_type(f'DPoP proof is missing the "{claim}" claim')

    value = payload[claim]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise error_type(f'DPoP proof "{claim}" claim must be a number')

    numeric_value = float(value)
    if not math.isfinite(numeric_value):
        raise error_type(f'DPoP proof "{claim}" claim must be finite')
    return numeric_value


def _validate_jose_header(header: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    typ = header.get("typ")
    if not isinstance(typ, str) or typ.lower() != "dpop+jwt":
        raise DPoPInvalidTypeError('DPoP proof "typ" header must be "dpop+jwt"')

    if header.get("b64", True) is False:
        raise DPoPMalformedProofError("DPoP proofs must use base64url payload encoding")

    for parameter in ("jku", "jwks", "x5u", "x5c"):
        if parameter in header:
            raise DPoPInvalidJWKError(
                f'DPoP proof must not contain the "{parameter}" header parameter'
            )

    alg = header.get("alg")
    if not isinstance(alg, str) or not alg:
        raise DPoPInvalidAlgorithmError('DPoP proof is missing the "alg" header')

    if alg not in _ALGORITHM_KEY_FAMILIES:
        raise DPoPInvalidAlgorithmError(
            f"DPoP proof algorithm {alg!r} is not an allowed asymmetric algorithm"
        )

    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        raise DPoPInvalidJWKError('DPoP proof requires a JWK object in the "jwk" header')

    private_members = sorted(_PRIVATE_JWK_MEMBERS.intersection(jwk))
    if private_members:
        raise DPoPInvalidJWKError(
            "DPoP proof JWK must contain only public key material "
            f"(found {', '.join(private_members)})"
        )

    key_use = jwk.get("use")
    if key_use is not None and key_use != "sig":
        raise DPoPInvalidJWKError(
            f'DPoP proof JWK "use" must be "sig" when present, got {key_use!r}'
        )

    key_ops = jwk.get("key_ops")
    if key_ops is not None:
        if not isinstance(key_ops, list) or any(
            not isinstance(operation, str) for operation in key_ops
        ):
            raise DPoPInvalidJWKError(
                'DPoP proof JWK "key_ops" must be a list of strings'
            )
        private_operations = {
            "sign",
            "decrypt",
            "unwrapKey",
            "deriveKey",
            "deriveBits",
        }
        if private_operations.intersection(key_ops):
            raise DPoPInvalidJWKError(
                "DPoP proof JWK must describe a public verification key"
            )

    jwk_alg = jwk.get("alg")
    if jwk_alg is not None and jwk_alg != alg:
        raise DPoPInvalidAlgorithmError(
            f'DPoP proof "alg" {alg!r} does not match JWK "alg" {jwk_alg!r}'
        )

    expected_kty, expected_curve = _ALGORITHM_KEY_FAMILIES[alg]
    kty = jwk.get("kty")
    if kty != expected_kty:
        raise DPoPInvalidAlgorithmError(
            f"DPoP proof algorithm {alg!r} requires a {expected_kty} JWK, "
            f"got {kty!r}"
        )

    if expected_curve is not None:
        curve = jwk.get("crv")
        if isinstance(expected_curve, frozenset):
            curve_matches = curve in expected_curve
            expected_description = " or ".join(sorted(expected_curve))
        else:
            curve_matches = curve == expected_curve
            expected_description = expected_curve

        if not curve_matches:
            raise DPoPInvalidAlgorithmError(
                f"DPoP proof algorithm {alg!r} requires curve "
                f"{expected_description}, got {curve!r}"
            )

    return alg, jwk


def _consume_jti(consume_jti: JtiConsumer, jti: str) -> None:
    try:
        result = consume_jti(jti)
    except DPoPError:
        # A consumer is allowed to signal a replay with DPoPJtiReplayError, and
        # other DPoP-specific errors should retain their own failure code.
        raise
    except Exception as error:
        raise DPoPJtiConsumptionError(
            f'Failed to consume DPoP "jti" {jti!r}: {error}'
        ) from error

    if inspect.isawaitable(result):
        if inspect.iscoroutine(result):
            result.close()
        raise DPoPJtiConsumptionError(
            "The DPoP jti consumer must be synchronous; awaitable results are not supported"
        )

    if result is False:
        raise DPoPJtiReplayError(f'DPoP proof "jti" {jti!r} has already been used')


def _resolve_argument(
    name: str,
    primary: Any,
    alias_name: str,
    alias: Any,
) -> Any:
    if primary is None:
        return alias
    if alias is not None and alias != primary:
        raise TypeError(f"Pass either {name} or {alias_name}, not both")
    return primary


def validate_dpop_proof(
    proof: str | bytes | None = None,
    method: str | None = None,
    uri: str | None = None,
    access_token: str | bytes | None = None,
    consume_jti: JtiConsumer | None = None,
    *,
    dpop_proof: str | bytes | None = None,
    http_method: str | None = None,
    http_uri: str | None = None,
    request_uri: str | None = None,
    normalized_uri: str | None = None,
    url: str | None = None,
    token: str | bytes | None = None,
    jti_consumer: JtiConsumer | None = None,
    jti_callback: JtiConsumer | None = None,
    leeway: float = 60,
    max_age: float = 300,
    iat_leeway: float | None = None,
    max_iat_age: float | None = None,
    max_proof_age: float | None = None,
    now: float | None = None,
) -> dict[str, Any]:
    """Validate a DPoP proof against an HTTP request and access token.

    :param proof: The compact DPoP proof JWT.
    :param method: HTTP method of the request (for example ``"GET"``).
    :param uri: HTTP request URI.  Query and fragment components are excluded
        from the comparison; userinfo and fragments are rejected.
    :param access_token: The access token the proof is being presented with.
    :param consume_jti: Optional synchronous callback invoked with the proof
        ``jti`` after every other check succeeds.  It should return ``False``
        (or raise :class:`~jwt.exceptions.DPoPJtiReplayError`) when the ``jti``
        was already consumed.  Any other exception from the callback is
        reported as :class:`~jwt.exceptions.DPoPJtiConsumptionError`.
    :param leeway: Clock skew tolerance in seconds for ``iat`` and ``exp``.
    :param max_age: Maximum accepted age of the proof in seconds.
    :param now: Override the current time (mainly useful in tests).
    :returns: The decoded DPoP proof claims.
    :raises DPoPError: If any DPoP check fails.
    """
    resolved_proof = _resolve_argument("proof", proof, "dpop_proof", dpop_proof)
    resolved_method = _resolve_argument("method", method, "http_method", http_method)

    resolved_uri = uri
    for alias_name, alias in (
        ("http_uri", http_uri),
        ("request_uri", request_uri),
        ("normalized_uri", normalized_uri),
        ("url", url),
    ):
        resolved_uri = _resolve_argument("uri", resolved_uri, alias_name, alias)

    resolved_token = _resolve_argument(
        "access_token", access_token, "token", token
    )
    resolved_consumer = _resolve_argument(
        "consume_jti", consume_jti, "jti_consumer", jti_consumer
    )
    resolved_consumer = _resolve_argument(
        "consume_jti", resolved_consumer, "jti_callback", jti_callback
    )

    if iat_leeway is not None:
        leeway = iat_leeway
    if max_iat_age is not None:
        max_age = max_iat_age
    if max_proof_age is not None:
        max_age = max_proof_age

    if not isinstance(resolved_proof, (str, bytes)):
        raise TypeError("proof must be a compact JWS string or bytes")
    if not isinstance(resolved_method, str) or not resolved_method:
        raise TypeError("method must be a non-empty string")
    if not isinstance(resolved_uri, str) or not resolved_uri:
        raise TypeError("uri must be a non-empty string")
    if not isinstance(resolved_token, (str, bytes, bytearray, memoryview)):
        raise TypeError("access_token must be a string or bytes")

    try:
        leeway_value = float(leeway)
        max_age_value = float(max_age)
        current_time = time.time() if now is None else float(now)
    except (TypeError, ValueError, OverflowError) as error:
        raise TypeError("leeway, max_age, and now must be numbers") from error

    if not math.isfinite(leeway_value) or leeway_value < 0:
        raise ValueError("leeway must be a finite, non-negative number")
    if not math.isfinite(max_age_value) or max_age_value <= 0:
        raise ValueError("max_age must be a finite, positive number")
    if not math.isfinite(current_time):
        raise ValueError("now must be finite")

    jws = PyJWS()
    try:
        header = jws.get_unverified_header(resolved_proof)
    except (InvalidTokenError, TypeError, ValueError) as error:
        raise DPoPMalformedProofError(
            f"DPoP proof is not a valid compact JWS: {error}"
        ) from error

    alg, jwk = _validate_jose_header(header)

    try:
        proof_key = PyJWK(jwk, algorithm=alg)
    except (InvalidKeyError, PyJWKError, TypeError, ValueError) as error:
        raise DPoPInvalidJWKError(f"Invalid DPoP proof JWK: {error}") from error

    try:
        decoded = jws.decode_complete(
            resolved_proof,
            key=proof_key,
            algorithms=[alg],
        )
    except InvalidSignatureError as error:
        raise DPoPInvalidSignatureError(
            "DPoP proof signature verification failed"
        ) from error
    except InvalidAlgorithmError as error:
        raise DPoPInvalidAlgorithmError(str(error)) from error
    except InvalidKeyError as error:
        raise DPoPInvalidJWKError(f"Invalid DPoP proof JWK: {error}") from error
    except (InvalidTokenError, TypeError, ValueError, DecodeError) as error:
        raise DPoPMalformedProofError(
            f"DPoP proof could not be decoded: {error}"
        ) from error

    try:
        payload = json.loads(decoded["payload"])
    except (TypeError, ValueError, RecursionError) as error:
        raise DPoPMalformedProofError(
            f"DPoP proof payload is not valid JSON: {error}"
        ) from error

    if not isinstance(payload, dict):
        raise DPoPMalformedProofError("DPoP proof payload must be a JSON object")

    htm = _require_string_claim(payload, "htm", DPoPInvalidHTMError)
    if htm != resolved_method:
        raise DPoPInvalidHTMError(
            f'DPoP proof "htm" {htm!r} does not match request method '
            f"{resolved_method!r}"
        )

    claimed_htu = _require_string_claim(payload, "htu", DPoPInvalidHTUError)
    normalized_claim_htu = normalize_htu(claimed_htu)
    normalized_request_uri = normalize_htu(resolved_uri)
    if not hmac.compare_digest(
        normalized_claim_htu.encode("utf-8"),
        normalized_request_uri.encode("utf-8"),
    ):
        raise DPoPInvalidHTUError(
            f'DPoP proof "htu" {claimed_htu!r} does not match request URI '
            f"{normalized_request_uri!r}"
        )

    issued_at = _require_numeric_date(payload, "iat", DPoPInvalidIATError)
    if issued_at > current_time + leeway_value:
        raise DPoPInvalidIATError("DPoP proof was issued in the future")
    if issued_at < current_time - max_age_value - leeway_value:
        raise DPoPInvalidIATError(
            f"DPoP proof is older than the maximum accepted age of "
            f"{max_age_value:g} seconds"
        )

    if "exp" in payload:
        expires_at = _require_numeric_date(payload, "exp", DPoPExpiredError)
        if expires_at <= current_time - leeway_value:
            raise DPoPExpiredError("DPoP proof has expired")

    claimed_ath = _require_string_claim(payload, "ath", DPoPInvalidATHError)
    expected_ath = compute_ath(resolved_token)
    if not hmac.compare_digest(
        claimed_ath.encode("utf-8"), expected_ath.encode("ascii")
    ):
        raise DPoPInvalidATHError(
            'DPoP proof "ath" does not match the supplied access token'
        )

    jti = _require_string_claim(payload, "jti", DPoPInvalidJTIError)
    if resolved_consumer is not None:
        if not callable(resolved_consumer):
            raise TypeError("consume_jti must be callable")
        _consume_jti(resolved_consumer, jti)

    return payload


class DPoPValidator:
    """Reusable DPoP proof validator with optional default settings."""

    def __init__(
        self,
        consume_jti: JtiConsumer | None = None,
        *,
        jti_consumer: JtiConsumer | None = None,
        leeway: float = 60,
        max_age: float = 300,
    ) -> None:
        if consume_jti is not None and jti_consumer is not None:
            if consume_jti != jti_consumer:
                raise TypeError("Pass either consume_jti or jti_consumer, not both")
        self.consume_jti = consume_jti if consume_jti is not None else jti_consumer
        self.leeway = leeway
        self.max_age = max_age

    def validate(
        self,
        proof: str | bytes | None = None,
        method: str | None = None,
        uri: str | None = None,
        access_token: str | bytes | None = None,
        consume_jti: JtiConsumer | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        if consume_jti is None:
            consume_jti = kwargs.pop("jti_consumer", None)
        if consume_jti is None:
            consume_jti = kwargs.pop("jti_callback", None)

        consumer = consume_jti if consume_jti is not None else self.consume_jti
        return validate_dpop_proof(
            proof,
            method,
            uri,
            access_token,
            consumer,
            leeway=self.leeway,
            max_age=self.max_age,
            **kwargs,
        )

    def validate_proof(
        self,
        proof: str | bytes | None = None,
        method: str | None = None,
        uri: str | None = None,
        access_token: str | bytes | None = None,
        consume_jti: JtiConsumer | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        return self.validate(
            proof,
            method,
            uri,
            access_token,
            consume_jti,
            **kwargs,
        )

    def __call__(
        self,
        proof: str | bytes | None = None,
        method: str | None = None,
        uri: str | None = None,
        access_token: str | bytes | None = None,
        consume_jti: JtiConsumer | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        return self.validate(
            proof,
            method,
            uri,
            access_token,
            consume_jti,
            **kwargs,
        )


# Descriptive aliases for applications that use a different verb in their API.
validate = validate_dpop_proof
validate_dpop = validate_dpop_proof
verify_dpop_proof = validate_dpop_proof
verify_dpop = validate_dpop_proof
decode_dpop_proof = validate_dpop_proof
decode_dpop = validate_dpop_proof
calculate_ath = compute_ath
access_token_hash = compute_ath
normalize_uri = normalize_htu
normalize_dpop_uri = normalize_htu
DPoP = DPoPValidator

__all__ = [
    "DPoPValidator",
    "DPoP",
    "JtiConsumer",
    "compute_ath",
    "normalize_htu",
    "normalize_uri",
    "normalize_dpop_uri",
    "validate_dpop_proof",
    "validate_dpop",
    "validate",
    "verify_dpop_proof",
    "verify_dpop",
    "decode_dpop_proof",
    "decode_dpop",
    "calculate_ath",
    "access_token_hash",
    "DPoPError",
    "DPoPMalformedProofError",
    "DPoPInvalidTypeError",
    "DPoPInvalidAlgorithmError",
    "DPoPInvalidJWKError",
    "DPoPInvalidSignatureError",
    "DPoPInvalidHTMError",
    "DPoPInvalidHTUError",
    "DPoPInvalidIATError",
    "DPoPExpiredError",
    "DPoPInvalidATHError",
    "DPoPInvalidJTIError",
    "DPoPJtiConsumptionError",
    "DPoPJtiReplayError",
    "DPoPJtiReuseError",
    "DPoPReplayError",
    "DPoPProofError",
    "DPoPValidationError",
    "InvalidDPoPProofError",
    "InvalidDPoPError",
]
