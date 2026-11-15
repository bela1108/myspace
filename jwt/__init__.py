from .api_jwk import PyJWK, PyJWKSet
from .api_jws import (
    PyJWS,
    get_algorithm_by_name,
    get_unverified_header,
    register_algorithm,
    unregister_algorithm,
)
from .api_jwt import PyJWT, decode, decode_complete, encode
from .dpop import (
    DPoPValidator,
    compute_ath,
    normalize_htu,
    validate_dpop,
    validate_dpop_proof,
)
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
    DPoPMalformedProofError,
    DPoPReplayError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAlgorithmError,
    InvalidAudienceError,
    InvalidIssuedAtError,
    InvalidIssuerError,
    InvalidKeyError,
    InvalidSignatureError,
    InvalidTokenError,
    MissingRequiredClaimError,
    PyJWKClientConnectionError,
    PyJWKClientError,
    PyJWKError,
    PyJWKSetError,
    PyJWTError,
)
from .jwks_client import PyJWKClient
from .warnings import InsecureKeyLengthWarning

__version__ = "2.15.1"

__title__ = "PyJWT"
__description__ = "JSON Web Token implementation in Python"
__url__ = "https://pyjwt.readthedocs.io"
__uri__ = __url__
__doc__ = f"{__description__} <{__uri__}>"

__author__ = "José Padilla"
__email__ = "hello@jpadilla.com"

__license__ = "MIT"
__copyright__ = "Copyright 2015-2026 José Padilla"


__all__ = [
    "PyJWS",
    "PyJWT",
    "PyJWKClient",
    "PyJWK",
    "PyJWKSet",
    "DPoPValidator",
    "decode",
    "decode_complete",
    "encode",
    "get_unverified_header",
    "register_algorithm",
    "unregister_algorithm",
    "get_algorithm_by_name",
    "validate_dpop_proof",
    "validate_dpop",
    "compute_ath",
    "normalize_htu",
    # Warnings
    "InsecureKeyLengthWarning",
    # Exceptions
    "DecodeError",
    "DPoPError",
    "DPoPExpiredError",
    "DPoPInvalidAlgorithmError",
    "DPoPInvalidATHError",
    "DPoPInvalidHTMError",
    "DPoPInvalidHTUError",
    "DPoPInvalidIATError",
    "DPoPInvalidJTIError",
    "DPoPInvalidJWKError",
    "DPoPInvalidSignatureError",
    "DPoPInvalidTypeError",
    "DPoPJtiConsumptionError",
    "DPoPJtiReplayError",
    "DPoPMalformedProofError",
    "DPoPReplayError",
    "ExpiredSignatureError",
    "ImmatureSignatureError",
    "InvalidAlgorithmError",
    "InvalidAudienceError",
    "InvalidIssuedAtError",
    "InvalidIssuerError",
    "InvalidKeyError",
    "InvalidSignatureError",
    "InvalidTokenError",
    "MissingRequiredClaimError",
    "PyJWKClientConnectionError",
    "PyJWKClientError",
    "PyJWKError",
    "PyJWKSetError",
    "PyJWTError",
]
