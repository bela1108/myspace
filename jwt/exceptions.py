from __future__ import annotations


class PyJWTError(Exception):
    """
    Base class for all exceptions
    """

    pass


class InvalidTokenError(PyJWTError):
    """Base exception when ``decode()`` fails on a token"""

    pass


class DecodeError(InvalidTokenError):
    """Raised when a token cannot be decoded because it failed validation"""

    pass


class InvalidSignatureError(DecodeError):
    """Raised when a token's signature doesn't match the one provided as part of
    the token."""

    pass


class ExpiredSignatureError(InvalidTokenError):
    """Raised when a token's ``exp`` claim indicates that it has expired"""

    pass


class InvalidAudienceError(InvalidTokenError):
    """Raised when a token's ``aud`` claim does not match one of the expected
    audience values"""

    pass


class InvalidIssuerError(InvalidTokenError):
    """Raised when a token's ``iss`` claim does not match the expected issuer"""

    pass


class InvalidIssuedAtError(InvalidTokenError):
    """Raised when a token's ``iat`` claim is non-numeric"""

    pass


class ImmatureSignatureError(InvalidTokenError):
    """Raised when a token's ``nbf`` or ``iat`` claims represent a time in the future"""

    pass


class InvalidKeyError(PyJWTError):
    """Raised when the specified key is not in the proper format"""

    pass


class InvalidAlgorithmError(InvalidTokenError):
    """Raised when the specified algorithm is not recognized by PyJWT"""

    pass


class MissingRequiredClaimError(InvalidTokenError):
    """Raised when a claim that is required to be present is not contained
    in the claimset"""

    def __init__(self, claim: str) -> None:
        self.claim = claim

    def __str__(self) -> str:
        return f'Token is missing the "{self.claim}" claim'


class PyJWKError(PyJWTError):
    pass


class MissingCryptographyError(PyJWKError):
    """Raised if the algorithm requires ``cryptography`` to be installed and it is not available."""

    pass


class PyJWKSetError(PyJWTError):
    pass


class PyJWKClientError(PyJWTError):
    pass


class PyJWKClientConnectionError(PyJWKClientError):
    pass


class InvalidSubjectError(InvalidTokenError):
    """Raised when a token's ``sub`` claim is not a string or doesn't match the expected ``subject``"""

    pass


class InvalidJTIError(InvalidTokenError):
    """Raised when a token's ``jti`` claim is not a string"""

    pass


class DPoPError(InvalidTokenError):
    """Base exception for DPoP proof validation failures.

    Each subclass exposes a stable ``code`` attribute so callers can map a
    failure to an HTTP response without having to parse the exception message.
    """

    code = "invalid_dpop_proof"

    def __init__(self, message: str | None = None, *, code: str | None = None) -> None:
        if code is not None:
            self.code = code

        # Keep a couple of conventional aliases so this works with applications
        # that expect either ``reason`` or ``error_code`` in their error handler.
        self.reason = self.code
        self.error_code = self.code
        self.failure_code = self.code
        self.error = self.code
        super().__init__(message or self.code)


class DPoPMalformedProofError(DPoPError):
    """Raised when a DPoP proof is not a well-formed signed JWT."""

    code = "invalid_dpop_proof"


class DPoPInvalidTypeError(DPoPError):
    """Raised when the DPoP proof ``typ`` header is not ``dpop+jwt``."""

    code = "invalid_dpop_typ"


class DPoPInvalidAlgorithmError(DPoPError, InvalidAlgorithmError):
    """Raised when a DPoP proof uses an unsafe or incompatible algorithm."""

    code = "invalid_dpop_alg"


class DPoPInvalidJWKError(DPoPError, InvalidKeyError):
    """Raised when the proof ``jwk`` header is not a public JWK."""

    code = "invalid_dpop_jwk"


class DPoPInvalidSignatureError(DPoPError, InvalidSignatureError):
    """Raised when the DPoP proof signature does not verify."""

    code = "invalid_dpop_signature"


class DPoPInvalidHTMError(DPoPError):
    """Raised when the proof ``htm`` claim does not match the request method."""

    code = "invalid_dpop_htm"


class DPoPInvalidHTUError(DPoPError):
    """Raised when the proof ``htu`` claim does not match the request URI."""

    code = "invalid_dpop_htu"


class DPoPInvalidIATError(DPoPError):
    """Raised when the proof ``iat`` claim is malformed or outside the window."""

    code = "invalid_dpop_iat"


class DPoPExpiredError(DPoPError, ExpiredSignatureError):
    """Raised when a DPoP proof's ``exp`` claim has expired."""

    code = "invalid_dpop_exp"


class DPoPInvalidATHError(DPoPError):
    """Raised when the proof ``ath`` claim does not match the access token."""

    code = "invalid_dpop_ath"


class DPoPInvalidJTIError(DPoPError):
    """Raised when the proof ``jti`` claim is missing or malformed."""

    code = "invalid_dpop_jti"


class DPoPJtiConsumptionError(DPoPError):
    """Raised when the server-side ``jti`` consumer fails to consume the proof."""

    code = "dpop_jti_consumption_failed"


class DPoPJtiReplayError(DPoPJtiConsumptionError):
    """Raised when a ``jti`` has already been consumed."""

    code = "dpop_jti_replayed"


# Compatibility aliases for callers that prefer one generic name.
InvalidDPoPProofError = DPoPError
InvalidDPoPError = DPoPError
DPoPProofError = DPoPError
DPoPValidationError = DPoPError
DPoPReplayError = DPoPJtiReplayError
DPoPJtiReuseError = DPoPJtiReplayError
