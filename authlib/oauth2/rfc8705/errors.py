"""authlib.oauth2.rfc8705.errors.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Errors raised when a certificate-bound access token cannot be matched to
the TLS client certificate, per :rfc:`8705#section-3`.
"""

from __future__ import annotations

from ..rfc6750.errors import InvalidTokenError

__all__ = ["CertificateBindingError", "InvalidCertificateThumbprintError"]


class CertificateBindingError(InvalidTokenError):
    """The access token is certificate-bound and the presented TLS client
    certificate is missing or does not match its ``cnf`` claim.

    The error code stays ``invalid_token``: :rfc:`6750#section-3.1` only
    defines ``invalid_request``, ``invalid_token`` and
    ``insufficient_scope``, and a failed certificate binding means the
    presented token is not valid for this request.

    :rfc:`8705#section-3.2`
    """

    def __init__(self, reason: str, description: str, **kwargs):
        super().__init__(description=description, **kwargs)
        #: Machine-readable audit reason, such as ``certificate_mismatch``.
        self.reason = reason


class InvalidCertificateThumbprintError(CertificateBindingError):
    """The ``x5t#S256`` value carried by the token ``cnf`` claim is not a
    valid base64url-encoded SHA-256 digest.
    """
