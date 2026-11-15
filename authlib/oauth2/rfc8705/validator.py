"""authlib.oauth2.rfc8705.validator.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Certificate-bound access token validation for resource servers,
per :rfc:`8705#section-3`.
"""

from __future__ import annotations

import hmac
import logging

from ..rfc9068.token_validator import JWTBearerTokenValidator
from .errors import CertificateBindingError
from .thumbprint import X5T_S256_LENGTH
from .thumbprint import calculate_x5t_s256
from .thumbprint import normalize_x5t_s256

log = logging.getLogger(__name__)

__all__ = [
    "CertificateBoundTokenMixin",
    "CertificateBoundJWTBearerTokenValidator",
]


class CertificateBoundTokenMixin:
    """Validate the ``cnf`` claim of an access token against the TLS peer
    certificate.

    The mixin works with any token object that exposes the token claims as a
    mapping, so it can be combined both with the :rfc:`9068` JWT validator and
    with an :rfc:`7662` introspection validator.

    :param enforce_certificate_binding: when ``True`` (the default), strong
        binding is enforced: a token without a usable ``cnf`` claim, or a
        request without a client certificate, is rejected and there is no
        fallback to an unbound validation. When ``False``, legacy tokens that
        carry no ``cnf`` claim are accepted for backward compatibility; a
        token that *is* bound must still match the presented certificate.

    The fingerprint is always computed from the TLS peer certificate's DER
    encoding. Fingerprint headers sent by an upstream proxy are request
    headers and can be spoofed, so they are never trusted: implementers MUST
    source the certificate from the terminated (or re-terminated) TLS session
    by overriding :meth:`get_tls_peer_cert_chain`.
    """

    enforce_certificate_binding: bool = True

    def __init__(self, *args, enforce_certificate_binding: bool = True, **kwargs):
        self.enforce_certificate_binding = enforce_certificate_binding
        super().__init__(*args, **kwargs)

    def get_tls_peer_cert_chain(self, request) -> list[bytes] | None:
        """Return the validated TLS peer certificate chain as DER blobs.

        Developers MUST re-implement this method for their WSGI/ASGI server.
        The leaf certificate comes first, followed by its chain. Only
        certificates obtained from the TLS session are acceptable: do not
        read a fingerprint forwarded by an upstream gateway, as it cannot be
        trusted end-to-end.

        :return: a list of DER-encoded certificates (leaf first), or ``None``
            when the client did not present a certificate.
        """
        raise NotImplementedError()

    def _reject(self, reason: str, description: str) -> None:
        log.warning(
            "Rejecting certificate-bound access token: %s",
            reason,
            extra={"reason": reason},
        )
        raise CertificateBindingError(
            reason=reason,
            description=description,
            realm=getattr(self, "realm", None),
            extra_attributes=getattr(self, "extra_attributes", None),
        )

    def validate_certificate_binding(self, token, request) -> None:
        """Match the token ``cnf`` claim against the TLS client certificate.

        Per :rfc:`8705#section-3.1`, the resource server rejects the request
        when a certificate-bound token is presented without a matching
        certificate.
        """
        cnf = token.get("cnf") if token is not None else None

        if cnf is None:
            if self.enforce_certificate_binding:
                self._reject(
                    "missing_cnf",
                    "A certificate-bound access token is required and the "
                    "token carries no cnf claim.",
                )
            # Compatibility mode: legacy unbound tokens are accepted.
            return

        if not isinstance(cnf, dict):
            self._reject(
                "invalid_cnf",
                "The token cnf claim must be a JSON object.",
            )

        x5t = cnf.get("x5t#S256")
        if not isinstance(x5t, str) or not x5t:
            self._reject(
                "missing_x5t_s256",
                "The token cnf claim does not carry an x5t#S256 member.",
            )

        try:
            expected = normalize_x5t_s256(x5t)
        except CertificateBindingError as exc:
            self._reject(exc.reason, exc.description)

        if len(x5t) != X5T_S256_LENGTH:
            self._reject(
                "invalid_thumbprint_length",
                "The cnf x5t#S256 member has an unexpected length; it must be "
                "the base64url-encoded SHA-256 certificate thumbprint.",
            )

        peer_chain = self.get_tls_peer_cert_chain(request)
        if not peer_chain:
            self._reject(
                "missing_client_certificate",
                "The resource requires a client certificate but none was "
                "presented for the certificate-bound access token.",
            )

        if not isinstance(peer_chain, (list, tuple)) or len(peer_chain) != 1:
            self._reject(
                "invalid_certificate_chain",
                "The TLS peer certificate chain must contain exactly one "
                "leaf certificate.",
            )

        der_cert = peer_chain[0]
        if not isinstance(der_cert, (bytes, bytearray)) or not der_cert:
            self._reject(
                "empty_client_certificate",
                "The presented TLS client certificate is empty.",
            )

        actual = calculate_x5t_s256(bytes(der_cert))
        if not hmac.compare_digest(actual, expected):
            self._reject(
                "certificate_mismatch",
                "The presented client certificate does not match the "
                "x5t#S256 thumbprint bound to the access token.",
            )


class CertificateBoundJWTBearerTokenValidator(
    CertificateBoundTokenMixin, JWTBearerTokenValidator
):
    """:rfc:`9068` JWT access token validator with :rfc:`8705` certificate
    binding.

    Example::

        class MyValidator(CertificateBoundJWTBearerTokenValidator):
            def get_jwks(self): ...

            def get_tls_peer_cert_chain(self, request):
                flask_request = request._request
                return flask_request.environ.get("myapp.tls_peer_cert_chain")


        require_oauth.register_token_validator(
            MyValidator(
                issuer="https://as.example.org",
                resource_server="https://api.example.org",
            )
        )

    Strong binding (the default) never falls back: a token without ``cnf`` or
    a request without the matching certificate is rejected with
    ``invalid_token``. Pass ``enforce_certificate_binding=False`` to keep
    accepting legacy unbound tokens while still validating bound ones.
    """

    def validate_token(self, token, scopes, request, **kwargs):
        super().validate_token(token, scopes, request, **kwargs)
        self.validate_certificate_binding(token, request)
