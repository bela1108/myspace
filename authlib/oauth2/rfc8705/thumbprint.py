"""authlib.oauth2.rfc8705.thumbprint.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

X.509 certificate thumbprints used by the ``x5t#S256`` member of the
``cnf`` claim, per :rfc:`8705#section-3`.
"""

from __future__ import annotations

import base64
import binascii
import hashlib

from .errors import InvalidCertificateThumbprintError

#: Length of an unpadded base64url-encoded SHA-256 digest.
X5T_S256_LENGTH = 43


def calculate_x5t_s256(der_cert: bytes) -> str:
    """Calculate the ``x5t#S256`` thumbprint of a DER-encoded certificate.

    Per :rfc:`8705#section-3`, the value is the base64url-encoded SHA-256
    hash of the DER encoding of the X.509 certificate, without padding.

    :param der_cert: the DER bytes of the client certificate.
    :return: the canonical unpadded base64url thumbprint.
    """
    digest = hashlib.sha256(der_cert).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def normalize_x5t_s256(thumbprint: str) -> str:
    """Decode and re-encode an ``x5t#S256`` value to its canonical form.

    Padded and unpadded base64url encodings, and standard base64 (``+`` and
    ``/``) values, are accepted. Anything that is not a valid
    base64-encoded SHA-256 digest is rejected.

    :param thumbprint: the raw ``x5t#S256`` value, typically read from a
        ``cnf`` claim.
    :return: the canonical unpadded base64url thumbprint.
    :raises InvalidCertificateThumbprintError: if the value is not a string
        or does not decode to a 32-byte SHA-256 digest.
    """
    if not isinstance(thumbprint, str) or not thumbprint:
        raise InvalidCertificateThumbprintError(
            reason="invalid_thumbprint",
            description="The cnf x5t#S256 member must be a non-empty string.",
        )

    encoded = thumbprint.replace("+", "-").replace("/", "_")
    padded = encoded + "=" * (-len(encoded) % 4)
    try:
        digest = base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError, TypeError) as exc:
        raise InvalidCertificateThumbprintError(
            reason="invalid_thumbprint",
            description="The cnf x5t#S256 member is not valid base64url.",
        ) from exc

    if len(digest) != hashlib.sha256().digest_size:
        raise InvalidCertificateThumbprintError(
            reason="invalid_thumbprint_length",
            description=(
                "The cnf x5t#S256 member must encode a 32-byte SHA-256 digest."
            ),
        )

    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
