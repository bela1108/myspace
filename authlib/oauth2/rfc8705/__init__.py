"""authlib.oauth2.rfc8705.
~~~~~~~~~~~~~~~~~~~~~~~~~~

OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access
Tokens. Resource server side support for the ``x5t#S256`` member of the
``cnf`` claim, per :rfc:`8705`.
"""

from .errors import CertificateBindingError
from .errors import InvalidCertificateThumbprintError
from .thumbprint import X5T_S256_LENGTH
from .thumbprint import calculate_x5t_s256
from .thumbprint import normalize_x5t_s256
from .validator import CertificateBoundJWTBearerTokenValidator
from .validator import CertificateBoundTokenMixin

__all__ = [
    "CertificateBindingError",
    "InvalidCertificateThumbprintError",
    "CertificateBoundJWTBearerTokenValidator",
    "CertificateBoundTokenMixin",
    "X5T_S256_LENGTH",
    "calculate_x5t_s256",
    "normalize_x5t_s256",
]
