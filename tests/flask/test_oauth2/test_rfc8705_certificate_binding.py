"""Flask resource server tests for RFC 8705 certificate-bound access tokens.

The TLS peer certificate is simulated through the WSGI environ, the same place
a real server exposes the material of the re-terminated mTLS session. A
fingerprint header sent by an upstream gateway must never be trusted.
"""

import datetime
import logging

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from flask import jsonify
from joserfc import jwt
from joserfc.jwk import OctKey

from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.oauth2.rfc6750.errors import InvalidTokenError
from authlib.oauth2.rfc8705 import CertificateBindingError
from authlib.oauth2.rfc8705 import CertificateBoundJWTBearerTokenValidator
from authlib.oauth2.rfc8705 import calculate_x5t_s256

ISSUER = "https://auth.example.com"
RESOURCE_SERVER = "https://api.example.com"

#: WSGI environ key used by the tests to carry the simulated TLS peer chain.
PEER_CHAIN_ENVIRON = "test.tls_peer_cert_chain"

#: Header a misconfigured upstream gateway might forward. It must be ignored.
SPOOFED_FINGERPRINT_HEADER = "X-SSL-Client-Cert-Fingerprint"


def _generate_client_certificate(common_name):
    """Generate a self-signed client certificate and return its DER bytes."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(private_key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.DER)


@pytest.fixture
def signing_key():
    return OctKey.generate_key()


@pytest.fixture
def client_certificate():
    return _generate_client_certificate("client-device-1")


@pytest.fixture
def other_client_certificate():
    return _generate_client_certificate("client-device-2")


@pytest.fixture
def bound_thumbprint(client_certificate):
    return calculate_x5t_s256(client_certificate)


class CertificateBoundValidatorStub(CertificateBoundJWTBearerTokenValidator):
    def get_jwks(self):
        return self._signing_key

    def get_tls_peer_cert_chain(self, request):
        # Only the TLS session material is read. Request headers such as a
        # fingerprint forwarded by a gateway are intentionally ignored.
        flask_request = request._request
        return flask_request.environ.get(PEER_CHAIN_ENVIRON)


@pytest.fixture
def make_app(signing_key):
    from flask import Flask

    def _make_app(enforce_certificate_binding=True):
        app = Flask(__name__)
        app.secret_key = "testing"

        validator = CertificateBoundValidatorStub(
            issuer=ISSUER,
            resource_server=RESOURCE_SERVER,
            enforce_certificate_binding=enforce_certificate_binding,
        )
        validator._signing_key = signing_key

        require_oauth = ResourceProtector()
        require_oauth.register_token_validator(validator)

        @app.route("/export")
        @require_oauth()
        def export_endpoint():
            return jsonify(status="ok")

        return app

    return _make_app


def _encode_access_token(signing_key, claims=None):
    import time

    base_claims = {
        "iss": ISSUER,
        "aud": RESOURCE_SERVER,
        "sub": "user-1",
        "client_id": "client-1",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "jti": "unique-jti",
    }
    if claims:
        base_claims.update(claims)
    return jwt.encode({"alg": "HS256", "typ": "at+jwt"}, base_claims, signing_key)


@pytest.fixture
def bound_access_token(signing_key, bound_thumbprint):
    return _encode_access_token(signing_key, {"cnf": {"x5t#S256": bound_thumbprint}})


@pytest.fixture
def unbound_access_token(signing_key):
    return _encode_access_token(signing_key)


def _call_export(app, access_token, peer_chain=None, extra_headers=None):
    headers = {"Authorization": f"Bearer {access_token}"}
    if extra_headers:
        headers.update(extra_headers)
    environ_overrides = {}
    if peer_chain is not None:
        environ_overrides[PEER_CHAIN_ENVIRON] = peer_chain
    return app.test_client().get(
        "/export", headers=headers, environ_overrides=environ_overrides
    )


def test_bound_token_with_matching_certificate_succeeds(
    make_app, bound_access_token, client_certificate
):
    app = make_app()
    rv = _call_export(app, bound_access_token, peer_chain=[client_certificate])
    assert rv.status_code == 200
    assert rv.get_json()["status"] == "ok"


def test_replay_with_another_certificate_is_rejected_and_audited(
    make_app, bound_access_token, client_certificate, other_client_certificate, caplog
):
    """The same token replayed from another device (another client
    certificate) must be rejected by both the gateway response and the audit
    log with the same certificate-mismatch conclusion."""
    app = make_app()

    with caplog.at_level(logging.WARNING, logger="authlib.oauth2.rfc8705.validator"):
        rv = _call_export(
            app,
            bound_access_token,
            peer_chain=[other_client_certificate],
        )

    assert rv.status_code == 401
    body = rv.get_json()
    assert body["error"] == "invalid_token"
    assert "certificate" in body["error_description"]
    assert rv.headers["WWW-Authenticate"].startswith("Bearer")

    audit_records = [
        record for record in caplog.records if record.reason == "certificate_mismatch"
    ]
    assert len(audit_records) == 1
    assert "certificate_mismatch" in audit_records[0].getMessage()

    # The original device can still use the token: the token itself is valid.
    rv = _call_export(app, bound_access_token, peer_chain=[client_certificate])
    assert rv.status_code == 200


def test_spoofed_fingerprint_header_is_never_trusted(
    make_app, bound_access_token, bound_thumbprint, other_client_certificate, caplog
):
    """A fingerprint header matching the token cannot bypass the check: the
    thumbprint is recomputed from the TLS peer certificate DER."""
    app = make_app()

    with caplog.at_level(logging.WARNING, logger="authlib.oauth2.rfc8705.validator"):
        rv = _call_export(
            app,
            bound_access_token,
            peer_chain=[other_client_certificate],
            extra_headers={SPOOFED_FINGERPRINT_HEADER: bound_thumbprint},
        )

    assert rv.status_code == 401
    assert rv.get_json()["error"] == "invalid_token"
    assert [
        record for record in caplog.records if record.reason == "certificate_mismatch"
    ]


def test_missing_client_certificate_is_rejected(make_app, bound_access_token, caplog):
    app = make_app()
    with caplog.at_level(logging.WARNING, logger="authlib.oauth2.rfc8705.validator"):
        rv = _call_export(app, bound_access_token, peer_chain=None)
    assert rv.status_code == 401
    assert rv.get_json()["error"] == "invalid_token"
    assert [
        record
        for record in caplog.records
        if record.reason == "missing_client_certificate"
    ]


def test_empty_client_certificate_is_rejected(make_app, bound_access_token, caplog):
    app = make_app()
    with caplog.at_level(logging.WARNING, logger="authlib.oauth2.rfc8705.validator"):
        rv = _call_export(app, bound_access_token, peer_chain=[b""])
    assert rv.status_code == 401
    assert rv.get_json()["error"] == "invalid_token"
    assert [
        record
        for record in caplog.records
        if record.reason == "empty_client_certificate"
    ]


def test_certificate_chain_with_several_certificates_is_rejected(
    make_app, bound_access_token, client_certificate, other_client_certificate, caplog
):
    """Only a single leaf certificate is accepted: an ambiguous chain must
    not let an attacker pick which material is thumbprinted."""
    app = make_app()
    with caplog.at_level(logging.WARNING, logger="authlib.oauth2.rfc8705.validator"):
        rv = _call_export(
            app,
            bound_access_token,
            peer_chain=[client_certificate, other_client_certificate],
        )
    assert rv.status_code == 401
    assert rv.get_json()["error"] == "invalid_token"
    assert [
        record
        for record in caplog.records
        if record.reason == "invalid_certificate_chain"
    ]


@pytest.mark.parametrize(
    ("bad_thumbprint", "reason"),
    [
        ("A" * 42, "invalid_thumbprint_length"),
        ("A" * 44, "invalid_thumbprint_length"),
        ("not-base64url!!", "invalid_thumbprint"),
    ],
)
def test_malformed_thumbprint_in_cnf_is_rejected(
    make_app, signing_key, client_certificate, caplog, bad_thumbprint, reason
):
    access_token = _encode_access_token(
        signing_key, {"cnf": {"x5t#S256": bad_thumbprint}}
    )
    app = make_app()
    with caplog.at_level(logging.WARNING, logger="authlib.oauth2.rfc8705.validator"):
        rv = _call_export(app, access_token, peer_chain=[client_certificate])
    assert rv.status_code == 401
    assert rv.get_json()["error"] == "invalid_token"
    assert [record for record in caplog.records if record.reason == reason]


@pytest.mark.parametrize(
    "cnf",
    [
        "not-an-object",
        {},
        {"other_member": "value"},
        {"x5t#S256": 123},
    ],
)
def test_malformed_cnf_claim_is_rejected(
    make_app, signing_key, client_certificate, caplog, cnf
):
    access_token = _encode_access_token(signing_key, {"cnf": cnf})
    app = make_app()
    with caplog.at_level(logging.WARNING, logger="authlib.oauth2.rfc8705.validator"):
        rv = _call_export(app, access_token, peer_chain=[client_certificate])
    assert rv.status_code == 401
    assert rv.get_json()["error"] == "invalid_token"
    assert caplog.records


def test_strong_binding_rejects_legacy_unbound_token_without_fallback(
    make_app, unbound_access_token, client_certificate, caplog
):
    """Once strong binding is selected, an unbound token never falls back to
    plain bearer validation, even when a certificate is presented."""
    app = make_app(enforce_certificate_binding=True)
    with caplog.at_level(logging.WARNING, logger="authlib.oauth2.rfc8705.validator"):
        rv = _call_export(app, unbound_access_token, peer_chain=[client_certificate])
    assert rv.status_code == 401
    assert rv.get_json()["error"] == "invalid_token"
    assert [record for record in caplog.records if record.reason == "missing_cnf"]


def test_strong_binding_rejects_unbound_token_without_certificate(
    make_app, unbound_access_token, caplog
):
    app = make_app(enforce_certificate_binding=True)
    with caplog.at_level(logging.WARNING, logger="authlib.oauth2.rfc8705.validator"):
        rv = _call_export(app, unbound_access_token, peer_chain=None)
    assert rv.status_code == 401
    assert [record for record in caplog.records if record.reason == "missing_cnf"]


def test_compatibility_mode_accepts_legacy_unbound_token(
    make_app, unbound_access_token
):
    """Explicit compatibility mode keeps accepting tokens that have no cnf."""
    app = make_app(enforce_certificate_binding=False)
    rv = _call_export(app, unbound_access_token, peer_chain=None)
    assert rv.status_code == 200

    rv = _call_export(app, unbound_access_token, peer_chain=[b"whatever"])
    assert rv.status_code == 200


def test_compatibility_mode_still_enforces_bound_tokens(
    make_app, bound_access_token, client_certificate, other_client_certificate, caplog
):
    """A bound token cannot bypass the certificate check in compatibility mode."""
    app = make_app(enforce_certificate_binding=False)

    rv = _call_export(app, bound_access_token, peer_chain=[client_certificate])
    assert rv.status_code == 200

    with caplog.at_level(logging.WARNING, logger="authlib.oauth2.rfc8705.validator"):
        rv = _call_export(
            app, bound_access_token, peer_chain=[other_client_certificate]
        )
    assert rv.status_code == 401
    assert [
        record for record in caplog.records if record.reason == "certificate_mismatch"
    ]


def test_compatibility_mode_rejects_bound_token_without_certificate(
    make_app, bound_access_token, caplog
):
    app = make_app(enforce_certificate_binding=False)
    with caplog.at_level(logging.WARNING, logger="authlib.oauth2.rfc8705.validator"):
        rv = _call_export(app, bound_access_token, peer_chain=None)
    assert rv.status_code == 401
    assert [
        record
        for record in caplog.records
        if record.reason == "missing_client_certificate"
    ]


def test_x5t_s256_is_canonical_base64url(client_certificate):
    thumbprint = calculate_x5t_s256(client_certificate)
    # SHA-256 base64url without padding is exactly 43 characters.
    assert len(thumbprint) == 43
    assert "=" not in thumbprint
    assert "+" not in thumbprint
    assert "/" not in thumbprint


@pytest.mark.parametrize(
    "representation",
    [
        lambda value: value,
        lambda value: value + "=",
        lambda value: value.replace("-", "+").replace("_", "/"),
    ],
)
def test_canonical_thumbprint_comparison_accepts_equivalent_encodings(
    client_certificate, representation
):
    from authlib.oauth2.rfc8705 import normalize_x5t_s256

    thumbprint = calculate_x5t_s256(client_certificate)
    assert normalize_x5t_s256(representation(thumbprint)) == thumbprint


def test_certificate_binding_error_is_an_invalid_token_error():
    error = CertificateBindingError(
        reason="certificate_mismatch", description="mismatch"
    )
    assert isinstance(error, InvalidTokenError)
    assert error.error == "invalid_token"
    assert error.status_code == 401
    assert error.reason == "certificate_mismatch"
