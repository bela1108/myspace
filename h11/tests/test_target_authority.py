import pytest

from .._connection import Connection
from .._events import Request
from .._headers import Headers, normalize_and_validate, validate_target_authority
from .._state import SERVER
from .._util import LocalProtocolError, RemoteProtocolError
from .helpers import receive_and_get


def make_request(target, host="public.example", **kwargs):
    headers = [("Host", host)] if host is not None else []
    return Request(method="GET", target=target, headers=headers, **kwargs)


# Direct Request-level validation (opt-in via validate_target_authority=True)


def test_absolute_form_matching_host_accepted():
    req = make_request(
        "http://public.example/admin", validate_target_authority=True
    )
    assert req.target == b"http://public.example/admin"
    # No path component
    make_request("http://public.example", validate_target_authority=True)
    # Scheme and host comparisons are case-insensitive
    make_request("HTTP://PUBLIC.EXAMPLE/admin", validate_target_authority=True)
    # Explicit default port matches implicit port, and vice-versa
    make_request("http://public.example:80/", validate_target_authority=True)
    make_request(
        "http://public.example/",
        host="public.example:80",
        validate_target_authority=True,
    )
    # Non-default ports must match
    make_request(
        "http://public.example:8080/",
        host="public.example:8080",
        validate_target_authority=True,
    )
    # https default port
    make_request(
        "https://public.example/",
        host="public.example:443",
        validate_target_authority=True,
    )
    # IPv6 literals
    make_request(
        "http://[::1]:8080/",
        host="[::1]:8080",
        validate_target_authority=True,
    )
    # Valid percent-encoding in the authority is allowed
    make_request(
        "http://public%2Dexample/",
        host="public%2Dexample",
        validate_target_authority=True,
    )


def test_absolute_form_host_mismatch_rejected():
    with pytest.raises(LocalProtocolError) as excinfo:
        make_request(
            "http://internal.service/admin",
            host="public.example",
            validate_target_authority=True,
        )
    # The raw target must not be echoed in the error
    assert "internal.service" not in str(excinfo.value)
    assert "/admin" not in str(excinfo.value)


def test_absolute_form_port_mismatch_rejected():
    with pytest.raises(LocalProtocolError):
        make_request(
            "http://public.example:8080/", validate_target_authority=True
        )
    with pytest.raises(LocalProtocolError):
        make_request(
            "http://public.example/",
            host="public.example:8080",
            validate_target_authority=True,
        )
    # https implies port 443, not 80
    with pytest.raises(LocalProtocolError):
        make_request(
            "https://public.example/",
            host="public.example:80",
            validate_target_authority=True,
        )


@pytest.mark.parametrize(
    "target",
    [
        # userinfo
        "http://user@public.example/",
        "http://user:password@public.example/",
        # fragment
        "http://public.example/admin#fragment",
        # empty host
        "http:///admin",
        "http://:8080/admin",
        # backslash
        "http://public.example\\internal.service/admin",
        "http://public.example\\@internal.service/",
        # invalid percent-encoding in the authority
        "http://public%2example/",
        "http://public%zz.example/",
        # malformed port
        "http://public.example:abc/",
        # bare IPv6 literal without brackets
        "http://::1/admin",
    ],
)
def test_absolute_form_bad_authority_rejected(target):
    with pytest.raises(LocalProtocolError) as excinfo:
        make_request(target, validate_target_authority=True)
    # The raw target must not be echoed in the error
    assert target not in str(excinfo.value)


def test_absolute_form_requires_unique_host():
    # HTTP/1.0 has no mandatory Host header, but absolute-form validation
    # still requires one to compare against.
    with pytest.raises(LocalProtocolError) as excinfo:
        make_request(
            "http://public.example/",
            host=None,
            http_version="1.0",
            validate_target_authority=True,
        )
    assert "public.example" not in str(excinfo.value)
    # Multiple Host headers are rejected (this already happened before this
    # feature, but make sure it still fires with validation enabled).
    with pytest.raises(LocalProtocolError):
        Request(
            method="GET",
            target="http://public.example/",
            headers=[("Host", "public.example"), ("Host", "public.example")],
            validate_target_authority=True,
        )


def test_origin_form_and_connect_authority_unaffected():
    # origin-form targets are not compared against Host
    req = make_request("/admin", validate_target_authority=True)
    assert req.target == b"/admin"
    # asterisk-form
    req = Request(
        method="OPTIONS",
        target="*",
        headers=[("Host", "public.example")],
        validate_target_authority=True,
    )
    assert req.target == b"*"
    # CONNECT authority-form keeps its existing semantics, even when it
    # disagrees with the Host header
    req = Request(
        method="CONNECT",
        target="internal.service:443",
        headers=[("Host", "public.example")],
        validate_target_authority=True,
    )
    assert req.target == b"internal.service:443"


def test_validation_is_opt_in():
    # Without the flag, a mismatched absolute-form target is accepted, as
    # before.
    req = make_request("http://internal.service/admin")
    assert req.target == b"http://internal.service/admin"


def test_validate_target_authority_function():
    headers = normalize_and_validate([("Host", "public.example")])
    assert isinstance(headers, Headers)
    # Matching absolute-form passes
    validate_target_authority(b"http://public.example/admin", headers)
    # Mismatch raises
    with pytest.raises(LocalProtocolError):
        validate_target_authority(b"http://internal.service/admin", headers)
    # origin-form is a no-op
    validate_target_authority(b"/admin", headers)


# Connection-level validation (opt-in via Connection(...,
# validate_target_authority=True)): errors must fire before the Request event
# reaches the application.


def test_connection_rejects_mismatched_absolute_form():
    conn = Connection(SERVER, validate_target_authority=True)
    conn.receive_data(
        b"GET http://internal.service/admin HTTP/1.1\r\n"
        b"Host: public.example\r\n"
        b"\r\n"
    )
    with pytest.raises(RemoteProtocolError) as excinfo:
        conn.next_event()
    assert excinfo.value.error_status_hint == 400
    # The raw target must not be echoed in the error
    assert "internal.service" not in str(excinfo.value)
    assert "/admin" not in str(excinfo.value)


def test_connection_rejects_userinfo_and_backslash():
    for target in (
        b"http://user@public.example/",
        b"http://public.example\\@internal.service/",
    ):
        conn = Connection(SERVER, validate_target_authority=True)
        conn.receive_data(
            b"GET " + target + b" HTTP/1.1\r\nHost: public.example\r\n\r\n"
        )
        with pytest.raises(RemoteProtocolError) as excinfo:
            conn.next_event()
        assert target.decode("ascii") not in str(excinfo.value)


def test_connection_accepts_matching_absolute_form():
    conn = Connection(SERVER, validate_target_authority=True)
    events = receive_and_get(
        conn,
        b"GET http://public.example/admin HTTP/1.1\r\n"
        b"Host: public.example\r\n"
        b"\r\n",
    )
    assert isinstance(events[0], Request)
    assert events[0].target == b"http://public.example/admin"


def test_connection_origin_form_and_connect_unaffected():
    conn = Connection(SERVER, validate_target_authority=True)
    events = receive_and_get(
        conn, b"GET /admin HTTP/1.1\r\nHost: public.example\r\n\r\n"
    )
    assert isinstance(events[0], Request)
    assert events[0].target == b"/admin"

    conn = Connection(SERVER, validate_target_authority=True)
    events = receive_and_get(
        conn,
        b"CONNECT internal.service:443 HTTP/1.1\r\n"
        b"Host: public.example\r\n"
        b"\r\n",
    )
    assert isinstance(events[0], Request)
    assert events[0].target == b"internal.service:443"


def test_connection_validation_is_opt_in():
    # Without the flag, a mismatched absolute-form target is delivered to the
    # application, as before.
    conn = Connection(SERVER)
    events = receive_and_get(
        conn,
        b"GET http://internal.service/admin HTTP/1.1\r\n"
        b"Host: public.example\r\n"
        b"\r\n",
    )
    assert isinstance(events[0], Request)
    assert events[0].target == b"http://internal.service/admin"
