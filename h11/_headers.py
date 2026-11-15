import re
from typing import (
    AnyStr,
    cast,
    List,
    Optional,
    overload,
    Sequence,
    Tuple,
    TYPE_CHECKING,
    Union,
)

from ._abnf import field_name, field_value
from ._util import bytesify, LocalProtocolError, validate

if TYPE_CHECKING:
    from ._events import Request

try:
    from typing import Literal
except ImportError:
    from typing_extensions import Literal  # type: ignore

CONTENT_LENGTH_MAX_DIGITS = 20  # allow up to 1 billion TB - 1


# Facts
# -----
#
# Headers are:
#   keys: case-insensitive ascii
#   values: mixture of ascii and raw bytes
#
# "Historically, HTTP has allowed field content with text in the ISO-8859-1
# charset [ISO-8859-1], supporting other charsets only through use of
# [RFC2047] encoding.  In practice, most HTTP header field values use only a
# subset of the US-ASCII charset [USASCII]. Newly defined header fields SHOULD
# limit their field values to US-ASCII octets.  A recipient SHOULD treat other
# octets in field content (obs-text) as opaque data."
# And it deprecates all non-ascii values
#
# Leading/trailing whitespace in header names is forbidden
#
# Values get leading/trailing whitespace stripped
#
# Content-Disposition actually needs to contain unicode semantically; to
# accomplish this it has a terrifically weird way of encoding the filename
# itself as ascii (and even this still has lots of cross-browser
# incompatibilities)
#
# Order is important:
# "a proxy MUST NOT change the order of these field values when forwarding a
# message"
# (and there are several headers where the order indicates a preference)
#
# Multiple occurences of the same header:
# "A sender MUST NOT generate multiple header fields with the same field name
# in a message unless either the entire field value for that header field is
# defined as a comma-separated list [or the header is Set-Cookie which gets a
# special exception]" - RFC 7230. (cookies are in RFC 6265)
#
# So every header aside from Set-Cookie can be merged by b", ".join if it
# occurs repeatedly. But, of course, they can't necessarily be split by
# .split(b","), because quoting.
#
# Given all this mess (case insensitive, duplicates allowed, order is
# important, ...), there doesn't appear to be any standard way to handle
# headers in Python -- they're almost like dicts, but... actually just
# aren't. For now we punt and just use a super simple representation: headers
# are a list of pairs
#
#   [(name1, value1), (name2, value2), ...]
#
# where all entries are bytestrings, names are lowercase and have no
# leading/trailing whitespace, and values are bytestrings with no
# leading/trailing whitespace. Searching and updating are done via naive O(n)
# methods.
#
# Maybe a dict-of-lists would be better?

_content_length_re = re.compile(rb"[0-9]+")
_field_name_re = re.compile(field_name.encode("ascii"))
_field_value_re = re.compile(field_value.encode("ascii"))


class Headers(Sequence[Tuple[bytes, bytes]]):
    """
    A list-like interface that allows iterating over headers as byte-pairs
    of (lowercased-name, value).

    Internally we actually store the representation as three-tuples,
    including both the raw original casing, in order to preserve casing
    over-the-wire, and the lowercased name, for case-insensitive comparisions.

    r = Request(
        method="GET",
        target="/",
        headers=[("Host", "example.org"), ("Connection", "keep-alive")],
        http_version="1.1",
    )
    assert r.headers == [
        (b"host", b"example.org"),
        (b"connection", b"keep-alive")
    ]
    assert r.headers.raw_items() == [
        (b"Host", b"example.org"),
        (b"Connection", b"keep-alive")
    ]
    """

    __slots__ = "_full_items"

    def __init__(self, full_items: List[Tuple[bytes, bytes, bytes]]) -> None:
        self._full_items = full_items

    def __bool__(self) -> bool:
        return bool(self._full_items)

    def __eq__(self, other: object) -> bool:
        return list(self) == list(other)  # type: ignore

    def __len__(self) -> int:
        return len(self._full_items)

    def __repr__(self) -> str:
        return "<Headers(%s)>" % repr(list(self))

    def __getitem__(self, idx: int) -> Tuple[bytes, bytes]:  # type: ignore[override]
        _, name, value = self._full_items[idx]
        return (name, value)

    def raw_items(self) -> List[Tuple[bytes, bytes]]:
        return [(raw_name, value) for raw_name, _, value in self._full_items]


HeaderTypes = Union[
    List[Tuple[bytes, bytes]],
    List[Tuple[bytes, str]],
    List[Tuple[str, bytes]],
    List[Tuple[str, str]],
]


@overload
def normalize_and_validate(headers: Headers, _parsed: Literal[True]) -> Headers:
    ...


@overload
def normalize_and_validate(headers: HeaderTypes, _parsed: Literal[False]) -> Headers:
    ...


@overload
def normalize_and_validate(
    headers: Union[Headers, HeaderTypes], _parsed: bool = False
) -> Headers:
    ...


def normalize_and_validate(
    headers: Union[Headers, HeaderTypes], _parsed: bool = False
) -> Headers:
    new_headers = []
    seen_content_length = None
    saw_transfer_encoding = False
    for name, value in headers:
        # For headers coming out of the parser, we can safely skip some steps,
        # because it always returns bytes and has already run these regexes
        # over the data:
        if not _parsed:
            name = bytesify(name)
            value = bytesify(value)
            validate(_field_name_re, name, "Illegal header name {!r}", name)
            validate(_field_value_re, value, "Illegal header value {!r}", value)
        assert isinstance(name, bytes)
        assert isinstance(value, bytes)

        raw_name = name
        name = name.lower()
        if name == b"content-length":
            lengths = {length.strip() for length in value.split(b",")}
            if len(lengths) != 1:
                raise LocalProtocolError("conflicting Content-Length headers")
            value = lengths.pop()
            validate(_content_length_re, value, "bad Content-Length")
            if len(value) > CONTENT_LENGTH_MAX_DIGITS:
                raise LocalProtocolError("bad Content-Length")
            if seen_content_length is None:
                seen_content_length = value
                new_headers.append((raw_name, name, value))
            elif seen_content_length != value:
                raise LocalProtocolError("conflicting Content-Length headers")
        elif name == b"transfer-encoding":
            # "A server that receives a request message with a transfer coding
            # it does not understand SHOULD respond with 501 (Not
            # Implemented)."
            # https://tools.ietf.org/html/rfc7230#section-3.3.1
            if saw_transfer_encoding:
                raise LocalProtocolError(
                    "multiple Transfer-Encoding headers", error_status_hint=501
                )
            # "All transfer-coding names are case-insensitive"
            # -- https://tools.ietf.org/html/rfc7230#section-4
            value = value.lower()
            if value != b"chunked":
                raise LocalProtocolError(
                    "Only Transfer-Encoding: chunked is supported",
                    error_status_hint=501,
                )
            saw_transfer_encoding = True
            new_headers.append((raw_name, name, value))
        else:
            new_headers.append((raw_name, name, value))
    return Headers(new_headers)


def get_comma_header(headers: Headers, name: bytes) -> List[bytes]:
    # Should only be used for headers whose value is a list of
    # comma-separated, case-insensitive values.
    #
    # The header name `name` is expected to be lower-case bytes.
    #
    # Connection: meets these criteria (including cast insensitivity).
    #
    # Content-Length: technically is just a single value (1*DIGIT), but the
    # standard makes reference to implementations that do multiple values, and
    # using this doesn't hurt. Ditto, case insensitivity doesn't things either
    # way.
    #
    # Transfer-Encoding: is more complex (allows for quoted strings), so
    # splitting on , is actually wrong. For example, this is legal:
    #
    #    Transfer-Encoding: foo; options="1,2", chunked
    #
    # and should be parsed as
    #
    #    foo; options="1,2"
    #    chunked
    #
    # but this naive function will parse it as
    #
    #    foo; options="1
    #    2"
    #    chunked
    #
    # However, this is okay because the only thing we are going to do with
    # any Transfer-Encoding is reject ones that aren't just "chunked", so
    # both of these will be treated the same anyway.
    #
    # Expect: the only legal value is the literal string
    # "100-continue". Splitting on commas is harmless. Case insensitive.
    #
    out: List[bytes] = []
    for _, found_name, found_raw_value in headers._full_items:
        if found_name == name:
            found_raw_value = found_raw_value.lower()
            for found_split_value in found_raw_value.split(b","):
                found_split_value = found_split_value.strip()
                if found_split_value:
                    out.append(found_split_value)
    return out


def set_comma_header(headers: Headers, name: bytes, new_values: List[bytes]) -> Headers:
    # The header name `name` is expected to be lower-case bytes.
    #
    # Note that when we store the header we use title casing for the header
    # names, in order to match the conventional HTTP header style.
    #
    # Simply calling `.title()` is a blunt approach, but it's correct
    # here given the cases where we're using `set_comma_header`...
    #
    # Connection, Content-Length, Transfer-Encoding.
    new_headers: List[Tuple[bytes, bytes]] = []
    for found_raw_name, found_name, found_raw_value in headers._full_items:
        if found_name != name:
            new_headers.append((found_raw_name, found_raw_value))
    for new_value in new_values:
        new_headers.append((name.title(), new_value))
    return normalize_and_validate(new_headers)


def has_expect_100_continue(request: "Request") -> bool:
    # https://tools.ietf.org/html/rfc7231#section-5.1.1
    # "A server that receives a 100-continue expectation in an HTTP/1.0 request
    # MUST ignore that expectation."
    if request.http_version < b"1.1":
        return False
    expect = get_comma_header(request.headers, b"expect")
    return b"100-continue" in expect


# Opt-in target authority validation
# ----------------------------------
#
# When a request target is in absolute-form (e.g. a request routed through a
# proxy or edge server), both the target URI and the Host header claim to
# identify the request's authority. If a server routes on one and logs on the
# other, a desync between them can be used to smuggle requests past access
# controls. validate_target_authority() checks that the two agree, and
# rejects target authority components that are known to be parsed
# inconsistently across implementations (userinfo, fragments, backslashes,
# bad percent-encoding, empty hosts).
#
# Error messages deliberately never include the raw target or Host value, so
# that an attacker-controlled request line can't be reflected into logs or
# error pages.

# absolute-form = scheme "://" authority ... (RFC 7230 section 5.3.2, by way
# of RFC 3986). We only need the scheme and authority here.
_absolute_form_re = re.compile(
    rb"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*)://(?P<authority>[^/?#]*)"
)

# A "%" that isn't followed by two hex digits.
_invalid_percent_re = re.compile(rb"%(?![0-9A-Fa-f][0-9A-Fa-f])")

# Default ports used when one side of the comparison leaves the port
# implicit.
_scheme_default_ports = {
    b"http": 80,
    b"https": 443,
    b"ws": 80,
    b"wss": 443,
}


def _parse_authority(authority: bytes, what: str) -> Tuple[bytes, Optional[int]]:
    # Splits an authority component (or Host header value) into (host, port),
    # where port is None if not specified. Raises LocalProtocolError on
    # malformed input; `what` identifies the source in the error message
    # without echoing attacker-controlled data.
    port_bytes: Optional[bytes]
    if authority.startswith(b"["):
        # IP-literal, e.g. "[::1]" or "[::1]:8080"
        closing = authority.find(b"]")
        if closing == -1:
            raise LocalProtocolError("malformed authority in %s" % what)
        host = authority[: closing + 1]
        rest = authority[closing + 1 :]
        if rest:
            if not rest.startswith(b":"):
                raise LocalProtocolError("malformed authority in %s" % what)
            port_bytes = rest[1:]
        else:
            port_bytes = None
    else:
        if authority.count(b":") > 1:
            # Bare IPv6 literals must use [...] brackets
            raise LocalProtocolError("malformed authority in %s" % what)
        if b":" in authority:
            host, _, port_bytes = authority.partition(b":")
        else:
            host, port_bytes = authority, None
    port: Optional[int] = None
    if port_bytes:
        if not port_bytes.isdigit():
            raise LocalProtocolError("malformed authority in %s" % what)
        port = int(port_bytes)
    return host, port


def validate_target_authority(target: bytes, headers: Headers) -> None:
    """Check that an absolute-form request target agrees with the Host header.

    This is an opt-in, strict validation intended for servers (e.g. edge
    proxies) that route on the absolute-form target URI: it guarantees that
    the request target and the Host header identify the same authority, so
    that routing and logging can't be desynchronized.

    For absolute-form targets, the target's scheme/host/port must be
    consistent with the unique Host header, and the target must not contain
    a userinfo subcomponent, a fragment, an empty host, backslashes, or
    invalid percent-encoding in the authority component.

    origin-form, asterisk-form, and authority-form (CONNECT) targets are not
    affected and keep their existing semantics.

    Raises LocalProtocolError on any violation. Error messages never echo
    the raw target or Host value.
    """
    match = _absolute_form_re.match(target)
    if match is None:
        # Not absolute-form: origin-form, asterisk-form, and authority-form
        # (CONNECT) targets keep their existing semantics.
        return
    if b"\\" in target:
        raise LocalProtocolError("backslash in absolute-form request target")
    if b"#" in target:
        raise LocalProtocolError("fragment in absolute-form request target")
    scheme = match.group("scheme").lower()
    authority = match.group("authority")
    if b"@" in authority:
        raise LocalProtocolError("userinfo in absolute-form request target")
    if _invalid_percent_re.search(authority):
        raise LocalProtocolError(
            "invalid percent-encoding in absolute-form request target"
        )
    target_host, target_port = _parse_authority(authority, "request target")
    if not target_host:
        raise LocalProtocolError("empty host in absolute-form request target")
    hosts = [value for name, value in headers if name == b"host"]
    if len(hosts) != 1:
        raise LocalProtocolError(
            "absolute-form request target requires a unique Host header"
        )
    host_header = hosts[0]
    if b"@" in host_header or b"\\" in host_header:
        raise LocalProtocolError("invalid Host header")
    header_host, header_port = _parse_authority(host_header, "Host header")
    default_port = _scheme_default_ports.get(scheme)
    if target_port is None:
        target_port = default_port
    if header_port is None:
        header_port = default_port
    if target_host.lower() != header_host.lower() or target_port != header_port:
        raise LocalProtocolError(
            "absolute-form request target authority does not match Host header"
        )
