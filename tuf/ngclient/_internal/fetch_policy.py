# Copyright 2026, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Opt-in security checks for redirect and URL path handling.

The policy is intentionally opt-in: callers that do not provide a policy keep
the historical fetcher behavior, including urllib3's default redirect handling.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final
from urllib.parse import unquote, urljoin, urlsplit

from tuf.api import exceptions

REASON_REDIRECT_LIMIT: Final = "redirect_limit"
REASON_BYTE_LIMIT: Final = "byte_limit"
REASON_PATH_ESCAPE: Final = "normalized_path_escape"
REASON_ORIGIN_MISMATCH: Final = "origin_mismatch"
REASON_UNSAFE_URL: Final = "unsafe_url"
REASON_ENCODED_PATH: Final = "encoded_path_not_canonicalizable"


class FetchPolicyError(exceptions.DownloadError):
    """A URL or redirect chain violates a configured fetch policy."""

    def __init__(
        self,
        reason: str,
        message: str,
        *,
        final_url: str | None = None,
        normalized_path: str | None = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.final_url = final_url
        self.normalized_path = normalized_path


@dataclass(frozen=True)
class NormalizedURL:
    """Canonical URL information used by containment checks."""

    raw_url: str
    resolved_url: str
    scheme: str
    host: str
    port: int
    path: str
    path_parts: tuple[str, ...]


@dataclass(frozen=True)
class FetchPolicy:
    """Policy for an HTTP fetch and its redirect chain.

    Args:
        allowed_base_url: URL prefix that every request must remain within.
        max_redirects: Maximum number of redirect responses to follow.
        enforce_same_origin: Require redirects to keep scheme, host and port.
        normalize_backslashes: Treat decoded backslashes as path separators.
        strip_matrix_parameters: Remove ``;parameter`` path segments before
            normalization. This catches aliases such as ``..;/``.
        max_decoding_passes: Maximum repeated percent-decoding passes. Repeated
            decoding is needed to inspect double-encoded traversal sequences.
    """

    allowed_base_url: str | None = None
    max_redirects: int = 3
    enforce_same_origin: bool = True
    normalize_backslashes: bool = True
    strip_matrix_parameters: bool = True
    max_decoding_passes: int = 4

    def __post_init__(self) -> None:
        if self.max_redirects < 0:
            raise ValueError("max_redirects must be non-negative")
        if self.max_decoding_passes < 1:
            raise ValueError("max_decoding_passes must be positive")
        if self.allowed_base_url is not None:
            # Validate the base URL when the policy is constructed.
            normalize_url(
                self.allowed_base_url,
                normalize_backslashes=self.normalize_backslashes,
                strip_matrix_parameters=self.strip_matrix_parameters,
                max_decoding_passes=self.max_decoding_passes,
            )

    def inspect(
        self, url: str, relative_to: str | None = None
    ) -> NormalizedURL:
        """Resolve and authorize ``url`` against this policy."""
        resolved = urljoin(relative_to, url) if relative_to is not None else url
        normalized = normalize_url(
            resolved,
            normalize_backslashes=self.normalize_backslashes,
            strip_matrix_parameters=self.strip_matrix_parameters,
            max_decoding_passes=self.max_decoding_passes,
        )

        if self.allowed_base_url is None:
            return normalized

        base = normalize_url(
            self.allowed_base_url,
            normalize_backslashes=self.normalize_backslashes,
            strip_matrix_parameters=self.strip_matrix_parameters,
            max_decoding_passes=self.max_decoding_passes,
        )

        if self.enforce_same_origin and (
            normalized.scheme != base.scheme
            or normalized.host != base.host
            or normalized.port != base.port
        ):
            raise FetchPolicyError(
                REASON_ORIGIN_MISMATCH,
                f"Redirect target {normalized.host!r} is outside allowed "
                f"origin {base.host!r}",
                final_url=normalized.resolved_url,
                normalized_path=normalized.path,
            )

        if not _is_within(normalized.path_parts, base.path_parts):
            raise FetchPolicyError(
                REASON_PATH_ESCAPE,
                f"Normalized path {normalized.path!r} is outside allowed "
                f"prefix {base.path!r}",
                final_url=normalized.resolved_url,
                normalized_path=normalized.path,
            )

        return normalized


def normalize_url(  # noqa: C901, PLR0912
    url: str,
    *,
    normalize_backslashes: bool = True,
    strip_matrix_parameters: bool = True,
    max_decoding_passes: int = 4,
) -> NormalizedURL:
    """Decode and normalize an HTTP(S) URL for authorization decisions."""
    if any(ord(character) < 32 for character in url):
        raise FetchPolicyError(
            REASON_UNSAFE_URL, "URL contains ASCII control characters"
        )

    try:
        parsed = urlsplit(url)
    except ValueError as error:
        raise FetchPolicyError(
            REASON_UNSAFE_URL, f"Invalid URL: {url}", final_url=url
        ) from error

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise FetchPolicyError(
            REASON_UNSAFE_URL,
            f"Unsupported URL scheme {parsed.scheme!r}",
            final_url=url,
        )

    if parsed.username is not None or parsed.password is not None:
        raise FetchPolicyError(
            REASON_UNSAFE_URL,
            "URL userinfo is not allowed in authorization targets",
            final_url=url,
        )

    host = parsed.hostname
    if not host:
        raise FetchPolicyError(
            REASON_UNSAFE_URL, "URL is missing a host", final_url=url
        )
    host = host.lower()

    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as error:
        raise FetchPolicyError(
            REASON_UNSAFE_URL,
            "URL contains an invalid port",
            final_url=url,
        ) from error

    decoded_path = _deep_unquote(parsed.path or "/", max_decoding_passes)
    if "\x00" in decoded_path:
        raise FetchPolicyError(
            REASON_UNSAFE_URL,
            "URL path contains a NUL byte after decoding",
            final_url=url,
        )

    if normalize_backslashes:
        decoded_path = decoded_path.replace("\\", "/")

    parts: list[str] = []
    for raw_part in decoded_path.split("/"):
        part = raw_part
        if strip_matrix_parameters:
            part = part.split(";", 1)[0]
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                raise FetchPolicyError(
                    REASON_PATH_ESCAPE,
                    f"Normalized path escapes URL root: {decoded_path!r}",
                    final_url=url,
                    normalized_path=decoded_path,
                )
            parts.pop()
            continue
        parts.append(part)

    normalized_path = "/" + "/".join(parts)
    if decoded_path.endswith("/") and parts:
        normalized_path += "/"

    return NormalizedURL(
        raw_url=url,
        resolved_url=url,
        scheme=scheme,
        host=host,
        port=port,
        path=normalized_path,
        path_parts=tuple(parts),
    )


def _deep_unquote(value: str, max_passes: int) -> str:
    for _ in range(max_passes):
        try:
            decoded = unquote(value, errors="strict")
        except UnicodeDecodeError as error:
            raise FetchPolicyError(
                REASON_UNSAFE_URL,
                "Percent-decoded URL path is not valid UTF-8",
                final_url=value,
            ) from error
        if decoded == value:
            return decoded
        value = decoded

    raise FetchPolicyError(
        REASON_ENCODED_PATH,
        "URL path did not reach a stable percent-decoding after "
        f"{max_passes} passes",
        final_url=value,
    )


def _is_within(
    path_parts: tuple[str, ...], base_parts: tuple[str, ...]
) -> bool:
    return path_parts[: len(base_parts)] == base_parts
