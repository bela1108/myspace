# Copyright 2021, New York University and the TUF contributors
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Provides an implementation of ``FetcherInterface`` using the urllib3 HTTP
library.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING
from urllib.parse import urljoin

# Imports
import urllib3

import tuf
from tuf.api import exceptions
from tuf.ngclient._internal.fetch_policy import (
    REASON_REDIRECT_LIMIT,
    FetchPolicy,
    FetchPolicyError,
)
from tuf.ngclient._internal.proxy import ProxyEnvironment
from tuf.ngclient.fetcher import FetcherInterface

if TYPE_CHECKING:
    from collections.abc import Iterator

# Globals
logger = logging.getLogger(__name__)

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})


# Classes
class Urllib3Fetcher(FetcherInterface):
    """An implementation of ``FetcherInterface`` based on the urllib3 library.

    Attributes:
        socket_timeout: Timeout in seconds, used for both initial connection
            delay and the maximum delay between bytes received.
        chunk_size: Chunk size in bytes used when downloading.
    """

    def __init__(
        self,
        socket_timeout: int = 30,
        chunk_size: int = 400000,
        app_user_agent: str | None = None,
        fetch_policy: FetchPolicy | None = None,
    ) -> None:
        # Default settings
        self.socket_timeout: int = socket_timeout  # seconds
        self.chunk_size: int = chunk_size  # bytes
        self.fetch_policy: FetchPolicy | None = fetch_policy

        # Create User-Agent.
        ua = f"python-tuf/{tuf.__version__}"
        if app_user_agent is not None:
            ua = f"{app_user_agent} {ua}"

        self._proxy_env = ProxyEnvironment(headers={"User-Agent": ua})

    def _fetch(self, url: str) -> Iterator[bytes]:
        """Fetch the contents of HTTP/HTTPS url from a remote server.

        Args:
            url: URL string that represents a file location.

        Raises:
            exceptions.SlowRetrievalError: Timeout occurs while receiving
                data.
            exceptions.DownloadHTTPError: HTTP error code is received.

        Returns:
            Bytes iterator
        """

        # Defer downloading the response body with preload_content=False.
        # Always set the timeout. This timeout value is interpreted by
        # urllib3 as:
        #  - connect timeout (max delay before first byte is received)
        #  - read (gap) timeout (max delay between bytes received)
        if self.fetch_policy is None:
            # Preserve the historical urllib3 call, including its default
            # redirect behavior.
            response = self._request(url, redirect=None)
        else:
            response = self._fetch_with_policy(self.fetch_policy, url)

        if response.status >= 400:
            response.close()
            raise exceptions.DownloadHTTPError(
                f"HTTP error occurred with status {response.status}",
                response.status,
            )

        return self._chunks(response)

    def _request(
        self, url: str, *, redirect: bool | None
    ) -> urllib3.response.BaseHTTPResponse:
        """Perform one HTTP request while preserving timeout mapping."""
        request_kwargs: dict[str, object] = {
            "preload_content": False,
            "timeout": urllib3.Timeout(self.socket_timeout),
        }
        if redirect is not None:
            request_kwargs["redirect"] = redirect

        try:
            return self._proxy_env.request("GET", url, **request_kwargs)
        except urllib3.exceptions.MaxRetryError as e:
            if isinstance(e.reason, urllib3.exceptions.TimeoutError):
                raise exceptions.SlowRetrievalError from e
            # Any other reason (e.g. TLS or connection error): let the original
            # error propagate instead of falling through to an unbound response.
            raise

    def _fetch_with_policy(
        self, policy: FetchPolicy, url: str
    ) -> urllib3.response.BaseHTTPResponse:
        """Follow redirects manually so every hop can be authorized."""
        current_url = url
        for followed in range(policy.max_redirects + 1):
            normalized = policy.inspect(current_url)
            response = self._request(current_url, redirect=False)

            if response.status in _REDIRECT_STATUSES:
                location = response.getheader("Location")
                if location:
                    if followed >= policy.max_redirects:
                        response.close()
                        raise FetchPolicyError(
                            REASON_REDIRECT_LIMIT,
                            "Refusing to follow more than "
                            f"{policy.max_redirects} redirect(s)",
                            final_url=normalized.resolved_url,
                            normalized_path=normalized.path,
                        )

                    response.close()
                    current_url = urljoin(current_url, location)
                    continue

            return response

        raise AssertionError(
            "redirect policy loop exited unexpectedly"
        )  # pragma: no cover

    def _chunks(
        self, response: urllib3.response.BaseHTTPResponse
    ) -> Iterator[bytes]:
        """A generator function to be returned by fetch.

        This way the caller of fetch can differentiate between connection
        and actual data download.
        """

        try:
            yield from response.stream(self.chunk_size)
        except urllib3.exceptions.TimeoutError as e:
            # Raised directly when the gap timeout expires mid-stream:
            # ReadTimeoutError is a TimeoutError but not a MaxRetryError.
            raise exceptions.SlowRetrievalError from e
        except urllib3.exceptions.MaxRetryError as e:
            if isinstance(e.reason, urllib3.exceptions.TimeoutError):
                raise exceptions.SlowRetrievalError from e
            # Any other reason: propagate rather than ending the stream
            # silently, which would look like a complete download.
            raise

        finally:
            response.release_conn()
