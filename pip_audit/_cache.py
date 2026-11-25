"""
Caching middleware for `pip-audit`.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

import pip_api
import requests
from cachecontrol import CacheControl
from cachecontrol.caches import FileCache
from packaging.version import Version
from platformdirs import user_cache_path

from pip_audit._service.interface import ServiceError
from pip_audit._service.status import CacheFreshness, CacheStatus

logger = logging.getLogger(__name__)

# The `cache dir` command was added to `pip` as of 20.1 so we should check before trying to use it
# to discover the `pip` HTTP cache
_MINIMUM_PIP_VERSION = Version("20.1")

_PIP_VERSION = Version(str(pip_api.PIP_VERSION))

_PIP_AUDIT_LEGACY_INTERNAL_CACHE = Path.home() / ".pip-audit-cache"


def _get_pip_cache() -> Path:
    # Unless the cache directory is specifically set by the `--cache-dir` option, we try to share
    # the `pip` HTTP cache
    cmd = [sys.executable, "-m", "pip", "cache", "dir"]
    try:
        process = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError as cpe:  # pragma: no cover
        # NOTE: This should only happen if pip's cache has been explicitly disabled,
        # which we check for in the caller (via `PIP_NO_CACHE_DIR`).
        raise ServiceError(f"Failed to query the `pip` HTTP cache directory: {cmd}") from cpe
    cache_dir = process.stdout.decode("utf-8").strip("\n")
    http_cache_dir = Path(cache_dir) / "http"
    return http_cache_dir


def _get_cache_dir(custom_cache_dir: Path | None, *, use_pip: bool = True) -> Path:
    """
    Returns a directory path suitable for HTTP caching.

    The directory is **not** guaranteed to exist.

    `use_pip` tells the function to prefer `pip`'s pre-existing cache,
    **unless** `PIP_NO_CACHE_DIR` is present in the environment.
    """

    # If the user has explicitly requested a directory, pass it through unscathed.
    if custom_cache_dir is not None:
        return custom_cache_dir

    # Retrieve pip-audit's default internal cache using `platformdirs`.
    pip_audit_cache_dir = user_cache_path("pip-audit", appauthor=False, ensure_exists=True)

    # If the retrieved cache isn't the legacy one, try to delete the old cache if it exists.
    if (
        _PIP_AUDIT_LEGACY_INTERNAL_CACHE.exists()
        and pip_audit_cache_dir != _PIP_AUDIT_LEGACY_INTERNAL_CACHE
    ):
        shutil.rmtree(_PIP_AUDIT_LEGACY_INTERNAL_CACHE)

    # Respect pip's PIP_NO_CACHE_DIR environment setting.
    if use_pip and not os.getenv("PIP_NO_CACHE_DIR"):
        pip_cache_dir = _get_pip_cache() if _PIP_VERSION >= _MINIMUM_PIP_VERSION else None
        if pip_cache_dir is not None:
            return pip_cache_dir
        else:
            logger.warning(
                f"pip {_PIP_VERSION} doesn't support the `cache dir` subcommand, "
                f"using {pip_audit_cache_dir} instead"
            )
            return pip_audit_cache_dir
    else:
        return pip_audit_cache_dir


class _SafeFileCache(FileCache):
    """
    A rough mirror of `pip`'s `SafeFileCache` that *should* be runtime-compatible
    with `pip` (i.e., does not interfere with `pip` when it shares the same
    caching directory as a running `pip` process).
    """

    def __init__(self, directory: Path):
        self._logged_warning = False
        super().__init__(str(directory))

    def get(self, key: str) -> Any | None:
        try:
            return super().get(key)
        except Exception as e:  # pragma: no cover
            if not self._logged_warning:
                logger.warning(
                    f"Failed to read from cache directory, performance may be degraded: {e}"
                )
                self._logged_warning = True
            return None

    def set(self, key: str, value: bytes, expires: Any | None = None) -> None:
        try:
            self._set_impl(key, value)
        except Exception as e:  # pragma: no cover
            if not self._logged_warning:
                logger.warning(
                    f"Failed to write to cache directory, performance may be degraded: {e}"
                )
                self._logged_warning = True

    def _set_impl(self, key: str, value: bytes) -> None:
        name: str = super()._fn(key)

        # Make sure the directory exists
        try:
            os.makedirs(os.path.dirname(name), self.dirmode)
        except OSError:  # pragma: no cover
            pass

        # We don't want to use lock files since `pip` isn't going to recognise those. We should
        # write to the cache in a similar way to how `pip` does it. We create a temporary file,
        # then atomically replace the actual cache key's filename with it. This ensures
        # that other concurrent `pip` or `pip-audit` instances don't read partial data.
        with NamedTemporaryFile(delete=False, dir=os.path.dirname(name)) as io:
            io.write(value)

            # NOTE(ww): Similar to what `pip` does in `adjacent_tmp_file`.
            io.flush()
            os.fsync(io.fileno())

        # NOTE(ww): Windows won't let us rename the temporary file until it's closed,
        # which is why we call `os.replace()` here rather than in the `with` block above.
        os.replace(io.name, name)

    def delete(self, key: str) -> None:  # pragma: no cover
        try:
            super().delete(key)
        except Exception as e:
            if not self._logged_warning:
                logger.warning(
                    f"Failed to delete file from cache directory, performance may be degraded: {e}"
                )
                self._logged_warning = True


def caching_session(cache_dir: Path | None, *, use_pip: bool = False) -> requests.Session:
    """
    Return a `requests` style session, with suitable caching middleware.

    Uses the given `cache_dir` for the HTTP cache.

    `use_pip` determines how the fallback cache directory is determined, if `cache_dir` is None.
    When `use_pip` is `False`, `caching_session` will use a `pip-audit` internal cache directory.
    When `use_pip` is `True`, `caching_session` will attempt to discover `pip`'s cache
    directory, falling back on the internal `pip-audit` cache directory if the user's
    version of `pip` is too old.
    """

    # We limit the number of redirects to 5, since the services we connect to
    # should really never redirect more than once or twice.
    inner_session = requests.Session()
    inner_session.max_redirects = 5

    return CacheControl(
        inner_session,
        cache=_SafeFileCache(_get_cache_dir(cache_dir, use_pip=use_pip)),
    )


def cache_status_for_response(source_name: str, response: Any) -> CacheStatus:
    """
    Build cache freshness metadata from a CacheControl/requests response.
    """
    now = datetime.now(timezone.utc)
    headers = getattr(response, "headers", {})
    from_cache = bool(getattr(response, "from_cache", False))

    age_seconds: float | None = None
    age_header = headers.get("Age") if hasattr(headers, "get") else None
    if age_header is not None:
        try:
            age_seconds = float(age_header)
        except (TypeError, ValueError):
            age_seconds = None

    ttl_seconds: int | None = None
    cache_control = headers.get("Cache-Control", "") if hasattr(headers, "get") else ""
    for directive in str(cache_control).split(","):
        key, _separator, value = directive.strip().partition("=")
        if key.lower() == "max-age" and value:
            try:
                ttl_seconds = int(value)
            except ValueError:
                ttl_seconds = None
            break

    cached_at: datetime | None = None
    if age_seconds is not None:
        cached_at = now - timedelta(seconds=age_seconds)
    else:
        date_header = headers.get("Date") if hasattr(headers, "get") else None
        if date_header is not None:
            try:
                cached_date = parsedate_to_datetime(date_header)
                if cached_date.tzinfo is None:
                    cached_date = cached_date.replace(tzinfo=timezone.utc)
                cached_at = cached_date
            except (TypeError, ValueError):
                cached_at = None

    if not from_cache:
        freshness = CacheFreshness.MISS
    elif age_seconds is not None and ttl_seconds is not None:
        freshness = CacheFreshness.FRESH if age_seconds < ttl_seconds else CacheFreshness.STALE
    else:
        freshness = CacheFreshness.UNKNOWN

    return CacheStatus(
        source=source_name,
        freshness=freshness,
        checked_at=now,
        cached_at=cached_at,
        age_seconds=age_seconds,
        ttl_seconds=ttl_seconds,
        from_cache=from_cache,
    )
