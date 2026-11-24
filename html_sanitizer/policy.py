"""
Request-scoped policy snapshots and generation-aware sanitize caching.

The document service sanitizes content against per-tenant policies which
may be hot-updated or revoked at any time.  This module provides the
coordination layer which guarantees:

* Each request works on a single immutable :class:`PolicySnapshot`
  captured when the request starts.  A policy update halfway through the
  request never changes the rules the in-flight request sees, so output
  can never mix old and new rules.
* Policy updates and revocations swap the whole policy state atomically.
  Concurrent readers observe either the complete old or the complete new
  policy, never a half-applied mixture.  An update which fails to build
  leaves the previous policy fully in effect.
* Cached output is only served when the requesting snapshot proves the
  same tenant, policy generation, revocation epoch and document version.
  Revocation bumps the epoch, invalidating every cached generation of
  the tenant at once instead of only the most recent one.
"""

import hashlib
import threading
from dataclasses import dataclass

from .sanitizer import Sanitizer


__all__ = (
    "PolicyRegistry",
    "PolicySnapshot",
    "SanitizationCache",
    "SanitizationService",
)


@dataclass(frozen=True)
class _PolicyState:
    """Immutable policy state, always replaced as a whole."""

    generation: int
    epoch: int
    sanitizer: Sanitizer


_INITIAL_STATE = _PolicyState(generation=0, epoch=0, sanitizer=Sanitizer())


@dataclass(frozen=True)
class PolicySnapshot:
    """
    Immutable, request-scoped view of a tenant's sanitization policy.

    Capture one snapshot per request and route every sanitize and cache
    operation of that request through it.
    """

    tenant: str
    generation: int
    epoch: int
    sanitizer: Sanitizer

    def cache_key(self, document_version, html):
        """
        Cache key proving tenant, epoch, generation and document version.

        The content digest avoids storing raw HTML in keys while still
        distinguishing different documents under the same version.
        """
        digest = hashlib.sha256(html.encode("utf-8")).hexdigest()
        return (self.tenant, self.epoch, self.generation, str(document_version), digest)


class PolicyRegistry:
    """
    Holds the current sanitization policy per tenant.

    All mutations replace the immutable state in a single step under a
    lock; readers therefore never observe a partially applied update.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._states = {}

    def snapshot(self, tenant="default"):
        """Capture the tenant's current policy state for one request."""
        with self._lock:
            state = self._states.get(tenant, _INITIAL_STATE)
        return PolicySnapshot(
            tenant=tenant,
            generation=state.generation,
            epoch=state.epoch,
            sanitizer=state.sanitizer,
        )

    def update_policy(self, settings=None, *, tenant="default"):
        """
        Hot-update the tenant's policy and return the new generation.

        The new sanitizer is fully built before any shared state is
        touched; invalid settings raise and leave the previous policy
        completely intact.
        """
        sanitizer = Sanitizer(settings or {})
        with self._lock:
            old = self._states.get(tenant, _INITIAL_STATE)
            state = _PolicyState(old.generation + 1, old.epoch, sanitizer)
            self._states[tenant] = state
        return state.generation

    def revoke(self, tenant="default"):
        """
        Revoke the tenant's policy and every output derived from it.

        Bumping the epoch invalidates all cached generations of this
        tenant atomically; the tenant falls back to the built-in
        defaults under a fresh generation.
        """
        with self._lock:
            old = self._states.get(tenant, _INITIAL_STATE)
            self._states[tenant] = _PolicyState(
                old.generation + 1, old.epoch + 1, Sanitizer()
            )


@dataclass(frozen=True)
class _CacheEntry:
    epoch: int
    generation: int
    html: str


class SanitizationCache:
    """
    Generation-aware sanitize output cache.

    A cached output is only served to a snapshot proving the same
    tenant, revocation epoch, policy generation and document version
    (all encoded in the key and re-verified on read); anything else is
    a miss and is recomputed under the request's own snapshot.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._entries = {}

    def get(self, snapshot, document_version, html):
        key = snapshot.cache_key(document_version, html)
        with self._lock:
            entry = self._entries.get(key)
        if (
            entry is not None
            and entry.epoch == snapshot.epoch
            and entry.generation == snapshot.generation
        ):
            return entry.html
        return None

    def set(self, snapshot, document_version, html, result):
        key = snapshot.cache_key(document_version, html)
        entry = _CacheEntry(snapshot.epoch, snapshot.generation, result)
        with self._lock:
            self._entries[key] = entry

    def __len__(self):
        return len(self._entries)


class SanitizationService:
    """Coordinates policy snapshots and the output cache per request."""

    def __init__(self, registry=None, cache=None):
        self.registry = registry if registry is not None else PolicyRegistry()
        self.cache = cache if cache is not None else SanitizationCache()

    def begin_request(self, tenant="default"):
        """Capture the policy snapshot to be used by one whole request."""
        return self.registry.snapshot(tenant)

    def sanitize(self, html, *, snapshot=None, tenant="default", document_version):
        """
        Sanitize HTML under the request's policy snapshot.

        Reuses cached output only when the snapshot proves the same
        policy generation, epoch, tenant and document version.
        """
        if snapshot is None:
            snapshot = self.registry.snapshot(tenant)
        elif snapshot.tenant != tenant:
            raise ValueError(
                f"Snapshot belongs to tenant {snapshot.tenant!r}, not {tenant!r}"
            )
        cached = self.cache.get(snapshot, document_version, html)
        if cached is not None:
            return cached
        result = snapshot.sanitizer.sanitize(html)
        self.cache.set(snapshot, document_version, html, result)
        return result

