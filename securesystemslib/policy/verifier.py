"""Pluggable verification backends.

A backend only answers two questions:

1. which signature schemes can it verify *right now*, and
2. does a concrete signature verify against a concrete public key.

It deliberately knows nothing about policy versions or material purposes.
The :class:`LocalVerifierBackend` works fully offline via ``pyca/cryptography``
and is used as the default; :class:`FakeVerifierBackend` is a configurable
test double that can simulate partial backend coverage and outages.
"""

from __future__ import annotations

from abc import ABCMeta, abstractmethod
from collections.abc import Collection

from securesystemslib.exceptions import (
    UnverifiedSignatureError,
    VerificationError,
)
from securesystemslib.signer import KEY_FOR_TYPE_AND_SCHEME, Signature
from securesystemslib.signer._key import CRYPTO_IMPORT_ERROR, Key


class VerifierCapabilityError(VerificationError):
    """The backend cannot verify a scheme it was asked to verify.

    This is an *environment* problem (missing optional dependency, partial
    backend deployment), not a policy problem and not proof that a signature
    is invalid.
    """


class BackendUnavailableError(VerifierCapabilityError):
    """The backend itself cannot be reached or is explicitly disabled."""


class VerifierBackend(metaclass=ABCMeta):
    """Abstract verification capability provider.

    Attributes:
        name: Short backend identifier used in reports.
    """

    name: str = "abstract"

    @abstractmethod
    def supported_schemes(self) -> frozenset[str]:
        """Return the schemes this backend can currently verify."""
        raise NotImplementedError

    def supports(self, scheme: str) -> bool:
        """Return whether ``scheme`` is currently verifiable."""
        return scheme in self.supported_schemes()

    @abstractmethod
    def verify(self, key: Key, signature: Signature, payload: bytes) -> None:
        """Verify ``signature`` over ``payload`` with ``key``.

        Raises:
            VerifierCapabilityError: The backend cannot handle the key's
                scheme in the current environment.
            UnverifiedSignatureError: The signature does not verify.
        """
        raise NotImplementedError


class LocalVerifierBackend(VerifierBackend):
    """Offline verifier built on the locally installed key implementations.

    The set of supported schemes is derived from
    :data:`~securesystemslib.signer.KEY_FOR_TYPE_AND_SCHEME`: every scheme
    registered for :class:`~securesystemslib.signer.SSlibKey` is verifiable
    without network access, provided ``pyca/cryptography`` is installed.
    Optional capabilities that fail to import (for example ML-DSA on an old
    ``cryptography`` release) are reported as unsupported rather than failing
    at verification time.
    """

    name = "local-offline"

    def __init__(self) -> None:
        # Imported lazily so that environments without pyca/cryptography can
        # still construct the backend and inspect its (empty) capabilities.
        from securesystemslib.signer import SSlibKey  # noqa: PLC0415

        self._sslib_key_cls = SSlibKey
        self._schemes: frozenset[str] | None = None

    def supported_schemes(self) -> frozenset[str]:
        if self._schemes is not None:
            return self._schemes

        if CRYPTO_IMPORT_ERROR is not None:
            self._schemes = frozenset()
            return self._schemes

        schemes = {
            scheme
            for (keytype, scheme), key_impl in KEY_FOR_TYPE_AND_SCHEME.items()
            if isinstance(key_impl, type) and issubclass(key_impl, self._sslib_key_cls)
        }
        self._schemes = frozenset(schemes)
        return self._schemes

    def verify(self, key: Key, signature: Signature, payload: bytes) -> None:
        if CRYPTO_IMPORT_ERROR is not None:
            raise VerifierCapabilityError(CRYPTO_IMPORT_ERROR)

        if not self.supports(key.scheme):
            raise VerifierCapabilityError(
                f"{self.name} backend cannot verify scheme {key.scheme!r}"
            )

        # Delegate to the registered Key implementation; failures there are
        # genuine signature failures, not capability gaps.
        key.verify_signature(signature, payload)


class FakeVerifierBackend(VerifierBackend):
    """Configurable test double for acceptance testing.

    Args:
        supported: Schemes the fake backend claims to support. Defaults to
            the schemes a :class:`LocalVerifierBackend` would support.
        name: Backend identifier shown in reports.
        available: When ``False`` every capability query and verification
            raises :class:`BackendUnavailableError`, simulating an outage.
        verify_failures: Schemes for which verification must raise
            :class:`~securesystemslib.exceptions.UnverifiedSignatureError`.

    The fake backend performs no cryptography of its own: for supported
    schemes it delegates to a real offline verifier so that tampered receipts
    are still detected, while optional capabilities can be removed freely to
    exercise partial-backend scenarios.
    """

    name = "fake-backend"

    def __init__(
        self,
        supported: Collection[str] | None = None,
        *,
        name: str | None = None,
        available: bool = True,
        verify_failures: Collection[str] = (),
    ) -> None:
        if name is not None:
            self.name = name
        self._available = available
        self._verify_failures = frozenset(verify_failures)

        if supported is None:
            supported = LocalVerifierBackend().supported_schemes()
        self._supported = frozenset(supported)
        self._fallback = LocalVerifierBackend()

    @property
    def available(self) -> bool:
        """Whether the simulated backend is currently reachable."""
        return self._available

    def set_available(self, available: bool) -> None:
        """Switch the simulated backend availability at runtime."""
        self._available = available

    def supported_schemes(self) -> frozenset[str]:
        if not self._available:
            raise BackendUnavailableError(f"{self.name} backend is unavailable")
        return self._supported

    def verify(self, key: Key, signature: Signature, payload: bytes) -> None:
        if not self._available:
            raise BackendUnavailableError(f"{self.name} backend is unavailable")
        if not self.supports(key.scheme):
            raise VerifierCapabilityError(
                f"{self.name} backend does not support scheme {key.scheme!r}"
            )
        if key.scheme in self._verify_failures:
            raise UnverifiedSignatureError(
                f"{self.name} backend rejected signature for scheme {key.scheme!r}"
            )
        self._fallback.verify(key, signature, payload)
