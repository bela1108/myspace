"""Exceptions for the replayable in-toto quota ledger."""


class LedgerError(Exception):
    """Base class for all ledger errors."""


class SignatureError(LedgerError):
    """Raised when a layout, link or credential signature is invalid."""


class VerificationError(LedgerError):
    """Raised when verified in-toto evidence contradicts a credential.

    Typical cases are an unknown signer, an expired layout or a link product
    digest that does not match the artifact named in a credential.
    """


class CredentialError(LedgerError):
    """Base class for malformed or conflicting credential handling."""


class DuplicateCredentialError(CredentialError):
    """Raised when a known credential id is reused with different content.

    Re-importing the exact same credential is idempotent and never raises;
    this error flags a conflicting credential that reuses a known id.
    """


class PendingCredentialError(LedgerError):
    """Raised when an operation lacks its predecessor state or evidence.

    The caller should park the request and retry after the missing layout,
    link, entitlement or quota line has been supplied.
    """


class InvalidTransitionError(LedgerError):
    """Raised when an event violates the quota-line state machine."""
