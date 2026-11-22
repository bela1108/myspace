class UnableToReadBaselineError(ValueError):
    """Think of this as a 404, if getting a baseline had a HTTPError code."""
    pass


class InvalidBaselineError(ValueError):
    """Think of this as a 400, if getting a baseline had a HTTPError code."""
    pass


class InvalidFile(ValueError):
    """Think of this as a 400, if FileNotFoundError was a 404 HTTPError code."""
    pass


class SecretNotFoundOnSpecifiedLineError(Exception):
    def __init__(self, line: int) -> None:
        super().__init__(
            'ERROR: Secret not found on line {}!\n'.format(line)
            + 'Try recreating your baseline to fix this issue.',
        )


class NoLineNumberError(Exception):
    def __init__(self) -> None:
        super().__init__(
            'ERROR: No line numbers found in baseline! Line numbers are needed '
            'for auditing secret occurrences. Try recreating your baseline to fix '
            'this issue.',
        )


class CheckpointError(ValueError):
    """Base class for errors relating to resumable scan checkpoints."""
    pass


class CheckpointInvalidError(CheckpointError):
    """
    Raised when a checkpoint cannot safely be resumed.

    ``reason`` is a stable, machine-readable identifier (for example
    ``source_changed``), while the exception message contains a human-readable
    explanation. No source content or secret values are included in either.
    """

    def __init__(
        self,
        reason: str,
        message: str = '',
        **details: object,
    ) -> None:
        self.reason = reason
        self.details = details
        super().__init__(message or reason)


class InvalidCheckpointError(CheckpointInvalidError):
    """Backwards-compatible, descriptive alias for CheckpointInvalidError."""
    pass


class CursorInvalidatedError(CheckpointInvalidError):
    """The checkpoint cursor is no longer valid for the requested scan."""
    pass


class StaleCheckpointError(CheckpointInvalidError):
    """The checkpoint describes an older scan state than the current input."""
    pass


class SimulatedCheckpointInterruption(RuntimeError):
    """
    Used by tests to model a process stopping around a checkpoint commit.

    This deliberately subclasses RuntimeError so callers only need to catch a
    regular crash when exercising interruption behavior.
    """
    pass


# Alternate names used by callers that describe an invalidated cursor.
CheckpointInvalidatedError = CheckpointInvalidError
CheckpointInvalidationError = CheckpointInvalidError
