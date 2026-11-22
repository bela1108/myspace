# Copyright New York University and the in-toto contributors
# SPDX-License-Identifier: Apache-2.0

# TODO: Add module docstring and remove pylint exemption in in-toto/in-toto#126
# pylint: disable=missing-docstring
from securesystemslib.exceptions import Error


class SignatureVerificationError(Error):
    """Indicates a signature verification Error."""


class LayoutExpiredError(Error):
    """Indicates that the layout expired."""


class RuleVerificationError(Error):
    """Indicates that artifact rule verification failed."""


class ReproducibilityVerificationError(RuleVerificationError):
    """Indicates that independent builds are not reproducible.

    The exception optionally carries a list of structured
    :class:`in_toto.reproducibility.ArtifactDifference` records.  Each record
    names the artifact, the side on which the difference was observed and the
    layout rule that governs the artifact.
    """

    def __init__(self, message=None, failures=None):
        self.failures = list(failures or [])
        self.differences = self.failures
        self.records = self.failures
        self.failure = self.failures[0] if self.failures else None
        if message is None:
            message = _format_reproducibility_failures(self.failures)
        super().__init__(message)


def _format_reproducibility_failures(failures):
    """Build a human readable message for reproducibility failures."""
    if not failures:
        return "Independent builds are not reproducible."

    lines = ["Independent builds are not reproducible:"]
    lines.extend(f"  - {failure}" for failure in failures)
    return "\n".join(lines)


# Convenient spellings used by some integrations.
ReproducibilityError = ReproducibilityVerificationError
ReproducibilityCheckError = ReproducibilityVerificationError
ReproducibleBuildError = ReproducibilityVerificationError


class ThresholdVerificationError(Error):
    """Indicates that signature threshold verification failed."""


class BadReturnValueError(Error):
    """Indicates that a ran command exited with non-int or non-zero return
    value."""


class LinkNotFoundError(Error):
    """Indicates that a link file was not found."""


class UnsupportedKeyTypeError(Error):
    """Indicates that the specified key type is not yet supported."""


class PrefixError(Error):
    """Indicates that there is an error because of the prefixes passed."""


class InvalidMetadata(Error):  # noqa: N818
    """Indicates that the metadata is not valid."""
