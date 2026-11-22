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


class SamplingError(Error):
    """Indicates an error in release sampling metadata or configuration."""


class SamplingVerificationError(SamplingError):
    """Indicates that sampling acceptance verification failed.

    The optional ``result`` attribute carries the partial/successful
    verification result, including evidence that was retained for re-review.
    """

    def __init__(self, message, result=None):
        super().__init__(message)
        self.result = result


class SamplingFullSetChangedError(SamplingVerificationError):
    """Indicates that the signed artifact full set changed after a draw.

    Attributes:
      expected_digest: Digest recorded in the draw sheet.
      actual_digest: Digest recomputed from the current full set.
      changed: Mapping of artifact ids to ``{"old": ..., "new": ...}``.
      added: Artifact ids that were not present in the recorded full set.
      removed: Artifact ids that are missing from the current full set.
    """

    def __init__(  # noqa: PLR0913
        self,
        message,
        result=None,
        expected_digest=None,
        actual_digest=None,
        changed=None,
        added=None,
        removed=None,
    ):
        super().__init__(message, result=result)
        self.expected_digest = expected_digest
        self.actual_digest = actual_digest
        self.changed = changed or {}
        self.added = added or []
        self.removed = removed or []


class SamplingCutoffError(SamplingVerificationError):
    """Indicates that only late evidence exists for a sampled artifact.

    Late evidence remains available on ``result.late`` for a later re-review.
    """
