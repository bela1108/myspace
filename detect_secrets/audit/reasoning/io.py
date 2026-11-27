"""Persistence for multi-explanation reasoning baselines.

Reasoning baselines are JSON documents versioned independently from the
secret-scan baseline. The legacy, already-audited ``detect-secrets`` baseline
remains readable through :func:`load_legacy_baseline`.
"""
import json
from typing import Any
from typing import Dict

from ...core import baseline as secret_baseline
from ...core.secrets_collection import SecretsCollection
from ...exceptions import InvalidBaselineError
from ...exceptions import UnableToReadBaselineError
from .case import ReasoningCase
from .models import InvalidReasoningError
from .models import ReasoningSchemaVersion


def save_case(case: ReasoningCase, filename: str) -> None:
    """Writes the full reasoning state (exclusions, reasons, evidence) to disk."""
    with open(filename, 'w') as f:
        f.write(json.dumps(case.json(), indent=2) + '\n')


def load_case(filename: str) -> ReasoningCase:
    """Loads a reasoning baseline previously written by :func:`save_case`.

    :raises: InvalidReasoningError when the file is missing, malformed, or
        uses an unsupported schema version.
    """
    try:
        with open(filename) as f:
            data = json.loads(f.read())
    except (FileNotFoundError, IOError, json.decoder.JSONDecodeError) as e:
        raise InvalidReasoningError(f'Not a valid reasoning baseline: {filename}') from e

    if not isinstance(data, dict):
        raise InvalidReasoningError('Reasoning baseline must be a JSON object.')

    supported_versions = {version.value for version in ReasoningSchemaVersion}
    version = data.get('version')
    if version not in supported_versions:
        raise InvalidReasoningError(
            f'Unsupported reasoning baseline version: {version!r}.',
        )

    return ReasoningCase.from_dict(data)


def load_legacy_baseline(filename: str) -> SecretsCollection:
    """Reads an existing, already-audited ``detect-secrets`` baseline.

    Secret labels (``is_secret``) captured by prior audits are preserved, so a
    reasoning case can start from an established audit baseline.

    :raises: InvalidBaselineError
    :raises: UnableToReadBaselineError
    """
    raw_baseline: Dict[str, Any] = secret_baseline.load_from_file(filename)
    if 'results' not in raw_baseline:
        raise InvalidBaselineError
    return secret_baseline.load(raw_baseline, filename)
