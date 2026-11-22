#
# Copyright 2026 PyCQA
#
# SPDX-License-Identifier: Apache-2.0
"""Loading and validation of exception mapping documents."""
import json

from bandit.exchange.errors import MappingValidationError
from bandit.exchange.model import ExceptionMapping

#: Current mapping document envelope identifier.
MAPPING_ENVELOPE = "bandit-exception-mappings"
#: Envelope identifiers accepted for backward compatibility.
SUPPORTED_ENVELOPES = (MAPPING_ENVELOPE, "bandit-baseline-exceptions")


def load_mapping_text(text):
    """Parse a mapping document from a JSON string."""
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise MappingValidationError(
            f"Mapping document is not valid JSON: {exc.msg}"
        ) from exc
    return load_mappings(payload)


def load_mappings(payload):
    """Validate a parsed mapping document and build mapping objects.

    The document envelope is versioned so older mapping files stay readable
    while structurally invalid input is rejected before any approval is
    computed.
    """
    if not isinstance(payload, dict):
        raise MappingValidationError(
            "Mapping document must be a JSON object"
        )

    envelope = payload.get("document")
    if envelope is not None and envelope not in SUPPORTED_ENVELOPES:
        raise MappingValidationError(
            f"Unsupported mapping document envelope: {envelope}"
        )

    version = payload.get("version", 1)
    if not isinstance(version, int) or version < 1:
        raise MappingValidationError("Mapping document 'version' must be >= 1")

    raw_mappings = payload.get("mappings")
    if not isinstance(raw_mappings, list) or not raw_mappings:
        raise MappingValidationError(
            "Mapping document must contain a non-empty 'mappings' list"
        )

    mappings = [ExceptionMapping.from_dict(item) for item in raw_mappings]

    seen_ids = set()
    for mapping in mappings:
        if mapping.mapping_id in seen_ids:
            raise MappingValidationError(
                f"Duplicate mapping id: {mapping.mapping_id}"
            )
        seen_ids.add(mapping.mapping_id)

    return {
        "document": envelope or MAPPING_ENVELOPE,
        "version": version,
        "mappings": mappings,
    }


def dump_mappings(mappings):
    """Serialise mapping objects back into a versioned JSON document."""
    return {
        "document": MAPPING_ENVELOPE,
        "version": 1,
        "mappings": [mapping.as_dict() for mapping in mappings],
    }
