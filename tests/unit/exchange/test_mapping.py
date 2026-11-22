#
# Copyright 2026 PyCQA
#
# SPDX-License-Identifier: Apache-2.0
import json

import testtools

from bandit.exchange.errors import MappingValidationError
from bandit.exchange.mapping import (
    MAPPING_ENVELOPE,
    dump_mappings,
    load_mapping_text,
    load_mappings,
)


def document(mappings, envelope=MAPPING_ENVELOPE, version=1):
    return {"document": envelope, "version": version, "mappings": mappings}


def one_mapping(**overrides):
    payload = {
        "id": "EXC-1",
        "source_rule": "B602",
        "target_rules": ["EXT-1", "EXT-2"],
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_until": "2027-01-01T00:00:00Z",
    }
    payload.update(overrides)
    return payload


class MappingLoaderTests(testtools.TestCase):
    def test_loads_one_to_many_mapping(self):
        loaded = load_mappings(document([one_mapping()]))
        self.assertEqual(MAPPING_ENVELOPE, loaded["document"])
        self.assertEqual(2, len(loaded["mappings"][0].target_rules))

    def test_legacy_envelope_still_accepted(self):
        loaded = load_mappings(
            document(
                [one_mapping()],
                envelope="bandit-baseline-exceptions",
            )
        )
        self.assertEqual(1, len(loaded["mappings"]))

    def test_invalid_json(self):
        with self.assertRaises(MappingValidationError):
            load_mapping_text("not-json")

    def test_unknown_envelope_rejected(self):
        with self.assertRaises(MappingValidationError):
            load_mappings(document([one_mapping()], envelope="something-else"))

    def test_empty_mappings_rejected(self):
        with self.assertRaises(MappingValidationError):
            load_mappings(document([]))

    def test_duplicate_ids_rejected(self):
        with self.assertRaises(MappingValidationError):
            load_mappings(document([one_mapping(), one_mapping()]))

    def test_invalid_timestamp_rejected(self):
        with self.assertRaises(MappingValidationError):
            load_mappings(document([one_mapping(valid_until="nope")]))

    def test_round_trip_dump(self):
        loaded = load_mappings(document([one_mapping()]))
        dumped = dump_mappings(loaded["mappings"])
        reloaded = load_mapping_text(json.dumps(dumped))
        self.assertEqual(
            reloaded["mappings"][0].target_ids(),
            loaded["mappings"][0].target_ids(),
        )
