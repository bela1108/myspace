"""Fixtures shared by the acceptance test modules."""

import pytest

from signedjson.acceptance.events import build_event, sign_event
from signedjson.acceptance.materials import material_id
from signedjson.acceptance.verifier import AcceptanceVerifier
from signedjson.key import (
    encode_verify_key_base64,
    generate_signing_key,
    get_verify_key,
)


@pytest.fixture
def signer():
    return "desk-1"


@pytest.fixture
def signing_key():
    return generate_signing_key("1")


@pytest.fixture
def verify_key(signing_key):
    return get_verify_key(signing_key)


@pytest.fixture
def originals():
    return {
        "contract": {"doc": "contract", "v": 1},
        "appendix-a": {"doc": "appendix-a", "v": 1},
        "appendix-b": {"doc": "appendix-b", "v": 1},
        "rider": {"doc": "rider", "v": 1},
    }


@pytest.fixture
def materials(originals):
    return {material_id(payload): payload for payload in originals.values()}


@pytest.fixture
def material_ids(originals):
    return {name: material_id(payload) for name, payload in originals.items()}


@pytest.fixture
def make_event(signer, signing_key):
    def _make(event_id, material, predecessor=None, declared=None):
        event = build_event(
            event_id,
            signer,
            material,
            predecessor=predecessor,
            material_id=declared,
        )
        return sign_event(event, signer, signing_key)

    return _make


@pytest.fixture
def verifier(materials, signer, verify_key):
    return AcceptanceVerifier(materials=materials, keys={signer: verify_key})


@pytest.fixture
def key_config(signer, verify_key):
    return {
        signer: {
            "key_id": "ed25519:1",
            "key": encode_verify_key_base64(verify_key),
        }
    }
