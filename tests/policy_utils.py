"""Shared helpers for the signature-policy acceptance tests.

The helpers only use the regular test PEM keys shipped under
``tests/data/pems``: no network access or private test infrastructure is
required.
"""

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives.serialization import load_pem_private_key

from securesystemslib.policy import MaterialPurpose, Receipt
from securesystemslib.signer import CryptoSigner, Signature, SSlibKey

PEMS_DIR = Path(__file__).parent / "data" / "pems"


def load_crypto_signer(pem_name: str, scheme: str) -> CryptoSigner:
    """Load one of the regular test PEM keys with an explicit scheme."""
    private_key = load_pem_private_key(
        (PEMS_DIR / f"{pem_name}_private.pem").read_bytes(), None
    )
    public_key = SSlibKey.from_crypto(private_key.public_key(), scheme=scheme)
    return CryptoSigner(private_key, public_key)


def make_signed_receipt(
    pem_name: str,
    scheme: str,
    purpose: MaterialPurpose,
    payload: bytes,
) -> tuple[Receipt, CryptoSigner]:
    """Sign ``payload`` and wrap it in a policy receipt."""
    signer = load_crypto_signer(pem_name, scheme)
    signature = signer.sign(payload)
    receipt = Receipt(
        purpose=purpose,
        payload=payload,
        key=signer.public_key,
        signature=signature,
    )
    return receipt, signer


def tamper(receipt: Receipt) -> Receipt:
    """Return a copy of ``receipt`` with one payload byte flipped."""
    payload = bytearray(receipt.payload)
    payload[0] ^= 0x01
    return Receipt(
        purpose=receipt.purpose,
        payload=bytes(payload),
        key=receipt.key,
        signature=Signature(
            receipt.signature.keyid,
            receipt.signature.signature,
            dict(receipt.signature.unrecognized_fields),
        ),
        schema_version=receipt.schema_version,
        unrecognized_fields=dict(receipt.unrecognized_fields),
    )
