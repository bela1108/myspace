"""Build and sign delivery events."""

from typing import Any, Dict, Optional

from signedjson.acceptance.materials import canonical_digest
from signedjson.sign import sign_json
from signedjson.types import SigningKey


def build_event(
    event_id: str,
    signer: str,
    material: Dict[str, Any],
    predecessor: Optional[str] = None,
    material_id: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the unsigned content of a delivery event.

    The event commits to one original material by its canonical digest and
    declares at most one predecessor event. ``predecessor=None`` marks a
    chain root. ``material_id`` is the binding recorded in the main archive;
    when it disagrees with the digest the event is flagged as misbound.
    """

    content: Dict[str, Any] = {
        "event_id": event_id,
        "signer": signer,
        "material_id": material_id,
        "material_digest": canonical_digest(material),
        "predecessor": predecessor,
    }
    if extra is not None:
        content["extra"] = extra
    return content


def sign_event(
    event: Dict[str, Any], signer: str, signing_key: SigningKey
) -> Dict[str, Any]:
    """Sign an event in place with an Ed25519 signing key."""

    return sign_json(event, signer, signing_key)
