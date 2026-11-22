# SPDX-License-Identifier: Apache-2.0

"""Adapter around the existing in-toto signature verification machinery.

The ledger never trusts a credential on its own. A credential is only
accepted for an artifact that a fully verified in-toto layout/link bundle
attests: the layout signature must pass with a trusted root key, the layout
must not be expired, and link files must be signed by functionaries that the
layout authorizes. The build artifact digest is then read from a verified link.
"""

import attr

from in_toto.exceptions import LayoutExpiredError
from in_toto.exceptions import ThresholdVerificationError
from in_toto.exceptions import LinkNotFoundError
from in_toto.models._signer import load_public_key_from_file
from in_toto.models.link import Link
from in_toto.models.metadata import Metadata
from in_toto.verifylib import load_links_for_layout
from in_toto.verifylib import verify_layout_expiration
from in_toto.verifylib import verify_link_signature_thresholds
from in_toto.verifylib import verify_metadata_signatures
from in_toto.exceptions import SignatureVerificationError

from quota_ledger.exceptions import SignatureError
from quota_ledger.exceptions import VerificationError


@attr.s(frozen=True)
class VerifiedRelease:
    """A release attested by verified in-toto metadata."

    Attributes:
      artifact_sha256: Digest of the build artifact from a verified link.
      channel: Delivery channel that the verified evidence is bound to.
      link_name: Name of the in-toto step that attests the artifact.
      functionary_keyid: Key id of the authorized link signer.
      layout: The verified, non-expired in-toto layout.
    """

    artifact_sha256 = attr.ib()
    channel = attr.ib()
    link_name = attr.ib()
    functionary_keyid = attr.ib()
    layout = attr.ib()


def _load_key_dict(key_paths):
    keys = {}
    for path in key_paths:
        key = load_public_key_from_file(path)
        keys[key["keyid"]] = key
    return keys


def verify_layout_file(layout_path, root_key_paths):
    """Load a layout and verify its signatures and expiration."""
    metadata = Metadata.load(layout_path)
    root_keys = _load_key_dict(root_key_paths)
    try:
        verify_metadata_signatures(metadata, root_keys)
        verify_layout_expiration(metadata.signed)
    except SignatureVerificationError as exc:
        raise SignatureError(
            f"layout {layout_path!r} signature invalid"
        ) from exc
    except LayoutExpiredError as exc:
        raise VerificationError(f"layout {layout_path!r} is expired") from exc
    return metadata, root_keys


def _verified_links(layout, link_dir):
    """Load links and keep only those with valid authorized signatures."""
    try:
        links_per_step = load_links_for_layout(layout, link_dir)
    except LinkNotFoundError as exc:
        raise VerificationError(str(exc)) from exc
    try:
        verified = verify_link_signature_thresholds(layout, links_per_step)
    except (SignatureVerificationError, ThresholdVerificationError) as exc:
        raise SignatureError("link signature verification failed") from exc
    return verified


def _digest_from_link(link_metadata):
    link = link_metadata.signed
    if not isinstance(link, Link):
        raise VerificationError("expected link metadata payload")
    products = link.products
    if not products:
        raise VerificationError(f"link {link.name!r} carries no products")
    digests = set()
    for artifact in products.values():
        if "sha256" not in artifact:
            raise VerificationError("only sha256 artifact digests are supported")
        digests.add(artifact["sha256"])
    if len(digests) > 1:
        raise VerificationError(
            f"link {link.name!r} products have inconsistent digests"
        )
    return digests.pop()


def load_verified_release(layout_path, root_key_paths, link_dir, channel,
                          link_name=None):
    """Verify an in-toto bundle and bind the evidence to a channel.

    Arguments:
      layout_path: Path to the signed layout metadata.
      root_key_paths: Paths of trusted layout verification public keys.
      link_dir: Directory containing the signed link metadata files.
      channel: Delivery channel to bind the verified evidence to.
      link_name: Optional step name whose link provides the digest. When
          omitted and exactly one step exists, that step link is used.
    """
    layout_metadata, _ = verify_layout_file(layout_path, root_key_paths)
    layout = layout_metadata.signed
    verified_links = _verified_links(layout, link_dir)

    step_names = list(verified_links)
    if link_name is None:
        if len(step_names) != 1:
            raise VerificationError(
                "link_name required when the layout has multiple steps"
            )
        link_name = step_names[0]

    step_links = verified_links.get(link_name)
    if not step_links:
        raise VerificationError(
            f"no verified link for step {link_name!r} on channel {channel!r}"
        )

    keyid, link_metadata = next(iter(step_links.items()))
    artifact_sha256 = _digest_from_link(link_metadata)

    return VerifiedRelease(
        artifact_sha256=artifact_sha256,
        channel=channel,
        link_name=link_name,
        functionary_keyid=keyid,
        layout=layout,
    )
