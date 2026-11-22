# SPDX-License-Identifier: Apache-2.0

"""Helpers to generate local test keys and signed in-toto demo metadata.

All keys are ephemeral ed25519 keys written as PEM files: one layout root
key and one functionary key per delivery channel. The same build artifact
digest is reused by both channels, which only proves the artifact is the
same one; quota lines stay isolated per channel.
"""

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from in_toto.models.layout import Layout
from in_toto.models.layout import Step
from in_toto.models.link import Link
from in_toto.models.metadata import Metablock
from securesystemslib.signer import CryptoSigner
from securesystemslib.signer import SSlibKey

ARTIFACT_NAME = "release-bundle.tar.gz"
STEP_NAME = "build"


def generate_signer():
    return CryptoSigner.generate_ed25519()


def write_key_pair(signer, name, out_dir):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    private_pem = signer._private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = signer._private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    priv_path = out_dir / f"{name}_private.pem"
    pub_path = out_dir / f"{name}_public.pem"
    priv_path.write_bytes(private_pem)
    pub_path.write_bytes(public_pem)
    return priv_path, pub_path


def build_signed_layout(root_signer, functionary_signers, out_path,
                        step_name=STEP_NAME):
    # One authorized functionary per channel on a shared build step.
    functionary_keys = {}
    pubkey_ids = []
    for signer in functionary_signers:
        key = SSlibKey.from_crypto(signer._private_key.public_key())
        functionary_keys[key.keyid] = key.to_dict()
        functionary_keys[key.keyid]["keyid"] = key.keyid
        pubkey_ids.append(key.keyid)

    step = Step(name=step_name, pubkeys=pubkey_ids, threshold=1)
    layout = Layout(keys=functionary_keys, steps=[step], inspect=[])
    layout.set_relative_expiration(years=1)
    metadata = Metablock(signed=layout)
    metadata.create_signature(root_signer)
    metadata.dump(str(out_path))
    return metadata


def build_signed_link(functionary_signer, artifact_sha256, link_dir,
                      step_name=STEP_NAME):
    # Link product digest is the evidence covered by the link signature.
    link_dir = Path(link_dir)
    link_dir.mkdir(parents=True, exist_ok=True)
    link = Link(
        name=step_name,
        materials={},
        products={ARTIFACT_NAME: {"sha256": artifact_sha256}},
        byproducts={"stdout": "", "stderr": "", "return-value": 0},
        command=["./build.sh"],
        environment={},
    )
    metadata = Metablock(signed=link)
    metadata.create_signature(functionary_signer)
    keyid = functionary_signer.public_key.keyid
    out_path = link_dir / (step_name + "." + keyid[:8] + ".link")
    metadata.dump(str(out_path))
    return metadata, out_path
