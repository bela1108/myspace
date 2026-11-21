# vim: set ai et ts=4 sw=4 sts=4:
"""Tests for selective-disclosure proofs over JKS archives."""

from __future__ import print_function

import hashlib
import json
import os
import struct
import unittest

import jks

from . import expected


CUR_PATH = os.path.dirname(os.path.abspath(__file__))
KS_PATH = os.path.join(CUR_PATH, "keystores")
PASSWORD = "12345678"


def make_store_bytes(*entries):
    return jks.KeyStore.new("jks", list(entries)).saves(PASSWORD)


def trusted(alias, certificate):
    return jks.TrustedCertEntry.new(alias, certificate)


class DisclosureTests(unittest.TestCase):
    def test_public_bundle_is_limited_to_approved_identities(self):
        store = jks.KeyStore.load(
            os.path.join(KS_PATH, "jks", "3certs.jks"),
            PASSWORD,
            try_decrypt_keys=False,
        )
        cert1, cert2, cert3 = expected.RSA2048_3certs.certs

        proof = store.disclosure_proof(["cert1", "cert2"])
        approved = set([
            jks.certificate_identity(cert1),
            jks.certificate_identity(cert2),
        ])

        self.assertEqual(set(proof.public_bundle["scope"]), approved)
        self.assertEqual(
            set(record["identity"]
                for record in proof.public_bundle["certificates"]),
            approved,
        )
        self.assertNotIn(
            jks.certificate_identity(cert3),
            proof.public_bundle["scope"],
        )
        self.assertNotIn("cert3", json.dumps(proof.public_bundle))
        self.assertEqual(len(proof.internal_attachment["entries"]), 3)
        self.assertTrue(proof.verify(store._source_bytes))

    def test_duplicate_certificate_occurrences_are_all_committed(self):
        shared = expected.RSA2048_3certs.certs[0]
        other = expected.RSA2048_3certs.certs[1]
        data = make_store_bytes(
            trusted("dup_a", shared),
            trusted("dup_b", shared),
            trusted("other", other),
        )
        store = jks.KeyStore.loads(data, PASSWORD, try_decrypt_keys=False)

        proof = store.disclosure_proof(["dup_a"])
        identity = jks.certificate_identity(shared)
        records = proof.public_bundle["certificates"]

        self.assertEqual(len(records), 2)
        self.assertEqual([record["identity"] for record in records],
                         [identity, identity])
        self.assertEqual(len(set(record["commitment"] for record in records)),
                         2)
        self.assertEqual(proof.public_bundle["occurrence_counts"][identity], 2)
        self.assertEqual(
            [opening["entry_position"]
             for opening in proof.internal_attachment["openings"]],
            [0, 1],
        )
        self.assertEqual(
            [opening["certificate_slot"]
             for opening in proof.internal_attachment["openings"]],
            [0, 0],
        )
        self.assertTrue(proof.verify(data))

    def test_duplicate_certificate_can_be_selected_by_identity(self):
        shared = expected.RSA2048_3certs.certs[0]
        data = make_store_bytes(
            trusted("first", shared),
            trusted("second", shared),
        )

        proof = jks.create_disclosure_proof(
            data, [jks.certificate_identity(shared)]
        )
        self.assertEqual(proof.public_bundle["certificate_count"], 2)
        self.assertEqual(
            len(proof.internal_attachment["openings"]),
            2,
        )

    def test_unreadable_entry_is_retained(self):
        first = expected.RSA2048_3certs.certs[0]
        second = expected.RSA2048_3certs.certs[1]
        data = make_store_bytes(
            trusted("readable", first),
            trusted("opaque", second),
        )
        manifest = jks.snapshot_manifest(data)
        second_offset = manifest["entries"][1]["offset"]
        damaged = (
            data[:second_offset]
            + struct.pack(">L", 9)
            + data[second_offset + 4:]
        )

        proof = jks.DisclosureProof.from_bytes(damaged, [first])
        entries = proof.internal_attachment["entries"]

        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[1]["position"], 1)
        self.assertEqual(entries[1]["kind"], "unreadable")
        self.assertFalse(entries[1]["readable"])
        self.assertEqual(entries[1]["alias"], "opaque")
        self.assertEqual(entries[1]["tag"], 9)
        self.assertTrue(proof.verify(damaged))
        self.assertTrue(jks.verify_disclosure_proof(
            proof.public_bundle,
            proof.internal_attachment,
            damaged,
        ))

    def test_same_certificate_does_not_cross_archives(self):
        shared = expected.RSA2048_3certs.certs[0]
        only_a = expected.RSA2048_3certs.certs[1]
        only_b = expected.RSA2048_3certs.certs[2]
        data_a = make_store_bytes(
            trusted("shared", shared),
            trusted("only_a", only_a),
        )
        data_b = make_store_bytes(
            trusted("shared", shared),
            trusted("only_b", only_b),
        )
        store_a = jks.KeyStore.loads(data_a, PASSWORD, try_decrypt_keys=False)
        store_b = jks.KeyStore.loads(data_b, PASSWORD, try_decrypt_keys=False)

        proof_a = store_a.disclosure_proof([shared])
        proof_b = store_b.disclosure_proof([shared])
        shared_identity = jks.certificate_identity(shared)

        self.assertEqual(proof_a.public_bundle["scope"], [shared_identity])
        self.assertEqual(proof_b.public_bundle["scope"], [shared_identity])
        self.assertNotEqual(
            proof_a.public_bundle["snapshot_digest"],
            proof_b.public_bundle["snapshot_digest"],
        )
        self.assertNotEqual(
            proof_a.public_bundle["certificates"][0]["commitment"],
            proof_b.public_bundle["certificates"][0]["commitment"],
        )

        self.assertFalse(proof_a.verify(data_b))
        self.assertFalse(proof_b.verify(data_a))
        self.assertFalse(jks.verify_disclosure_proof(
            proof_a.public_bundle,
            proof_b.internal_attachment,
            data_b,
        ))
        self.assertFalse(jks.verify_disclosure_proof(
            proof_a.public_bundle,
            proof_a.internal_attachment,
            data_b,
        ))

    def test_private_key_entry_stays_encrypted(self):
        store = jks.KeyStore.load(
            os.path.join(KS_PATH, "jks", "RSA2048_3certs.jks"),
            PASSWORD,
            try_decrypt_keys=False,
        )
        private_entry = store.entries["mykey"]
        certificate = private_entry.cert_chain[0][1]

        proof = store.disclosure_proof([certificate])

        self.assertFalse(private_entry.is_decrypted())
        self.assertEqual(proof.public_bundle["certificate_count"], 1)
        self.assertTrue(proof.verify(store._source_bytes))

    def test_removing_a_duplicate_from_both_halves_fails(self):
        shared = expected.RSA2048_3certs.certs[0]
        data = make_store_bytes(
            trusted("first", shared),
            trusted("second", shared),
        )
        proof = jks.create_disclosure_proof(data, [shared])
        public = json.loads(json.dumps(proof.public_bundle))
        internal = json.loads(json.dumps(proof.internal_attachment))
        identity = jks.certificate_identity(shared)

        public["certificates"].pop()
        public["commitments"].pop()
        public["certificate_count"] -= 1
        public["occurrence_counts"][identity] -= 1
        internal["openings"].pop()

        self.assertFalse(jks.verify_disclosure_proof(public, internal, data))

    def test_json_round_trip_preserves_proof(self):
        data = make_store_bytes(
            trusted("one", expected.RSA2048_3certs.certs[0]),
        )
        proof = jks.create_disclosure_proof(data, ["one"])
        public = json.loads(json.dumps(proof.public_bundle))
        internal = json.loads(json.dumps(proof.internal_attachment))

        self.assertTrue(jks.verify_disclosure_proof(public, internal, data))
        self.assertEqual(
            public["snapshot_digest"],
            hashlib.sha256(data).hexdigest(),
        )


if __name__ == "__main__":
    unittest.main()
