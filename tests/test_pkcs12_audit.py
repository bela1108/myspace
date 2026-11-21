# coding: utf-8
from __future__ import unicode_literals, division, absolute_import, print_function

import os
import unittest

from asn1crypto import cms, core, keys, pem, pkcs12, pkcs12_audit
from ._unittest_compat import patch

patch()


tests_root = os.path.dirname(__file__)
fixtures_dir = os.path.join(tests_root, "fixtures")
inventory_fixtures = os.path.join(fixtures_dir, "pkcs12_inventory")


def fixture(name):
    return os.path.join(inventory_fixtures, name)


def mac_data():
    return {
        "mac": {
            "digest_algorithm": {"algorithm": "sha256"},
            "digest": b"\x00" * 32,
        },
        "mac_salt": b"mac-salt-0000001",
        "iterations": 120000,
    }


def build_pfx(safe_contents):
    content_info = cms.ContentInfo({
        "content_type": "data",
        "content": safe_contents.dump(),
    })
    auth_safe = cms.ContentInfo({
        "content_type": "data",
        "content": pkcs12.AuthenticatedSafe([content_info]).dump(),
    })
    return pkcs12.Pfx({
        "version": "v3",
        "auth_safe": auth_safe,
        "mac_data": mac_data(),
    })


class PKCS12AuditTests(unittest.TestCase):

    def test_existing_archive_layers(self):
        path = os.path.join(fixtures_dir, "test-tripledes.p12")
        with open(path, "rb") as f:
            original = f.read()

        inventory = pkcs12_audit.inventory(original)

        self.assertEqual("pkcs12_inventory", inventory["kind"])
        self.assertEqual("v3", inventory["version"])
        self.assertEqual("encrypted_data", inventory["encapsulation"][1]["content_type"])
        self.assertEqual("pkcs12_sha1_rc2_40", inventory["encapsulation"][1]["algorithm"])
        self.assertEqual("rc2_40", inventory["encapsulation"][1]["cipher"])
        self.assertEqual("pkcs12", inventory["encapsulation"][1]["kdf"])
        self.assertEqual("unobservable", inventory["encapsulation"][1]["content_state"])
        self.assertEqual(
            "pfx.authenticated_safe[0].encrypted_content_info",
            inventory["encapsulation"][1]["protection_layer"]
        )

        bag = inventory["safe_bags"][0]
        self.assertEqual("pkcs8_shrouded_key_bag", bag["bag_id"])
        self.assertEqual("pkcs12_sha1_tripledes_3key", bag["algorithm"])
        self.assertEqual("unobservable", bag["content_state"])
        self.assertEqual(
            "pfx.authenticated_safe[1].safe_contents[0].bag_value",
            bag["protection_layer"]
        )
        self.assertEqual(["local_key_id", "friendly_name"], [a["type"] for a in bag["attributes"]])

        self.assertEqual("sha1", inventory["integrity"]["algorithm"])
        self.assertEqual("pfx.mac_data", inventory["integrity"]["layer"])
        self.assertIn("pfx.authenticated_safe[0].encrypted_content_info", [
            item["layer"] for item in inventory["unobservable"]
        ])

        # Inventorying must not mutate the archive bytes or its parsed value.
        self.assertEqual(original, pkcs12.Pfx.load(original).dump())
        with open(path, "rb") as f:
            self.assertEqual(original, f.read())

    def test_pfx_method_and_module_function_agree(self):
        path = fixture("shared-outer-weak-inner.p12")
        with open(path, "rb") as f:
            from_method = pkcs12.Pfx.load(f.read()).inventory()
        from_function = pkcs12.inventory(path)
        self.assertEqual(from_method.to_json(), from_function.to_json())

    def test_paired_samples_share_outer_layer(self):
        with open(fixture("shared-outer-weak-inner.p12"), "rb") as f:
            weak_pfx = pkcs12.Pfx.load(f.read())
        with open(fixture("shared-outer-strong-inner.p12"), "rb") as f:
            strong_pfx = pkcs12.Pfx.load(f.read())

        # The sealed outer ContentInfo and the MAC encoding are byte-identical.
        self.assertEqual(
            weak_pfx.authenticated_safe[0].dump(),
            strong_pfx.authenticated_safe[0].dump()
        )
        self.assertEqual(weak_pfx["mac_data"].dump(), strong_pfx["mac_data"].dump())

        weak = pkcs12_audit.inventory(weak_pfx)
        strong = pkcs12_audit.inventory(strong_pfx)

        outer_keys = (
            "content_type",
            "algorithm",
            "algorithm_oid",
            "cipher",
            "cipher_oid",
            "kdf",
            "kdf_oid",
            "iterations",
            "salt_length",
            "iv_length",
            "protection_layer",
        )
        for key in outer_keys:
            self.assertEqual(weak["encapsulation"][1][key], strong["encapsulation"][1][key])

        self.assertEqual(weak["integrity"]["algorithm"], strong["integrity"]["algorithm"])
        self.assertEqual(weak["integrity"]["iterations"], strong["integrity"]["iterations"])

        self.assertEqual("rc2_40", weak["safe_bags"][0]["cipher"])
        self.assertEqual("aes256_cbc", strong["safe_bags"][0]["cipher"])
        self.assertEqual("pass", weak["encapsulation"][1]["status"])
        self.assertEqual("pass", strong["encapsulation"][1]["status"])

    def test_governance_report_points_only_at_changed_inner_layer(self):
        report = pkcs12_audit.governance_report([
            ("weak-inner", fixture("shared-outer-weak-inner.p12")),
            ("strong-inner", fixture("shared-outer-strong-inner.p12")),
        ])

        self.assertEqual("change_required", report["summary"]["conclusion"])
        self.assertFalse(report["summary"]["compliant"])
        self.assertIn("pkcs12_governance_report", report.to_json())
        self.assertEqual(
            ["pfx.authenticated_safe[1].safe_contents[0].bag_value"],
            report["recommended_layers"]
        )
        self.assertEqual("weak-inner", report["layers_to_change"][0]["archive"])
        self.assertEqual(
            "pfx.authenticated_safe[1].safe_contents[0].bag_value",
            report["layers_to_change"][0]["layer"]
        )
        self.assertNotIn(
            "pfx.authenticated_safe[0].encrypted_content_info",
            report["recommended_layers"]
        )
        self.assertEqual(
            [],
            [item for item in report["layers_to_change"] if item["archive"] == "strong-inner"]
        )

    def test_policy_findings_bind_to_the_configured_layer(self):
        report = pkcs12_audit.governance_report(
            [("weak-inner", fixture("shared-outer-weak-inner.p12"))],
            policy={"min_pbkdf2_iterations": 200000}
        )
        findings = [item for item in report["findings"] if item["code"] == "pbkdf2_iterations_low"]
        self.assertEqual(1, len(findings))
        self.assertEqual("pfx.authenticated_safe[0].encrypted_content_info", findings[0]["layer"])
        self.assertEqual("pfx.authenticated_safe[0]", findings[0]["scope_layer"])

    def test_sealed_and_unknown_layers_are_not_passing(self):
        strong = pkcs12_audit.inventory(fixture("shared-outer-strong-inner.p12"))
        self.assertNotEqual("pass", strong["summary"]["status"])
        self.assertFalse(strong["summary"]["compliant"])
        self.assertIn("unobservable", [item["status"] for item in strong["findings"]])

        unknown_bag = pkcs12.SafeBag({
            "bag_id": "1.2.3.4",
            "bag_value": core.Any.load(core.Integer(1).dump()),
        })
        pfx = build_pfx(pkcs12.SafeContents([unknown_bag]))
        inventory = pkcs12_audit.inventory(pfx)

        self.assertNotEqual("pass", inventory["summary"]["status"])
        self.assertFalse(inventory["summary"]["compliant"])
        unknown_layers = [item["layer"] for item in inventory["unknown"]]
        self.assertEqual(["pfx.authenticated_safe[0].safe_contents[0]"], unknown_layers)
        unknown_findings = [item for item in inventory["findings"] if item["status"] == "unknown"]
        self.assertEqual(1, len(unknown_findings))
        self.assertEqual("pfx.authenticated_safe[0].safe_contents[0]", unknown_findings[0]["layer"])

        report = pkcs12_audit.governance_report([("unknown", inventory)])
        self.assertEqual("review_required", report["summary"]["conclusion"])
        self.assertEqual([], report["layers_to_change"])
        self.assertEqual("unknown", report["review_required"][0]["status"])

    def test_unencrypted_private_key_bag_is_bound_to_bag_value(self):
        key_path = os.path.join(fixtures_dir, "globalsign_example_keys", "SSL1.key")
        with open(key_path, "rb") as f:
            type_name, headers, der_bytes = pem.unarmor(f.read())
        self.assertEqual("RSA PRIVATE KEY", type_name)
        private_key = keys.PrivateKeyInfo.wrap(keys.RSAPrivateKey.load(der_bytes), "rsa")
        bag = pkcs12.SafeBag({
            "bag_id": "key_bag",
            "bag_value": private_key,
        })
        inventory = pkcs12_audit.inventory(build_pfx(pkcs12.SafeContents([bag])))

        self.assertEqual("rsa", inventory["safe_bags"][0]["key_algorithm"])
        finding = [item for item in inventory["findings"] if item["code"] == "unencrypted_private_key"][0]
        self.assertEqual("fail", finding["status"])
        self.assertEqual(
            "pfx.authenticated_safe[0].safe_contents[0].bag_value",
            finding["layer"]
        )
        self.assertEqual("pfx.authenticated_safe[0].safe_contents[0]", finding["scope_layer"])
