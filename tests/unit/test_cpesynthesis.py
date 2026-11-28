# -*- coding: utf-8 -*-

from cpe.comp.cpecomp import CPEComponent
from cpe.cpe import CPE
from cpe.cpesynthesis import (
    FieldVerdict,
    SynthesisRecord,
    Testimony,
    conclusions_needing_device_record,
)

import unittest


class ComplementarySynthesis(unittest.TestCase):
    """
    The product inventory reports a full version, the device measurement
    only confirms the same product but contributes concrete platform
    attributes. Both testimonies complement each other.
    """

    def setUp(self):
        self.inventory = Testimony(
            "inventory",
            "cpe:2.3:h:acme:router_9000:4.2.1:sp2:*:*:*:*:*:*")
        self.measurement = Testimony(
            "measurement",
            "cpe:2.3:h:acme:router_9000:*:*:*:*:*:*:armv7l:*")
        self.record = SynthesisRecord.synthesize(
            "edge-router-01", [self.inventory, self.measurement])

    def test_complementary_fields_are_adopted(self):
        """
        Fields attested by a single source are adopted from it.
        """

        version = self.record.verdict(CPEComponent.ATT_VERSION)
        self.assertEqual(version.status, FieldVerdict.COMPLEMENTED)
        self.assertEqual(version.value, "4.2.1")

        update = self.record.verdict(CPEComponent.ATT_UPDATE)
        self.assertEqual(update.status, FieldVerdict.COMPLEMENTED)
        self.assertEqual(update.value, "sp2")

        target_hw = self.record.verdict(CPEComponent.ATT_TARGET_HW)
        self.assertEqual(target_hw.status, FieldVerdict.COMPLEMENTED)
        self.assertEqual(target_hw.value, "armv7l")

    def test_field_provenance_is_kept(self):
        """
        Each adopted field keeps the sources that asserted it.
        """

        version = self.record.verdict(CPEComponent.ATT_VERSION)
        self.assertEqual(version.provenance, ("inventory",))

        target_hw = self.record.verdict(CPEComponent.ATT_TARGET_HW)
        self.assertEqual(target_hw.provenance, ("measurement",))

        product = self.record.verdict(CPEComponent.ATT_PRODUCT)
        self.assertEqual(product.status, FieldVerdict.AGREED)
        self.assertEqual(product.provenance, ("inventory", "measurement"))

    def test_nothing_is_pending(self):
        """
        Complementary testimonies leave no conclusion pending.
        """

        self.assertEqual(self.record.pending(), [])

    def test_synthesized_cpe_is_parseable(self):
        """
        The synthesized CPE Name merges the attested fields.
        """

        cpe = CPE(self.record.as_cpe(), CPE.VERSION_2_3)
        self.assertEqual(cpe.get_attribute_values("version"), ["4.2.1"])
        self.assertEqual(cpe.get_attribute_values("update"), ["sp2"])
        self.assertEqual(cpe.get_attribute_values("target_hw"), ["armv7l"])


class MutuallyExclusiveSynthesis(unittest.TestCase):
    """
    Two sources assert mutually exclusive values of an attribute.
    """

    def setUp(self):
        self.inventory = Testimony(
            "inventory",
            "cpe:2.3:h:acme:router_9000:4.2.1:*:*:*:*:*:armv7l:*")
        self.measurement = Testimony(
            "measurement",
            "cpe:2.3:h:acme:router_9000:4.2.1:*:*:*:*:*:x86_64:*")
        self.record = SynthesisRecord.synthesize(
            "edge-router-01", [self.inventory, self.measurement])

    def test_contested_field_keeps_candidates(self):
        """
        A mutually exclusive field keeps both values as pending
        candidates instead of picking a winner.
        """

        target_hw = self.record.verdict(CPEComponent.ATT_TARGET_HW)
        self.assertEqual(target_hw.status, FieldVerdict.CONTESTED)
        self.assertIsNone(target_hw.value)
        self.assertEqual(
            target_hw.candidates,
            (("armv7l", ("inventory",)), ("x86_64", ("measurement",))))

    def test_contested_field_is_pending(self):
        """
        A contested conclusion needs an additional device record.
        """

        self.assertEqual(self.record.pending(),
                         [CPEComponent.ATT_TARGET_HW])
        self.assertTrue(
            self.record.verdict(CPEComponent.ATT_TARGET_HW)
            .needs_device_record)

    def test_contested_field_is_any_in_synthesized_cpe(self):
        """
        A contested field is emitted as ANY in the synthesized CPE Name.
        """

        cpe = CPE(self.record.as_cpe(), CPE.VERSION_2_3)
        self.assertEqual(cpe.get_attribute_values("target_hw"), ["*"])
        self.assertEqual(cpe.get_attribute_values("version"), ["4.2.1"])


class RiskSystemAcceptance(unittest.TestCase):
    """
    Acceptance: three synthesis records of a same-named device let the
    risk system point out exactly which conclusion needs an additional
    device record.
    """

    def setUp(self):
        # Record 1: inventory and measurement complement each other
        self.record1 = SynthesisRecord.synthesize("edge-router-01", [
            Testimony(
                "inventory",
                "cpe:2.3:h:acme:router_9000:4.2.1:*:*:*:*:*:*:*"),
            Testimony(
                "measurement",
                "cpe:2.3:h:acme:router_9000:*:*:*:*:*:*:armv7l:*"),
        ])

        # Record 2: sources are mutually exclusive on target hardware
        self.record2 = SynthesisRecord.synthesize("edge-router-01", [
            Testimony(
                "inventory",
                "cpe:2.3:h:acme:router_9000:4.2.1:*:*:*:*:*:armv7l:*"),
            Testimony(
                "measurement",
                "cpe:2.3:h:acme:router_9000:4.2.1:*:*:*:*:*:x86_64:*"),
        ])

        # Record 3: sources agree on every attested field
        self.record3 = SynthesisRecord.synthesize("edge-router-01", [
            Testimony(
                "inventory",
                "cpe:2.3:h:acme:router_9000:4.2.1:*:*:*:*:*:armv7l:*"),
            Testimony(
                "measurement",
                "cpe:2.3:h:acme:router_9000:4.2.1:*:*:*:*:*:armv7l:*"),
        ])

    def test_risk_system_pinpoints_unsettled_conclusion(self):
        """
        Among the three records of the same device, only the contested
        target hardware conclusion needs an additional device record.
        """

        flagged = conclusions_needing_device_record(
            [self.record1, self.record2, self.record3])
        self.assertEqual(flagged, [CPEComponent.ATT_TARGET_HW])

    def test_settled_records_need_nothing(self):
        """
        Consistent records of the same device need no further record.
        """

        flagged = conclusions_needing_device_record(
            [self.record1, self.record3])
        self.assertEqual(flagged, [])

    def test_records_of_other_devices_are_rejected(self):
        """
        Records of different devices cannot be assessed together.
        """

        other = SynthesisRecord.synthesize("core-switch-02", [
            Testimony(
                "inventory",
                "cpe:2.3:h:acme:router_9000:4.2.1:*:*:*:*:*:*:*"),
            Testimony(
                "measurement",
                "cpe:2.3:h:acme:router_9000:*:*:*:*:*:*:armv7l:*"),
        ])

        with self.assertRaises(ValueError):
            conclusions_needing_device_record([self.record1, other])


class CrossRecordDisagreement(unittest.TestCase):
    """
    Records settled on their own may still disagree with each other.
    """

    def test_disagreeing_conclusions_are_flagged(self):
        """
        Two records of the same device that resolve an attribute to
        different values need an additional device record.
        """

        record_old = SynthesisRecord.synthesize("edge-router-01", [
            Testimony(
                "inventory",
                "cpe:2.3:h:acme:router_9000:4.2.1:*:*:*:*:*:*:*"),
            Testimony(
                "measurement",
                "cpe:2.3:h:acme:router_9000:4.2.1:*:*:*:*:*:*:*"),
        ])
        record_new = SynthesisRecord.synthesize("edge-router-01", [
            Testimony(
                "inventory",
                "cpe:2.3:h:acme:router_9000:5.0.0:*:*:*:*:*:*:*"),
            Testimony(
                "measurement",
                "cpe:2.3:h:acme:router_9000:5.0.0:*:*:*:*:*:*:*"),
        ])

        flagged = conclusions_needing_device_record(
            [record_old, record_new])
        self.assertEqual(flagged, [CPEComponent.ATT_VERSION])


class TestimonyNormalization(unittest.TestCase):
    """
    Testimonies expressed in other CPE versions are normalized before
    being synthesized.
    """

    def test_uri_testimony_is_normalized(self):
        """
        A CPE 2.3 URI testimony takes part in the synthesis.
        """

        record = SynthesisRecord.synthesize("edge-router-01", [
            Testimony("inventory", "cpe:/h:acme:router_9000:4.2.1"),
            Testimony(
                "measurement",
                "cpe:2.3:h:acme:router_9000:*:*:*:*:*:*:armv7l:*"),
        ])

        version = record.verdict(CPEComponent.ATT_VERSION)
        self.assertEqual(version.value, "4.2.1")
        self.assertEqual(version.provenance, ("inventory",))

    def test_single_testimony_is_rejected(self):
        """
        Synthesis requires at least two testimonies.
        """

        with self.assertRaises(ValueError):
            SynthesisRecord.synthesize("edge-router-01", [
                Testimony(
                    "inventory",
                    "cpe:2.3:h:acme:router_9000:4.2.1:*:*:*:*:*:*:*"),
            ])


if __name__ == "__main__":
    unittest.main()
