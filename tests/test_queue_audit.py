import sys
import unittest
from datetime import datetime, timedelta
from os import path

sys.path.insert(0, path.dirname(path.dirname(path.abspath(__file__))))

from cvss.queue_audit import QueueAudit, QueueAuditError, base_score, detect_version

# Tiers are comparable across CVSS versions: 3.x and 4.0 tickets share one
# ladder. Version 2.0 is deliberately not configured, so legacy v2-only
# tickets fall into the manual-handling slot.
TIERS = [
    {"name": "P1-critical", "min_score": 9.0, "max_score": 10.0, "versions": ["3.0", "3.1", "4.0"]},
    {"name": "P2-high", "min_score": 7.0, "max_score": 8.9, "versions": ["3.0", "3.1", "4.0"]},
    {"name": "P3-medium", "min_score": 4.0, "max_score": 6.9, "versions": ["3.0", "3.1", "4.0"]},
    {"name": "P4-low", "min_score": 0.1, "max_score": 3.9, "versions": ["3.0", "3.1", "4.0"]},
    {"name": "P5-none", "min_score": 0.0, "max_score": 0.0, "versions": ["3.0", "3.1", "4.0"]},
]

CRITICAL_31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 9.8
HIGH_31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"  # 7.5
MEDIUM_31_A = "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H"  # 5.5
MEDIUM_31_B = "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"  # 5.5
CRITICAL_40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N"  # 9.9
LEGACY_V2 = "AV:N/AC:L/Au:N/C:P/I:P/A:P"  # 7.5, version not configured

START = datetime(2026, 11, 26, 9, 0, 0)


class FixedClock(object):
    def __init__(self, now):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, delta):
        self.now += delta


class TestQueueAudit(unittest.TestCase):
    def setUp(self):
        self.clock = FixedClock(START)
        self.audit = QueueAudit(TIERS, self.clock)

    def entries_for(self, ticket_id):
        return [entry for entry in self.audit.log if entry.ticket_id == ticket_id]

    def last_entry(self, ticket_id):
        return self.entries_for(ticket_id)[-1]

    def build_queue(self):
        self.audit.submit("T1", CRITICAL_31)
        self.audit.submit("T2", HIGH_31)
        self.audit.submit("T3", HIGH_31)
        self.audit.submit("T4", MEDIUM_31_A)
        self.audit.submit("T5", LEGACY_V2)

    def test_detect_version(self):
        self.assertEqual(detect_version(CRITICAL_31), "3.1")
        self.assertEqual(detect_version(CRITICAL_40), "4.0")
        self.assertEqual(detect_version(LEGACY_V2), "2.0")

    def test_base_score(self):
        self.assertEqual(base_score("3.1", CRITICAL_31), 9.8)
        self.assertEqual(base_score("4.0", CRITICAL_40), 9.9)
        self.assertEqual(base_score("2.0", LEGACY_V2), 7.5)

    def test_submission_version_and_vector_kept(self):
        self.build_queue()
        self.audit.correct("T1", HIGH_31)
        ticket = self.audit.tickets["T1"]
        self.assertEqual(ticket.submission_version, "3.1")
        self.assertEqual(ticket.submission_vector, CRITICAL_31)
        self.assertEqual(ticket.vector, HIGH_31)
        self.assertEqual(len(ticket.history), 2)
        self.assertEqual(ticket.history[0][2], CRITICAL_31)

    def test_initial_order_and_manual_slot(self):
        self.build_queue()
        self.assertEqual(self.audit.queue(), ["T1", "T2", "T3", "T4"])
        self.assertEqual(self.audit.manual_queue(), ["T5"])
        entry = self.last_entry("T5")
        self.assertIsNone(entry.to_pos)
        self.assertIn("manual handling", entry.reason)
        self.assertIn("2.0", entry.reason)

    def test_same_score_submission_keeps_queue_order(self):
        self.build_queue()
        self.audit.log = []
        self.clock.advance(timedelta(minutes=5))
        self.audit.submit("T6", HIGH_31)
        # Same tier and same score as T2/T3: appended after them, existing
        # order untouched except the displaced T4.
        self.assertEqual(self.audit.queue(), ["T1", "T2", "T3", "T6", "T4"])
        entry = self.last_entry("T6")
        self.assertEqual(entry.to_pos, 4)
        self.assertIn("P2-high", entry.reason)
        moved = {entry.ticket_id for entry in self.audit.log if entry.from_pos != entry.to_pos}
        self.assertEqual(moved, {"T6", "T4"})
        t4 = self.last_entry("T4")
        self.assertEqual((t4.from_pos, t4.to_pos), (4, 5))
        self.assertIn("shifted by T6", t4.reason)

    def test_cross_tier_correction_reorders(self):
        self.build_queue()
        self.audit.log = []
        self.clock.advance(timedelta(minutes=5))
        self.audit.correct("T3", CRITICAL_31)
        self.assertEqual(self.audit.queue(), ["T1", "T3", "T2", "T4"])
        entry = self.last_entry("T3")
        self.assertEqual((entry.from_pos, entry.to_pos), (3, 2))
        self.assertIn("cross-tier correction P2-high -> P1-critical", entry.reason)
        self.assertIn("7.5 -> 9.8", entry.reason)
        t2 = self.last_entry("T2")
        self.assertEqual((t2.from_pos, t2.to_pos), (2, 3))
        self.assertIn("shifted by T3", t2.reason)

    def test_same_score_correction_keeps_position(self):
        self.build_queue()
        self.audit.log = []
        self.clock.advance(timedelta(minutes=5))
        self.audit.correct("T4", MEDIUM_31_B)
        self.assertEqual(self.audit.queue(), ["T1", "T2", "T3", "T4"])
        entry = self.last_entry("T4")
        self.assertEqual((entry.from_pos, entry.to_pos), (4, 4))
        self.assertIn("existing queue order kept", entry.reason)
        # Nobody else moved.
        self.assertEqual(len(self.audit.log), 1)

    def test_pin_and_expiry_restores_order(self):
        self.build_queue()
        self.audit.log = []
        expires_at = self.clock() + timedelta(hours=2)
        self.audit.pin("T4", approver="handler-alice", expires_at=expires_at)
        self.assertEqual(self.audit.queue(), ["T4", "T1", "T2", "T3"])
        entry = self.last_entry("T4")
        self.assertEqual((entry.from_pos, entry.to_pos), (4, 1))
        self.assertIn("approved by handler-alice", entry.reason)
        # Before expiry nothing changes.
        self.clock.advance(timedelta(hours=1))
        self.audit.advance()
        self.assertEqual(self.audit.queue(), ["T4", "T1", "T2", "T3"])
        # After expiry the natural order is restored.
        self.clock.advance(timedelta(hours=1, seconds=1))
        self.audit.advance()
        self.assertEqual(self.audit.queue(), ["T1", "T2", "T3", "T4"])
        entry = self.last_entry("T4")
        self.assertEqual(entry.event, "pin-expired")
        self.assertEqual((entry.from_pos, entry.to_pos), (1, 4))
        self.assertIn("expired", entry.reason)
        self.assertIn("restored to natural position", entry.reason)
        t1 = self.last_entry("T1")
        self.assertEqual((t1.from_pos, t1.to_pos), (2, 1))
        self.assertIn("shifted by T4", t1.reason)

    def test_manual_ticket_correction_joins_queue(self):
        self.build_queue()
        self.audit.log = []
        self.clock.advance(timedelta(minutes=5))
        self.audit.correct("T5", CRITICAL_40)
        self.assertEqual(self.audit.manual_queue(), [])
        # 9.9 outranks the 9.8 of T1 inside P1-critical.
        self.assertEqual(self.audit.queue(), ["T5", "T1", "T2", "T3", "T4"])
        entry = self.last_entry("T5")
        self.assertEqual(entry.to_pos, 1)
        self.assertIn("left manual handling", entry.reason)
        self.assertIn("P1-critical", entry.reason)

    def test_correction_to_unconfigured_version_goes_manual(self):
        self.build_queue()
        self.audit.correct("T4", LEGACY_V2)
        self.assertEqual(self.audit.queue(), ["T1", "T2", "T3"])
        self.assertEqual(self.audit.manual_queue(), ["T5", "T4"])
        entry = self.last_entry("T4")
        self.assertIsNone(entry.to_pos)
        self.assertIn("moved to manual handling", entry.reason)

    def test_report_explains_every_move(self):
        self.build_queue()
        self.clock.advance(timedelta(minutes=5))
        self.audit.submit("T6", HIGH_31)
        self.clock.advance(timedelta(minutes=5))
        self.audit.correct("T3", CRITICAL_31)
        self.clock.advance(timedelta(minutes=5))
        expires_at = self.clock() + timedelta(hours=1)
        self.audit.pin("T4", approver="handler-alice", expires_at=expires_at)
        self.clock.advance(timedelta(hours=2))
        self.audit.advance()
        report = self.audit.report()
        # Every line is timestamped with the fixed clock and names a ticket.
        for line in report.splitlines():
            self.assertTrue(line.startswith("[2026-11-26T"))
            self.assertIn("] T", line)
        # The three replayed events each explain who moved and why.
        self.assertIn("T6: moved None -> 4", report)
        self.assertIn("cross-tier correction P2-high -> P1-critical", report)
        self.assertIn("approved jump by handler-alice", report)
        self.assertIn("restored to natural position", report)

    def test_errors(self):
        self.build_queue()
        with self.assertRaises(QueueAuditError):
            self.audit.submit("T1", HIGH_31)
        with self.assertRaises(QueueAuditError):
            self.audit.correct("UNKNOWN", HIGH_31)
        with self.assertRaises(QueueAuditError):
            self.audit.pin("UNKNOWN", approver="x", expires_at=START + timedelta(hours=1))
        with self.assertRaises(QueueAuditError):
            self.audit.pin("T5", approver="x", expires_at=START + timedelta(hours=1))
        with self.assertRaises(QueueAuditError):
            self.audit.pin("T1", approver="x", expires_at=START - timedelta(hours=1))
        with self.assertRaises(QueueAuditError):
            self.audit.submit("T7", "not-a-vector")


if __name__ == "__main__":
    unittest.main()
