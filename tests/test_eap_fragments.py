"""Tests for EAP-Message reassembly and State session binding.

Covers the 802.1X scenario in which an EAP-Message arrives split over
several RADIUS attributes: fragments must be contiguous and complete,
duplicates and interleaved fragments must not reach the authentication
state machine, and State must be bound to the NAS session it was issued
for. Concurrent NASes must not leak fragments or State into each other's
sessions.
"""
import os
import struct
import unittest

from pyrad.dictionary import Dictionary
from pyrad.eap import EAPFragmentError
from pyrad.eap import EAPSessionTracker
from pyrad.eap import EAPStateError
from pyrad.eap import packet_eap_fragments
from pyrad.eap import packet_state
from pyrad.packet import AccessRequest
from pyrad.packet import AuthPacket

DICTIONARY = os.path.join(os.path.dirname(__file__), os.pardir,
                          'pyrad', 'tests', 'data', 'freeradius')

NAS1 = '192.0.2.1'
NAS2 = '192.0.2.2'


def eap_message(identifier, payload, declared=None):
    """Build an EAP packet, with a forged Length if declared is given."""
    length = 4 + len(payload) if declared is None else declared
    return struct.pack('!BBH', 1, identifier, length) + payload


def split(message, size=10):
    """Split an EAP packet into RADIUS EAP-Message fragments."""
    return [message[i:i + size] for i in range(0, len(message), size)]


class Authenticator:
    """Minimal MFA state machine fed through an EAPSessionTracker.

    A request only reaches the state machine (and advances it) when the
    tracker accepted its State and fragments.
    """

    def __init__(self, tracker):
        self.tracker = tracker
        self.steps = {}

    def handle(self, nas, session, fragments, state=None):
        message = self.tracker.process(nas, session, fragments, state)
        self.steps[(nas, session)] = self.step(nas, session) + 1
        return message

    def step(self, nas, session):
        return self.steps.get((nas, session), 0)


class ReassemblyTests(unittest.TestCase):
    def setUp(self):
        self.tracker = EAPSessionTracker()

    def testSingleFragment(self):
        message = eap_message(1, b'hello')
        self.assertEqual(
            self.tracker.reassemble(NAS1, 'user1', [message]), message)

    def testSixFragments(self):
        message = eap_message(1, b'x' * 56)
        fragments = split(message)
        self.assertEqual(len(fragments), 6)
        self.assertEqual(
            self.tracker.reassemble(NAS1, 'user1', fragments), message)

    def testLongMessage(self):
        # 6 fragments of 253 octets: a message longer than one attribute
        message = eap_message(1, b'y' * (6 * 253 - 4))
        fragments = split(message, 253)
        self.assertEqual(len(fragments), 6)
        self.assertEqual(
            self.tracker.reassemble(NAS1, 'user1', fragments), message)

    def testEmptyLastFragment(self):
        # the attack of the ticket: six attributes, the last one empty
        message = eap_message(1, b'x' * 46, declared=60)
        fragments = split(message) + [b'']
        self.assertEqual(len(fragments), 6)
        with self.assertRaises(EAPFragmentError) as cm:
            self.tracker.reassemble(NAS1, 'user1', fragments)
        self.assertEqual(cm.exception.index, 5)
        self.assertEqual(cm.exception.length, 0)

    def testMissingFragment(self):
        # the declared length is never reached: a fragment is missing
        message = eap_message(1, b'x' * 46, declared=60)
        with self.assertRaises(EAPFragmentError) as cm:
            self.tracker.reassemble(NAS1, 'user1', split(message))
        self.assertEqual(cm.exception.index, 4)
        self.assertEqual(cm.exception.length, 10)

    def testOverflowingFragment(self):
        # more octets than the EAP header declares: interleaved extra
        message = eap_message(1, b'x' * 26)
        fragments = split(message) + [b'extra']
        with self.assertRaises(EAPFragmentError) as cm:
            self.tracker.reassemble(NAS1, 'user1', fragments)
        self.assertEqual(cm.exception.index, 3)
        self.assertEqual(cm.exception.length, 5)

    def testFirstFragmentTooShort(self):
        with self.assertRaises(EAPFragmentError) as cm:
            self.tracker.reassemble(NAS1, 'user1', [b'\x01\x01\x00'])
        self.assertEqual(cm.exception.index, 0)
        self.assertEqual(cm.exception.length, 3)

    def testInvalidDeclaredLength(self):
        with self.assertRaises(EAPFragmentError):
            self.tracker.reassemble(NAS1, 'user1', [eap_message(1, b'', declared=2)])
        with self.assertRaises(EAPFragmentError):
            self.tracker.reassemble(NAS1, 'user1', [eap_message(1, b'', declared=9000)])

    def testNoFragments(self):
        with self.assertRaises(EAPFragmentError):
            self.tracker.reassemble(NAS1, 'user1', [])

    def testDuplicateMessage(self):
        message = eap_message(1, b'hello')
        self.tracker.reassemble(NAS1, 'user1', [message])
        # a retransmission or replay must not enter the state machine again
        with self.assertRaises(EAPFragmentError) as cm:
            self.tracker.reassemble(NAS1, 'user1', [message])
        self.assertEqual(cm.exception.index, 0)
        # ... but the same identifier is fine on another session
        self.assertEqual(
            self.tracker.reassemble(NAS1, 'user2', [message]), message)

    def testInterleavedMessages(self):
        # fragments of a second EAP message glued behind the first
        first = eap_message(1, b'a' * 16)
        second = eap_message(2, b'b' * 16)
        with self.assertRaises(EAPFragmentError):
            self.tracker.reassemble(NAS1, 'user1', [first] + split(second))
        # the failed request consumed nothing: both messages still go
        # through on their own
        self.assertEqual(
            self.tracker.reassemble(NAS1, 'user1', [first]), first)
        self.assertEqual(
            self.tracker.reassemble(NAS1, 'user1', [second]), second)

    def testErrorCarriesOnlyIndexAndLength(self):
        secret_content = b'user-42-mfa-token'
        message = eap_message(1, secret_content + b'x' * 29, declared=60)
        fragments = split(message) + [b'']
        try:
            self.tracker.reassemble(NAS1, 'user1', fragments)
            self.fail('truncated message accepted')
        except EAPFragmentError as err:
            self.assertEqual((err.index, err.length), (5, 0))
            text = str(err)
            self.assertIn('5', text)
            self.assertIn('0', text)
            self.assertNotIn('user-42-mfa-token', text)


class StateBindingTests(unittest.TestCase):
    def setUp(self):
        self.tracker = EAPSessionTracker()

    def testBoundStateAccepted(self):
        self.tracker.bind_state(NAS1, 'user1', b'state-1')
        self.tracker.check_state(NAS1, 'user1', b'state-1')

    def testUnknownStateRejected(self):
        with self.assertRaises(EAPStateError):
            self.tracker.check_state(NAS1, 'user1', b'no-such-state')

    def testForeignStateRejected(self):
        # the same State value another NAS session uses
        self.tracker.bind_state(NAS2, 'user2', b'state-2')
        with self.assertRaises(EAPStateError):
            self.tracker.check_state(NAS1, 'user1', b'state-2')
        with self.assertRaises(EAPStateError):
            self.tracker.check_state(NAS2, 'user1', b'state-2')
        self.tracker.check_state(NAS2, 'user2', b'state-2')

    def testUnbindState(self):
        self.tracker.bind_state(NAS1, 'user1', b'state-1')
        self.tracker.unbind_state(b'state-1')
        with self.assertRaises(EAPStateError):
            self.tracker.check_state(NAS1, 'user1', b'state-1')

    def testEndSessionDropsStates(self):
        self.tracker.bind_state(NAS1, 'user1', b'state-1')
        self.tracker.bind_state(NAS2, 'user2', b'state-2')
        self.tracker.end_session(NAS1, 'user1')
        with self.assertRaises(EAPStateError):
            self.tracker.check_state(NAS1, 'user1', b'state-1')
        self.tracker.check_state(NAS2, 'user2', b'state-2')

    def testEmptyStateRejected(self):
        with self.assertRaises(ValueError):
            self.tracker.bind_state(NAS1, 'user1', b'')

    def testStateCheckedBeforeFragments(self):
        # a request with an unknown State is rejected before its
        # fragments are touched, so it cannot disturb the session
        message = eap_message(1, b'hello')
        with self.assertRaises(EAPStateError):
            self.tracker.process(NAS1, 'user1', [message], state=b'forged')
        self.assertEqual(
            self.tracker.reassemble(NAS1, 'user1', [message]), message)


class ConcurrentNasTests(unittest.TestCase):
    def setUp(self):
        self.tracker = EAPSessionTracker()
        self.auth = Authenticator(self.tracker)

    def testInterleavedSessionsStayApart(self):
        self.tracker.bind_state(NAS1, 'user1', b'state-1')
        self.tracker.bind_state(NAS2, 'user2', b'state-2')
        # both NASes use the same EAP Identifier and the same State
        # value; each must land in its own session
        message1 = eap_message(1, b'one-way-conversation!')
        message2 = eap_message(1, b'other-conversation!!')
        self.assertEqual(
            self.auth.handle(NAS1, 'user1', split(message1), b'state-1'),
            message1)
        self.assertEqual(
            self.auth.handle(NAS2, 'user2', split(message2), b'state-2'),
            message2)
        self.assertEqual(self.auth.step(NAS1, 'user1'), 1)
        self.assertEqual(self.auth.step(NAS2, 'user2'), 1)

    def testAttacksDoNotAdvanceMfaState(self):
        self.tracker.bind_state(NAS1, 'user1', b'state-1')
        message = eap_message(1, b'x' * 46, declared=60)
        # missing fragment
        with self.assertRaises(EAPFragmentError):
            self.auth.handle(NAS1, 'user1', split(message), b'state-1')
        # empty trailing fragment
        with self.assertRaises(EAPFragmentError):
            self.auth.handle(NAS1, 'user1', split(message) + [b''], b'state-1')
        # State of another NAS session
        self.tracker.bind_state(NAS2, 'user2', b'state-2')
        with self.assertRaises(EAPStateError):
            self.auth.handle(NAS1, 'user1', [eap_message(2, b'hi')], b'state-2')
        # unknown State
        with self.assertRaises(EAPStateError):
            self.auth.handle(NAS1, 'user1', [eap_message(2, b'hi')], b'forged')
        self.assertEqual(self.auth.step(NAS1, 'user1'), 0)
        self.assertEqual(self.auth.step(NAS2, 'user2'), 0)
        # the genuine message still completes afterwards
        complete = eap_message(1, b'x' * 56)
        self.auth.handle(NAS1, 'user1', split(complete), b'state-1')
        self.assertEqual(self.auth.step(NAS1, 'user1'), 1)
        # and its retransmission does not advance the state machine
        with self.assertRaises(EAPFragmentError):
            self.auth.handle(NAS1, 'user1', split(complete), b'state-1')
        self.assertEqual(self.auth.step(NAS1, 'user1'), 1)


class PacketTests(unittest.TestCase):
    def setUp(self):
        self.dict = Dictionary(DICTIONARY)
        self.tracker = EAPSessionTracker()

    def request(self, fragments, state=None):
        pkt = AuthPacket(code=AccessRequest, secret=b'secret', dict=self.dict)
        for fragment in fragments:
            pkt.AddAttribute('EAP-Message', fragment)
        if state is not None:
            pkt[24] = [state]
        return pkt

    def testPacketRoundTrip(self):
        message = eap_message(1, b'z' * 56)
        fragments = split(message)
        pkt = self.request(fragments, state=b'state-1')
        raw = pkt.RequestPacket()
        decoded = AuthPacket(packet=raw, secret=b'secret', dict=self.dict)
        # all six attributes survive encoding and decoding, in order
        self.assertEqual(packet_eap_fragments(decoded), fragments)
        self.assertEqual(packet_state(decoded), b'state-1')
        self.tracker.bind_state(NAS1, 'user1', b'state-1')
        self.assertEqual(
            self.tracker.process_packet(NAS1, 'user1', decoded), message)

    def testPacketWithoutDictionary(self):
        message = eap_message(1, b'hello')
        pkt = AuthPacket(code=AccessRequest, secret=b'secret')
        pkt[79] = [message]
        pkt[24] = [b'state-1']
        decoded = AuthPacket(packet=pkt.RequestPacket(), secret=b'secret')
        self.assertEqual(packet_eap_fragments(decoded), [message])
        self.assertEqual(packet_state(decoded), b'state-1')

    def testPacketWithoutEap(self):
        pkt = AuthPacket(code=AccessRequest, secret=b'secret', dict=self.dict)
        decoded = AuthPacket(packet=pkt.RequestPacket(), secret=b'secret',
                             dict=self.dict)
        self.assertIsNone(self.tracker.process_packet(NAS1, 'user1', decoded))

    def testRawReplyForwarding(self):
        # a decoded packet keeps its raw form for proxy-style forwarding
        message = eap_message(1, b'z' * 56)
        pkt = self.request(split(message))
        raw = pkt.RequestPacket()
        decoded = AuthPacket(packet=raw, secret=b'secret', dict=self.dict)
        self.assertEqual(decoded.raw_packet, raw)
        reply = decoded.CreateReply()
        raw_reply = reply.ReplyPacket()
        forwarded = AuthPacket(packet=raw_reply, secret=b'secret',
                               dict=self.dict)
        self.assertEqual(forwarded.raw_packet, raw_reply)
        self.assertEqual(forwarded.id, decoded.id)


if __name__ == '__main__':
    unittest.main()
