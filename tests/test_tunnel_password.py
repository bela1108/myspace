"""RFC 2868 Tunnel-Password (encrypt=2) codec tests."""

import hashlib
import struct
import unittest
import unittest.mock
from io import StringIO

from pyrad import packet
from pyrad.dictionary import Dictionary


SECRET = b'shared-secret'
REQUEST_AUTH = b'0123456789ABCDEF'
PASSWORD = 'a tunnel password that spans more than one md5 block'

DICTIONARY = '''
ATTRIBUTE Tunnel-Password          69 string has_tag,encrypt=2
ATTRIBUTE Tunnel-Private-Group-Id  81 string has_tag

VENDOR Test-Vendor 4242
BEGIN-VENDOR Test-Vendor
ATTRIBUTE Test-Vendor-Key           1 octets encrypt=2
END-VENDOR Test-Vendor
'''


def make_dictionary():
    return Dictionary(StringIO(DICTIONARY))


def crypt_blocks(plain, salt, vector, secret=SECRET):
    """The RFC 2868 section 3.5 block chain, independent of packet.py."""
    if len(plain) % 16:
        plain += b'\x00' * (16 - len(plain) % 16)
    result = b''
    last = vector + salt
    while plain:
        digest = hashlib.md5(secret + last).digest()
        block = bytes(a ^ b for (a, b) in zip(digest, plain[:16]))
        result += block
        last = block
        plain = plain[16:]
    return result


def decrypt_blocks(data, salt, vector, secret=SECRET):
    """Decrypt blocks with RFC 2868 section 3.5, independent of packet.py."""
    result = b''
    last = vector + salt
    while data:
        digest = hashlib.md5(secret + last).digest()
        block = bytes(a ^ b for (a, b) in zip(digest, data[:16]))
        result += block
        last = data[:16]
        data = data[16:]
    return result


def encrypt_value(plain, salt=b'\x80\x00', tag=b'\x01', vector=REQUEST_AUTH,
                  secret=SECRET):
    """Build a raw Tunnel-Password value (tag + salt + encrypted blocks)."""
    if isinstance(plain, str):
        plain = plain.encode('utf-8')
    inner = struct.pack('!B', len(plain)) + plain
    return tag + salt + crypt_blocks(inner, salt, vector, secret)


def decode_value(value, vector=REQUEST_AUTH, secret=SECRET):
    """Decode a raw Tunnel-Password value as a packet would."""
    pkt = packet.AuthPacket(
        code=packet.AccessAccept, secret=secret, authenticator=vector,
        dict=make_dictionary())
    pkt.request_authenticator = vector
    pkt[69] = [value]
    return pkt['Tunnel-Password']


class TunnelPasswordRoundTripTests(unittest.TestCase):
    def testTaggedRoundTrip(self):
        dictionary = make_dictionary()
        request = packet.AuthPacket(
            secret=SECRET, authenticator=REQUEST_AUTH, dict=dictionary)
        request['Tunnel-Password:1'] = PASSWORD

        received = packet.AuthPacket(
            packet=request.RequestPacket(), secret=SECRET, dict=dictionary)

        self.assertEqual(received['Tunnel-Password:1'], [PASSWORD])
        self.assertEqual(received['Tunnel-Password'], [PASSWORD])

    def testLengthPrefixAndTagAreSeparateFromSalt(self):
        dictionary = make_dictionary()
        request = packet.AuthPacket(
            secret=SECRET, authenticator=REQUEST_AUTH, dict=dictionary)
        request['Tunnel-Password:3'] = PASSWORD

        value = request[69][0]
        tag = value[0]
        salt = value[1:3]
        ciphertext = value[3:]
        plain = decrypt_blocks(ciphertext, salt, REQUEST_AUTH)

        self.assertEqual(tag, 3)
        self.assertTrue(salt[0] & 0x80)
        self.assertEqual(len(ciphertext) % 16, 0)
        self.assertEqual(plain[0], len(PASSWORD.encode('utf-8')))
        self.assertEqual(plain[1:1 + len(PASSWORD)], PASSWORD.encode('utf-8'))
        self.assertEqual(plain[1 + len(PASSWORD):], b'\x00' * (len(plain) - 1 - len(PASSWORD)))

    def testBlockChainRoundTrip(self):
        dictionary = make_dictionary()
        for password in ('', 'x', '0123456789abcde', '0123456789abcdef',
                         'x' * 16, 'x' * 17, PASSWORD, 'x' * 239):
            with self.subTest(length=len(password)):
                request = packet.AuthPacket(
                    secret=SECRET, authenticator=REQUEST_AUTH, dict=dictionary)
                request['Tunnel-Password:1'] = password
                received = packet.AuthPacket(
                    packet=request.RequestPacket(), secret=SECRET,
                    dict=dictionary)
                self.assertEqual(received['Tunnel-Password:1'], [password])

    def testMultipleTagsStaySeparate(self):
        dictionary = make_dictionary()
        request = packet.AuthPacket(
            secret=SECRET, authenticator=REQUEST_AUTH, dict=dictionary)
        reply = request.CreateReply()
        reply.AddAttribute('Tunnel-Password:1', 'first-tunnel-password')
        reply.AddAttribute('Tunnel-Password:2', 'second-tunnel-password')
        reply.AddAttribute('Tunnel-Password:1', 'third-tunnel-password')

        received = packet.AuthPacket(
            packet=reply.ReplyPacket(), secret=SECRET, dict=dictionary)
        received.request_authenticator = REQUEST_AUTH

        self.assertEqual(received['Tunnel-Password:1'],
                         ['first-tunnel-password', 'third-tunnel-password'])
        self.assertEqual(received['Tunnel-Password:2'], ['second-tunnel-password'])
        self.assertEqual(received['Tunnel-Password'],
                         ['first-tunnel-password', 'second-tunnel-password',
                          'third-tunnel-password'])

    def testSaltIsRandomAndNotReused(self):
        dictionary = make_dictionary()
        request = packet.AuthPacket(
            secret=SECRET, authenticator=REQUEST_AUTH, dict=dictionary)
        with unittest.mock.patch.object(
                packet.random_generator, 'randrange', return_value=0x1234):
            request['Tunnel-Password:1'] = ['same-password'] * 8

        salts = [value[1:3] for value in request[69]]
        self.assertEqual(len(set(salts)), len(salts))
        self.assertTrue(all(salt[0] & 0x80 for salt in salts))

    def testReplyUsesRequestAuthenticator(self):
        dictionary = make_dictionary()
        request = packet.AuthPacket(
            secret=SECRET, authenticator=REQUEST_AUTH, dict=dictionary)
        reply = request.CreateReply()
        reply['Tunnel-Password:2'] = PASSWORD
        raw = reply.ReplyPacket()

        received = packet.AuthPacket(packet=raw, secret=SECRET, dict=dictionary)
        received.request_authenticator = REQUEST_AUTH
        self.assertEqual(received['Tunnel-Password:2'], [PASSWORD])

        wrong = packet.AuthPacket(packet=raw, secret=SECRET, dict=dictionary)
        wrong.request_authenticator = b'fedcba9876543210'
        with self.assertRaises(packet.PacketError):
            wrong['Tunnel-Password:2']

    def testVendorSpecificRoundTrip(self):
        dictionary = make_dictionary()
        request = packet.AuthPacket(
            secret=SECRET, authenticator=REQUEST_AUTH, dict=dictionary)
        reply = request.CreateReply()
        reply['Tunnel-Password:1'] = PASSWORD
        reply['Test-Vendor-Key'] = b'\x01\x02\x03\x04' * 12

        received = packet.AuthPacket(
            packet=reply.ReplyPacket(), secret=SECRET, dict=dictionary)
        received.request_authenticator = REQUEST_AUTH

        self.assertEqual(received['Tunnel-Password:1'], [PASSWORD])
        self.assertEqual(received['Test-Vendor-Key'],
                         [b'\x01\x02\x03\x04' * 12])

    def testProxyForwardingRawAttributes(self):
        dictionary = make_dictionary()
        request = packet.AuthPacket(
            secret=SECRET, authenticator=REQUEST_AUTH, dict=dictionary)
        home_reply = request.CreateReply()
        home_reply.AddAttribute('Tunnel-Password:1', PASSWORD)
        home_reply.AddAttribute('Tunnel-Password:2', 'second-password')
        home_reply['Test-Vendor-Key'] = b'vendor-key' * 4

        home = packet.AuthPacket(
            packet=home_reply.ReplyPacket(), secret=SECRET, dict=dictionary)
        home.request_authenticator = REQUEST_AUTH

        # A proxy forwards the raw values without decrypting/re-encrypting
        # them; they are encrypted with the request authenticator, which is
        # also what the reply to the client uses.
        forwarded = packet.AuthPacket(
            code=packet.AccessAccept, id=home.id, secret=SECRET,
            authenticator=REQUEST_AUTH, dict=dictionary)
        forwarded[69] = list(home[69])
        forwarded[(4242, 1)] = list(home[(4242, 1)])

        received = packet.AuthPacket(
            packet=forwarded.ReplyPacket(), secret=SECRET, dict=dictionary)
        received.request_authenticator = REQUEST_AUTH
        self.assertEqual(received['Tunnel-Password:1'], [PASSWORD])
        self.assertEqual(received['Tunnel-Password:2'], ['second-password'])
        self.assertEqual(received['Test-Vendor-Key'], [b'vendor-key' * 4])

    def testProxyReencodingKeepsPlaintext(self):
        dictionary = make_dictionary()
        request = packet.AuthPacket(
            secret=SECRET, authenticator=REQUEST_AUTH, dict=dictionary)
        home_reply = request.CreateReply()
        home_reply.AddAttribute('Tunnel-Password:1', PASSWORD)
        home_reply.AddAttribute('Tunnel-Password:1', 'second-password')

        home = packet.AuthPacket(
            packet=home_reply.ReplyPacket(), secret=SECRET, dict=dictionary)
        home.request_authenticator = REQUEST_AUTH
        values = home['Tunnel-Password:1']

        forwarded = packet.AuthPacket(
            code=packet.AccessAccept, id=home.id, secret=SECRET,
            authenticator=REQUEST_AUTH, dict=dictionary)
        for value in values:
            forwarded.AddAttribute('Tunnel-Password:1', value)

        received = packet.AuthPacket(
            packet=forwarded.ReplyPacket(), secret=SECRET, dict=dictionary)
        received.request_authenticator = REQUEST_AUTH
        self.assertEqual(received['Tunnel-Password:1'], values)


class TunnelPasswordValidationTests(unittest.TestCase):
    def testMinimumBlockLength(self):
        # salt plus at least one full block is required
        for value in (b'\x01', b'\x01\x80\x00',
                      b'\x01\x80\x00' + b'x' * 15):
            with self.subTest(value=value):
                with self.assertRaises(packet.PacketError):
                    decode_value(value)

    def testBadTag(self):
        value = encrypt_value(b'password')
        value = b'\x20' + value[1:]
        with self.assertRaises(packet.PacketError) as caught:
            decode_value(value)
        self.assertNotIn(b'password', str(caught.exception).encode())

    def testBadSalt(self):
        value = encrypt_value(b'password')
        value = value[:1] + b'\x00\x01' + value[3:]
        with self.assertRaises(packet.PacketError) as caught:
            decode_value(value)
        self.assertNotIn(b'password', str(caught.exception).encode())

    def testBadPadding(self):
        value = encrypt_value(b'password')
        salt = value[1:3]
        inner = b'\x08password' + b'X' * 7
        value = value[:1] + salt + crypt_blocks(inner, salt, REQUEST_AUTH)
        with self.assertRaises(packet.PacketError) as caught:
            decode_value(value)
        self.assertNotIn(b'password', str(caught.exception).encode())

    def testLengthPrefixBeyondBlock(self):
        value = encrypt_value(b'password')
        salt = value[1:3]
        inner = b'\xffpassword'
        value = value[:1] + salt + crypt_blocks(inner, salt, REQUEST_AUTH)
        with self.assertRaises(packet.PacketError) as caught:
            decode_value(value)
        self.assertNotIn(b'password', str(caught.exception).encode())

    def testWrongSecretDoesNotReturnPlaintext(self):
        value = encrypt_value(PASSWORD)
        with self.assertRaises(packet.PacketError) as caught:
            decode_value(value, secret=b'wrong-secret')
        self.assertNotIn(PASSWORD.encode(), str(caught.exception).encode())

    def testMalformedValueIsNotForwardedAsPlaintext(self):
        dictionary = make_dictionary()
        value = encrypt_value(b'password')
        salt = value[1:3]
        inner = b'\x08password' + b'X' * 7
        malformed = value[:1] + salt + crypt_blocks(inner, salt, REQUEST_AUTH)

        request = packet.AuthPacket(
            secret=SECRET, authenticator=REQUEST_AUTH, dict=dictionary)
        received = packet.AuthPacket(
            packet=request.RequestPacket(), secret=SECRET, dict=dictionary)
        received[69] = [malformed]

        with self.assertRaises(packet.PacketError):
            received['Tunnel-Password']
        # A proxy that drops the broken attribute and replies does not echo
        # the decrypted password or its ciphertext.
        reply = request.CreateReply()
        reply.code = packet.AccessReject
        self.assertNotIn(b'password', reply.ReplyPacket())

    def testUntaggedLegacyValueStillDecodes(self):
        dictionary = make_dictionary()
        request = packet.AuthPacket(
            secret=SECRET, authenticator=REQUEST_AUTH, dict=dictionary)
        request[69] = [request.SaltCrypt('legacy-password')]
        self.assertEqual(request['Tunnel-Password:0'], ['legacy-password'])


if __name__ == '__main__':
    unittest.main()
