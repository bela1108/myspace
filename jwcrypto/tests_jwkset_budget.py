import json
import tracemalloc
import unittest

from jwcrypto import jwk
from jwcrypto import jws
from jwcrypto import jwt
from jwcrypto.common import json_encode


def make_oct(kid='sig', size=256):
    key = jwk.JWK.generate(kty='oct', size=size)
    key['kid'] = kid
    return key


class JWKSetBudgetTests(unittest.TestCase):

    def setUp(self):
        self.key = make_oct()
        self.good = json.loads(self.key.export())

    def _signed_token(self, kid='sig'):
        token = jws.JWS(b'payload')
        token.add_signature(
            self.key, None,
            json_encode({'alg': 'HS256', 'kid': kid}), None)
        return token.serialize(compact=True)

    def test_healthy_single_and_triple_keyset_roundtrip(self):
        keys = [self.good]
        for index in range(2):
            extra = json.loads(make_oct('k' + str(index)).export())
            keys.append(extra)
        single = jwk.JWKSet.from_json(json_encode({'keys': [self.good]}))
        triple = jwk.JWKSet.from_json(json_encode({'keys': keys}))
        self.assertEqual(1, len(single['keys']))
        self.assertEqual(3, len(triple['keys']))
        self.assertFalse(single.has_quarantine())
        self.assertFalse(triple.has_quarantine())
        self.assertEqual(single.export(),
                         jwk.JWKSet.from_json(single.export()).export())

    def test_bad_tail_key_does_not_invalidate_good_keys(self):
        bad = {'kty': 'RSA', 'kid': 'bad',
               'n': 'ab!cd', 'e': 'AQAB'}
        keyset = json_encode({'keys': [self.good, bad]})
        result = jwk.JWKSet.from_json(keyset)
        self.assertEqual(1, len(result['keys']))
        self.assertEqual(self.key, result.get_key('sig'))
        report = result.quarantine_report()
        self.assertEqual(1, len(report))
        self.assertEqual(1, report[0]['index'])
        self.assertEqual('invalid_base64url', report[0]['reason'])
        self.assertEqual('bad', report[0]['kid'])
        self.assertEqual('RSA', report[0]['kty'])
        self.assertTrue(report[0]['detail'])

    def test_quarantine_records_are_exportable_one_by_one(self):
        bad_first = {'kty': 'RSA', 'n': 'ab!cd',
                     'e': 'AQAB', 'kid': 'b1'}
        bad_second = {'kty': 'oct', 'kid': 'b2'}
        keyset = json_encode({'keys': [bad_first, self.good, bad_second]})
        result = jwk.JWKSet.from_json(keyset)
        self.assertEqual(1, len(result['keys']))
        indices = [record.index for record in result.quarantine]
        self.assertEqual([0, 2], indices)
        reasons = {record.index: record.reason for record in result.quarantine}
        self.assertEqual('invalid_base64url', reasons[0])
        self.assertEqual('construction_failed', reasons[2])
        exported = result.quarantine_report()
        self.assertEqual(indices, [row['index'] for row in exported])
        self.assertTrue(all('reason' in row and 'detail' in row
                            for row in exported))

    def test_unknown_kty_is_quarantined(self):
        future = {'kty': 'future'}
        keyset = json_encode({'keys': [future, self.good]})
        result = jwk.JWKSet.from_json(keyset)
        self.assertEqual(1, len(result['keys']))
        self.assertEqual('kty_invalid',
                         result.quarantine[0].reason)

    def test_missing_kty_is_quarantined(self):
        result = jwk.JWKSet.from_json(json_encode({'keys': [{}]}))
        self.assertEqual(0, len(result['keys']))
        self.assertEqual('kty_missing', result.quarantine[0].reason)

    def test_duplicate_kid_is_quarantined_by_default(self):
        duplicate = dict(self.good)
        result = jwk.JWKSet.from_json(
            json_encode({'keys': [self.good, duplicate]}))
        self.assertEqual(1, len(result['keys']))
        self.assertEqual('duplicate_kid',
                         result.quarantine[0].reason)
        self.assertEqual(set(), result.duplicate_kids())
        self.assertEqual('sig', result.quarantine[0].kid)

    def test_duplicate_kid_budget_can_admit_then_gate_flags_it(self):
        other = json.loads(make_oct('sig').export())
        budget = jwk.JWKSetBudget(max_duplicate_kid=1)
        result = jwk.JWKSet.from_json(
            json_encode({'keys': [self.good, other]}), budget=budget)
        self.assertEqual(2, len(result['keys']))
        self.assertEqual({'sig'}, result.duplicate_kids())
        with self.assertRaises(jwk.AmbiguousKeySelection):
            result.get_verification_keys('sig')

    def test_structurally_invalid_keysets_raise(self):
        for invalid in ['', 'null', '[]', '{}',
                        '{"keys": 1}', '{"keys": [1]}']:
            with self.assertRaises(jwk.InvalidJWKValue):
                jwk.JWKSet.from_json(invalid)

    def test_quarantine_cap_bounds_retained_records(self):
        entries = []
        for index in range(20):
            entries.append({'kty': 'RSA', 'kid': 'b',
                           'n': 'ab!cd', 'e': 'AQAB'})
        budget = jwk.JWKSetBudget(max_quarantine=5, max_keys=100)
        result = jwk.JWKSet.from_json(
            json_encode({'keys': entries}), budget=budget)
        self.assertEqual(0, len(result['keys']))
        self.assertEqual(5, len(result.quarantine))
        self.assertEqual(15, result.quarantine_suppressed_count)
        self.assertTrue(result.has_quarantine())

    def test_accepted_healthy_keys_survive_later_budget_failure(self):
        entries = [self.good]
        for index in range(30):
            entries.append({'kty': 'RSA',
                           'kid': 'x' + str(index),
                           'n': 'ab!cd', 'e': 'AQAB'})
        budget = jwk.JWKSetBudget(max_quarantine=10)
        result = jwk.JWKSet.from_json(
            json_encode({'keys': entries}), budget=budget)
        self.assertEqual(1, len(result['keys']))
        self.assertEqual(self.key, result.get_key('sig'))
        self.assertEqual(10, len(result.quarantine))
        self.assertEqual(20, result.quarantine_suppressed_count)

    def test_dict_input_is_supported(self):
        result = jwk.JWKSet.from_json({'keys': [self.good]})
        self.assertEqual(1, len(result['keys']))

    def test_budget_type_is_validated(self):
        with self.assertRaises(TypeError):
            jwk.JWKSet().import_keyset(
                json_encode({'keys': []}), budget=object())

class JWKSetVerificationGateTests(unittest.TestCase):

    def setUp(self):
        self.key = make_oct()
        self.good = json.loads(self.key.export())
        token = jws.JWS(b'payload')
        token.add_signature(self.key, None,
                            json_encode({'alg': 'HS256',
                                         'kid': 'sig'}), None)
        self.compact = token.serialize(compact=True)

    def _jws(self):
        token = jws.JWS()
        token.deserialize(self.compact)
        return token

    def test_healthy_keyset_verifies(self):
        keyset = jwk.JWKSet.from_json(
            json_encode({'keys': [self.good]}))
        self._jws().verify(keyset)

    def test_duplicate_kid_raises_ambiguity_on_jws_verify(self):
        other = json.loads(make_oct('sig').export())
        keyset = jwk.JWKSet.from_json(
            json_encode({'keys': [self.good, other]}),
            budget=jwk.JWKSetBudget(max_duplicate_kid=1))
        with self.assertRaises(jwk.AmbiguousKeySelection):
            self._jws().verify(keyset)

    def test_quarantined_kid_raises_unavailable_on_jws_verify(self):
        bad = {'kty': 'RSA', 'kid': 'sig',
               'n': 'ab!cd', 'e': 'AQAB'}
        keyset = jwk.JWKSet.from_json(json_encode({'keys': [bad]}))
        self.assertTrue(keyset.has_quarantine())
        with self.assertRaises(jwk.QuarantinedKeyNotAvailable):
            self._jws().verify(keyset)

    def test_unknown_kid_raises_key_not_found(self):
        keyset = jwk.JWKSet()
        with self.assertRaises(Exception):
            self._jws().verify(keyset)

    def test_jwt_surfaces_ambiguity_and_unavailable(self):
        builder = jwt.JWT(header={'alg': 'HS256',
                                  'kid': 'sig'},
                          claims={'a': 1}, check_claims=False)
        builder.make_signed_token(self.key)
        serialized = builder.serialize(compact=True)

        other = json.loads(make_oct('sig').export())
        ambiguous = jwk.JWKSet.from_json(
            json_encode({'keys': [self.good, other]}),
            budget=jwk.JWKSetBudget(max_duplicate_kid=1))
        with self.assertRaises(jwk.AmbiguousKeySelection):
            jwt.JWT(check_claims=False).deserialize(serialized, ambiguous)

        bad = {'kty': 'RSA', 'kid': 'sig',
               'n': 'ab!cd', 'e': 'AQAB'}
        unavailable = jwk.JWKSet.from_json(
            json_encode({'keys': [bad]}))
        with self.assertRaises(jwt.JWTMissingKey):
            jwt.JWT(check_claims=False).deserialize(
                serialized, unavailable)

        healthy = jwk.JWKSet.from_json(
            json_encode({'keys': [self.good]}))
        verified = jwt.JWT(check_claims=False)
        verified.deserialize(serialized, healthy)
        self.assertEqual({'a': 1}, json.loads(verified.claims))

class JWKSetMemoryBoundTests(unittest.TestCase):

    def test_oversized_keyset_has_bounded_peak_memory(self):
        # 50,000 keys emulate the denial-of-service sample. The raw
        # document stays under the raw cap, but key/byte/quarantine
        # budgets must keep retained work tightly bounded.
        entries = [{
            'kty': 'oct',
            'kid': 'k' + str(index),
            'k': 'AAAA',
        } for index in range(50000)]
        raw = json_encode({'keys': entries})
        budget = jwk.JWKSetBudget(
            max_raw_size=10 * 1024 * 1024,
            max_keys=20,
            max_total_decoded_bytes=64,
            max_quarantine=100)
        tracemalloc.start()
        try:
            result = jwk.JWKSet.from_json(raw, budget=budget)
            current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        self.assertEqual(20, len(result['keys']))
        self.assertEqual(100, len(result.quarantine))
        self.assertEqual(49880, result.quarantine_suppressed_count)
        self.assertLessEqual(result.total_decoded_bytes, 64)
        # Concrete ceiling: even for a 50k-entry document the whole
        # import stays well under 32 MiB because no crypto objects are
        # built for rejected entries and retained records are capped.
        self.assertLess(peak, 32 * 1024 * 1024)
        # The retained data is bounded by the budget, not by the 50k
        # requested keys: assert the post-import live allocation is a
        # small fraction of what accepting every key would require.
        self.assertLess(current, len(raw))
        self.assertIsNotNone(result.get_key('k0'))

    def test_long_members_are_rejected_without_crypto_objects(self):
        entries = [{
            'kty': 'RSA',
            'kid': 'k' + str(index),
            'n': 'A' * 200000,
            'e': 'AQAB',
        } for index in range(300)]
        raw = json_encode({'keys': entries})
        self.assertGreater(len(raw), 8 * 1024 * 1024)
        with self.assertRaises(jwk.JWKSetBudgetExceeded):
            jwk.JWKSet.from_json(raw)

        budget = jwk.JWKSetBudget(
            max_raw_size=100 * 1024 * 1024,
            max_member_encoded_length=16384,
            max_quarantine=500)
        result = jwk.JWKSet.from_json(raw, budget=budget)
        self.assertEqual(0, len(result['keys']))
        self.assertEqual(300, len(result.quarantine))
        self.assertTrue(all(
            record.reason == 'member_too_long'
            for record in result.quarantine))


if __name__ == '__main__':
    unittest.main()

