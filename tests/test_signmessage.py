from binascii import hexlify, unhexlify

import cbor2
import pytest

from pycose.keys import EC2Key
from pycose.headers import Algorithm, KID
from pycose.messages.signmessage import SignMessage
from pycose.messages.signer import CoseSignature
from pycose.exceptions import CoseException
from tests.conftest import _setup_signers


def test_sign_encoding(test_sign):
    test_input = test_sign['input']
    test_output = test_sign['output']

    signers = _setup_signers(test_input['signers'])

    msg = SignMessage(
        phdr=test_input['protected'],
        uhdr=test_input['unprotected'],
        payload=test_input['plaintext'],
        signers=signers)

    assert msg.phdr == test_input['protected']
    assert msg.uhdr == test_input['unprotected']

    for s, s_output in zip(msg.signers, test_output['signers']):
        assert hexlify(s._create_sig_structure()) == hexlify(s_output['structure'])
        if 'signature' in s_output:
            assert s.compute_signature() == s_output['signature']

    # remove signature for probabilistic behavior
    do_tag = test_sign['cbor_tag']
    msg_dec = cbor2.loads(msg.encode(tag=do_tag))
    test_dec = test_output['result']
    if 'signature' not in s_output:
        msg = msg_dec.value if do_tag else msg_dec
        for signer in msg[3]:
            signer[2] = b''

        msg = test_dec.value if do_tag else test_dec
        for signer in msg[3]:
            signer[2] = b''
    assert msg_dec == test_dec


def test_sign_decoding(test_sign):
    if not test_sign['cbor_tag']:
        pytest.skip("Missing CBOR tag")

    test_input = test_sign['input']
    test_output = test_sign['output']

    msg = SignMessage.decode(cbor2.dumps(test_output['result']))

    for s, s_input, s_output in zip(msg.signers, test_input['signers'], test_output['signers']):
        s.external_aad = unhexlify(s_input['external_aad'])
        s.key = s_input['signing_key']
        assert hexlify(s._create_sig_structure()) == hexlify(s_output['structure'])
        assert s.verify_signature()


def test_verified_snapshot_isolates_consumers():
    key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})
    encoded_receipts = []

    for receipt_id, payload in [
        (b'receipt-1', b'first receipt'),
        (b'receipt-2', b'second receipt'),
    ]:
        signer = CoseSignature(
            phdr={Algorithm: key.alg},
            uhdr={KID: receipt_id},
            key=key)
        receipt = SignMessage(uhdr={KID: receipt_id}, payload=payload, signers=[signer])
        encoded_receipts.append(receipt.encode())

    business_results = []

    for encoded_receipt in encoded_receipts:
        receipt = SignMessage.decode(encoded_receipt)
        signer = receipt.signers[0]
        signer.key = key

        assert receipt.verified_snapshot is None
        assert signer.verify_signature(capture_snapshot=True)

        snapshot = receipt.verified_snapshot
        original_kid = snapshot.uhdr[KID]
        original_signature = snapshot.signers[0].signature

        receipt.uhdr[KID] = b'display receipt kid'
        receipt.payload = b'display payload'
        signer.uhdr[KID] = b'display signer kid'
        signer.signature = b'display signature'

        assert snapshot is not receipt
        assert snapshot.uhdr == {KID: original_kid}
        assert snapshot.payload == snapshot.signers[0]._parent.payload
        assert snapshot.signers[0].uhdr == {KID: original_kid}
        assert snapshot.signers[0].signature == original_signature
        assert snapshot.signers[0]._parent is snapshot

        business_results.append({
            'kid': snapshot.uhdr[KID],
            'payload': snapshot.payload,
        })

    assert business_results == [
        {'kid': b'receipt-1', 'payload': b'first receipt'},
        {'kid': b'receipt-2', 'payload': b'second receipt'},
    ]


def test_detached_payload():
    ec2_key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})

    payload = "signed message".encode('utf-8')

    signer = CoseSignature(phdr={'ALG': 'ES256'})
    signer.key = ec2_key

    msg = SignMessage(phdr={}, signers=[signer])

    encoded = msg.encode(detached_payload=payload)

    msg = SignMessage.decode(encoded)
    
    assert msg.payload is None
    
    signer = msg.signers[0]
    signer.key = ec2_key

    assert signer.verify_signature(detached_payload=payload)


def test_fail_on_missing_payload_signing():
    ec2_key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})

    signer = CoseSignature(phdr={'ALG': 'ES256'})
    signer.key = ec2_key

    msg = SignMessage(phdr={}, signers=[signer])

    with pytest.raises(CoseException, match="Missing payload"):
        msg.encode()


def test_fail_on_missing_payload_verification():
    ec2_key = EC2Key.generate_key(crv='P_256', optional_params={'ALG': 'ES256'})

    payload = "signed message".encode('utf-8')

    signer = CoseSignature(phdr={'ALG': 'ES256'})
    signer.key = ec2_key

    msg = SignMessage(phdr={}, signers=[signer])

    encoded = msg.encode(detached_payload=payload)

    msg = SignMessage.decode(encoded)

    signer = msg.signers[0]
    signer.key = ec2_key

    with pytest.raises(CoseException, match="Missing payload"):
        signer.verify_signature()
