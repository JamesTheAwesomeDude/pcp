from asn1crypto.algos import EncryptionAlgorithm, EncryptionAlgorithmId
from asn1crypto.cms import KeyTransRecipientInfo
from asn1crypto.core import Integer

from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.aead import AESSIV
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC, GCM

from pqc.kem import mceliece6960119

from hashlib import shake_256
from os import urandom

from ._util import make_skid, RecipientKemAlgorithm


def kem_wrap(pk, cek):
    # https://datatracker.ietf.org/doc/html/draft-perret-prat-lamps-cms-pq-kem-01#name-senders-operations

    # 1. Generate SS
    kem_ss, kem_ct_internal = mceliece6960119.kem_enc(pk)
    skid = make_skid(pk)
    kem_alg_internal = {
        'algorithm': 'classic_mceliece',
        'parameters': {'standard_set': 'mceliece6960119'},
    }

    # 2. Derive KEK
    kdf_alg_internal, kek = kdf(kem_ss, 2*len(cek))

    # 3. Wrap CEK
    kw_alg_internal, kw_ct = _siv_encrypt(kek, cek)

    # 4. Concat CTs
    kem_ct = kw_ct + kem_ct_internal
    kea = RecipientKemAlgorithm({
        'algorithm': 'kem_trans',
        'parameters': {
            'kem': kem_alg_internal,
            'kdf': kdf_alg_internal,
            'wrap': kw_alg_internal,
        },
    })

    # 5. Output
    return KeyTransRecipientInfo({
        'version': 'v2',
        'rid': {'subject_key_identifier': skid},
        'key_encryption_algorithm': kea,
        'encrypted_key': kem_ct,
    })


def aencrypt(key, data, aad=None, tag_length=16):
    if aad is None:
        aad = b''
    nonce_len = 12

    nonce = urandom(nonce_len)
    cea = {
        'algorithm': f'aes{len(key)*8}_gcm',
        'parameters': {
            'aes_nonce': nonce,
            'aes_icvlen': tag_length,
        },
    }

    # TODO factor this out properly for len(file) > len(RAM) situations
    cipher = Cipher(AES(key), GCM(nonce)).encryptor()
    cipher.authenticate_additional_data(aad)
    ciphertext = cipher.update(data)
    cipher.finalize()

    return cea, ciphertext, cipher.tag


def decrypt(*a):
    raise NotImplementedError()


def kdf(seed, keyLen):
    key = shake_256(seed).digest(keyLen)
    kdf_alg = {
        'algorithm': '2.16.840.1.101.3.4.2.18',
        'parameters': Integer(keyLen),  # TODO
    }
    return kdf_alg, key


def _siv_encrypt(kek, k, aad=None):
    if aad is None:
        aad=b''
    wk = AESSIV(kek).encrypt(k, [aad])
    oid = f'1.2.840.113549.1.9.16.3.{ {32: 25}[len(k)] }'
    kw_alg = {
        'algorithm': oid,
    }

    return kw_alg, wk

