
from asn1crypto.cms import AuthEnvelopedData, ContentInfo
from asn1crypto import core, keys, pem, pkcs12

import argparse
from os import urandom
from pathlib import Path
from tkinter import simpledialog

from ._util import OneAsymmetricKey
from ._crypto import aencrypt, kem_wrap

parser = argparse.ArgumentParser(prog='pcp')
result = parser.parse_args()
print("Le Arg Parse:", result)


def demo_encrypt(pk, message, aad=None, eci_type='data'):

    # 1. Encrypt content
    cek = urandom(32)
    cea, ct, icv = aencrypt(cek, message, aad=aad)

    # 2. Encrypt cek with KEM
    recipient1 = kem_wrap(pk, cek)

    # 3. Envelope it all up
    env = AuthEnvelopedData({
        'version': 'v0',
        'recipient_infos': [
            recipient1,
        ],
        'auth_encrypted_content_info': {
            'content_type': eci_type,
            'content_encryption_algorithm': cea,
            'encrypted_content': ct,
        },
        'mac': icv,
    })

    return env.dump()


def demo_keywrap(sk, pk):
    from asn1crypto.pkcs12 import Pfx

    pfx = Pfx({
        'version': 'v3',
        'auth_safe': {
            'content_type': 'data',
            'content': ...,
        },
    })


from time import perf_counter
print(perf_counter(), 'Moving key into RAM...')
oak = oak_text = Path('privatekey.p8.txt').read_bytes()
print(perf_counter(), 'Done.')
print(perf_counter(), 'Unarmoring key...')
oak = pem.unarmor(oak)[2]
print(perf_counter(), 'Done.')
print(perf_counter(), 'Loading key...')
oak = OneAsymmetricKey.load(oak)
print(perf_counter(), 'Done.')
sk = oak['private_key'].native
pk = oak['public_key'].native
m = b"lol123"
m = simpledialog.askstring("Sample Text", "Enter the message:").encode('utf-8')
payload = demo_encrypt(pk, m)
print(pem.armor('CMS', payload).decode('ascii'))
