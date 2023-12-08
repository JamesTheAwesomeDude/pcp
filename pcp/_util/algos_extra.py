from asn1crypto.core import Integer, ObjectIdentifier, OctetString, Sequence, Void
from asn1crypto.algos import EncryptionAlgorithm, SignedDigestAlgorithm, SignedDigestAlgorithmId

from ._misc import _asn1crypto_register, _asn1crypto_register_params


@_asn1crypto_register_params(EncryptionAlgorithm, 'aes256_gcm')
class GcmParams(Sequence):
    _fields = [
        ('aes_nonce', OctetString),
        ('aes_icvlen', Integer, {'default': 12}),
    ]



@_asn1crypto_register(SignedDigestAlgorithmId)
class NoSignatureId(ObjectIdentifier):
    _map = {
        '1.0.20248.1.1': 'null_none',
    }

_asn1crypto_register_params(SignedDigestAlgorithm, 'null_none')(Void)
