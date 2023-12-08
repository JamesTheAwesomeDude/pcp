from asn1crypto.core import Integer, OctetBitString, OctetString, Sequence
from asn1crypto.keys import Attributes, PrivateKeyAlgorithm


class Pkcs8Version(Integer):
    # https://datatracker.ietf.org/doc/html/rfc5958
    _map = {
        0: 'v1',
        1: 'v2',
    }


class OneAsymmetricKey(Sequence):
    # https://datatracker.ietf.org/doc/html/rfc5958
    _fields = [
        ('version', Pkcs8Version),
        ('private_key_algorithm', PrivateKeyAlgorithm),
        ('private_key', OctetString),
        ('attributes', Attributes, {'implicit': 0, 'optional': True}),
        ('public_key', OctetBitString, {'implicit': 1, 'optional': True}),  # TODO make this not opaque
    ]
