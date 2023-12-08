from asn1crypto.algos import AlgorithmIdentifier, EncryptionAlgorithm, SignedDigestAlgorithm
from asn1crypto.cms import KeyEncryptionAlgorithm
from asn1crypto.core import ObjectIdentifier
from asn1crypto.keys import PrivateKeyAlgorithm

from abc import ABC
from hashlib import sha1


# TODO check if this should be done differently or what
# May https://www.hyrumslaw.com/ forgive me for this

class _Abstract_AlgorithmIdentifier(ABC):
    pass

_Abstract_AlgorithmIdentifier.register(AlgorithmIdentifier)
_Abstract_AlgorithmIdentifier.register(EncryptionAlgorithm)
_Abstract_AlgorithmIdentifier.register(PrivateKeyAlgorithm)


def _asn1crypto_register(asn1crypto_cls):
    def wrap(custom_cls):
        if issubclass(asn1crypto_cls, ObjectIdentifier):
            asn1crypto_cls._map.update(custom_cls._map)
            if hasattr(asn1crypto_cls, '_reverse_map') and asn1crypto_cls._reverse_map:
                asn1crypto_cls._reverse_map.update(((v, k) for k, v in custom_cls._map.items()))
            return custom_cls
        elif issubclass(asn1crypto_cls, _Abstract_AlgorithmIdentifier):
            asn1crypto_cls._oid_specs.update(custom_cls._oid_specs)
            return custom_cls
        elif issubclass(asn1crypto_cls, (KeyEncryptionAlgorithm, SignedDigestAlgorithm)):
            # I hate this
            return type(
                custom_cls.__name__,
                custom_cls.__bases__ + (asn1crypto_cls,),
                custom_cls.__dict__.copy()
            )
        raise NotImplementedError(asn1crypto_cls)
    return wrap


def _asn1crypto_register_params(asn1crypto_cls, name):
    def wrap(custom_cls):
        asn1crypto_cls._oid_specs.update({name: custom_cls})
        return custom_cls
    return wrap


def make_skid(pk):
    h = sha1(pk).digest()
    h0 = (0x40 | (0x0F & h[-8]))
    return bytes([h0]) + h[-7:]


def b2_kdf(digest, id_, salt, password, r, n=None):
    """
    Source: https://datatracker.ietf.org/doc/html/rfc7292#appendix-B.2
    """
    password = _b1_encode(password)
    h = getattr(hashlib, digest)
    u = h().digest_size
    if n is None:
        n = u
    v = h().block_size
    D = _tile_finite(bytes([id_]), v)
    S = _tile_finite(salt, v*ceil_div(len(salt), v))
    P = _tile_finite(password, v*ceil_div(len(password), v))
    I = S + P
    c = ceil_div(n, u)
    A_ = []

    for i in range(c):
        Ai = D + I
        for j in range(r):
            Ai = h(Ai).digest()
        A_.append(Ai)
        B = int.from_bytes(_tile_finite(Ai, v), 'big')
        I = b''.join(
            int.to_bytes(
                ((int.from_bytes(I[k:k+v], 'big') + B + 1) % (8**v))
            , v, 'big')
            for k in range(0, len(I), v)
        )

    return bytes(islice(chain.from_iterable(A_), n))


def b1_encode(s):
    """
    Source: https://datatracker.ietf.org/doc/html/rfc7292#appendix-B.1
    """
    return (s + '\u0000').encode('utf-16-be')


def _tile_finite(b, n):
    return bytes(islice(cycle(b), n))


def ceil_div(a, b):
    return -(-a//b)
