from asn1crypto.cms import KdfAlgorithm, KeyEncryptionAlgorithm
from asn1crypto.core import Any, Choice, Integer, ObjectIdentifier, Sequence
from asn1crypto.algos import AlgorithmIdentifier, EncryptionAlgorithm, EncryptionAlgorithmId
from asn1crypto.keys import PrivateKeyAlgorithm, PrivateKeyAlgorithmId

from ._misc import _asn1crypto_register, _asn1crypto_register_params


@_asn1crypto_register(EncryptionAlgorithmId)
class RecipientKemAlgorithmId(ObjectIdentifier):
    _map = {
        '1.3.6.1.4.1.61241.1.2315.0.1': 'kem_trans',  # { ... algorithm-identifiers(1) CMSRelated(2315) Meta(0) id-kem-trans(1) }
    }


@_asn1crypto_register(EncryptionAlgorithmId)
@_asn1crypto_register(PrivateKeyAlgorithmId)
class KemAlgorithmId(ObjectIdentifier):
    _map = {
        '1.3.6.1.4.1.61241.1.2315.1.1': 'classic_mceliece',  # { ... algorithm-identifiers(1) CMSRelated(2315) KEMs(1) id-ClassicMcEliece(1) }
    }


class McElieceStandardParameterSet(Integer):
    _map = {
        1: 'mceliece348864',
        2: 'mceliece460896',
        3: 'mceliece6688128',
        4: 'mceliece6960119',
        5: 'mceliece8192128',
    }


@_asn1crypto_register_params(EncryptionAlgorithm, 'classic_mceliece')
class McElieceParams(Choice):
    _alternatives = [
        ('standard_set', McElieceStandardParameterSet),
        ('custom_set', Sequence),  # import FootGun.asn1
    ]


@_asn1crypto_register(EncryptionAlgorithm)
@_asn1crypto_register(PrivateKeyAlgorithm)
@_asn1crypto_register(KeyEncryptionAlgorithm)
class KemAlgorithm(AlgorithmIdentifier):
    _fields = [
        ('algorithm', KemAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]

    _oid_pair = ('algorithm', 'parameters')
    _oid_specs = {
        'classic_mceliece': McElieceParams,
    }


@_asn1crypto_register_params(EncryptionAlgorithm, 'kem_trans')
class GenericHybridParameters(Sequence):
    _fields = [
        ('kem', KemAlgorithm),
        ('kdf', KdfAlgorithm),
        ('wrap', EncryptionAlgorithm),
    ]


@_asn1crypto_register(EncryptionAlgorithm)
@_asn1crypto_register(KeyEncryptionAlgorithm)
class RecipientKemAlgorithm(AlgorithmIdentifier):
    _fields = [
        ('algorithm', RecipientKemAlgorithmId),
        ('parameters', Any, {'optional': True}),
    ]

    _oid_pair = ('algorithm', 'parameters')
    _oid_specs = {
        'kem_trans': GenericHybridParameters,
    }
