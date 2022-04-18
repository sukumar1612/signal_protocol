from __future__ import annotations

import pickle
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from exceptions.keys_exception import OneTimeKeysListEmpty, KeysNotFound, FileLocationNotValid
from src.EdDSA.signature import sign_public_key, verify_public_key
from src.x3dh.abstract_class import PublicKey, PrivateKey, ImportExportMode


class PreKeyBundlePublic(PublicKey):
    """ enter keys in RAW bytes format"""

    def __init__(self, IK_public: bytes, SPK_public: bytes, signature: bytes, OP_key_public: bytes,
                 verify_signature_public_key: bytes):
        self.IK_public = X25519PublicKey.from_public_bytes(IK_public)
        self.SPK_public = X25519PublicKey.from_public_bytes(SPK_public)
        self.signature = signature
        self.OP_key_public = X25519PublicKey.from_public_bytes(OP_key_public)
        self.verify_signature_public_key = verify_signature_public_key

    def export_keys(self) -> dict:
        return {
            'IK_public': self.IK_public.public_bytes(serialization.Encoding.Raw,
                                                     serialization.PublicFormat.Raw),
            'SPK_public': self.SPK_public.public_bytes(serialization.Encoding.Raw,
                                                       serialization.PublicFormat.Raw),
            'signature': self.signature,
            'one_time_key': self.OP_key_public.public_bytes(serialization.Encoding.Raw,
                                                            serialization.PublicFormat.Raw),
            'verify_signature_public_key': self.verify_signature_public_key,
        }

    def verify_signature(self) -> bool:
        return verify_public_key(verify_signature_public_key=self.verify_signature_public_key,
                                 signed_public_key=self.signature)


class PreKeyBundlePrivate(PrivateKey):
    """In the example given in the signal documentation, this would be the bob side of things"""

    def __init__(self, IK_private: X25519PrivateKey, IK_public: X25519PublicKey, SPK_private: X25519PrivateKey,
                 SPK_public: X25519PublicKey, OP_key_private: list):
        self.IK_private = IK_private
        self.IK_public = IK_public
        self.SPK_private = SPK_private
        self.SPK_public = SPK_public
        self.signature, self.verify_signature_public_key = sign_public_key(
            seed=IK_private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                          serialization.NoEncryption()),
            public_key=self.SPK_public.public_bytes(serialization.Encoding.Raw,
                                                    serialization.PublicFormat.Raw))
        self.OP_key_private = OP_key_private

    def publish_keys(self) -> PreKeyBundlePublic:
        one_time_key: X25519PrivateKey = None
        try:
            one_time_key = self.OP_key_private[0]
        except IndexError:
            raise OneTimeKeysListEmpty

        keys = {
            'IK_public': self.IK_public.public_bytes(serialization.Encoding.Raw,
                                                     serialization.PublicFormat.Raw),
            'SPK_public': self.SPK_public.public_bytes(serialization.Encoding.Raw,
                                                       serialization.PublicFormat.Raw),
            'signature': self.signature,
            'OP_key_public': one_time_key.public_key().public_bytes(serialization.Encoding.Raw,
                                                                    serialization.PublicFormat.Raw),
            'verify_signature_public_key': self.verify_signature_public_key
        }
        return PreKeyBundlePublic(**keys)

    def dump_keys(self, mode: ImportExportMode, location: Optional[str] = None) -> Optional[dict]:
        keys = {
            'IK_private': self.IK_private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                                        serialization.NoEncryption()),
            'IK_public': self.IK_public.public_bytes(serialization.Encoding.Raw,
                                                     serialization.PublicFormat.Raw),
            'SPK_private': self.SPK_private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                                          serialization.NoEncryption()),
            'SPK_public': self.SPK_public.public_bytes(serialization.Encoding.Raw,
                                                       serialization.PublicFormat.Raw),
            'OP_key_private': [key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                                 serialization.NoEncryption()) for key in self.OP_key_private]
        }
        if mode == ImportExportMode.file:
            with open(location, 'wb') as pre_keys:
                pickle.dump(keys, pre_keys)
            return

        return keys

    @staticmethod
    def load_data(mode: ImportExportMode, location: Optional[str] = None,
                  keys_dictionary: dict = None) -> PreKeyBundlePrivate:
        keys_dict: dict = keys_dictionary
        if mode == ImportExportMode.file:
            try:
                with open(location, 'rb') as pre_keys:
                    keys_dict = pickle.load(pre_keys)
            except IOError:
                raise FileLocationNotValid

        key_list = ['IK_private', 'IK_public', 'SPK_private', 'SPK_public', 'OP_key_private']
        if keys_dict is None or set(keys_dict.keys()) != set(key_list):
            raise KeysNotFound
        else:
            keys_dict['IK_private'] = X25519PrivateKey.from_private_bytes(keys_dict['IK_private'])
            keys_dict['IK_public'] = X25519PublicKey.from_public_bytes(keys_dict['IK_public'])
            keys_dict['SPK_private'] = X25519PrivateKey.from_private_bytes(keys_dict['SPK_private'])
            keys_dict['SPK_public'] = X25519PublicKey.from_public_bytes(keys_dict['SPK_public'])
            keys_dict['OP_key_private'] = [X25519PrivateKey.from_private_bytes(key) for key in
                                           keys_dict['OP_key_private']]

        return PreKeyBundlePrivate(**keys_dict)


def generate_keys():
    key_private = X25519PrivateKey.generate()
    return key_private, key_private.public_key()
