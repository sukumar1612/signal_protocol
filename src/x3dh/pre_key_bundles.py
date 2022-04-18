from __future__ import annotations

import pickle
from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from exceptions.keys_exception import (
    OneTimeKeysListEmpty,
    KeysNotFound,
    FileLocationNotValid,
)
from src.EdDSA.sign_and_verify_functions import sign_public_key, verify_public_key
from src.x3dh.interface import PublicKey, PrivateKey, ImportExportMode


class PreKeyBundlePublic(PublicKey):
    """enter keys in RAW bytes format"""

    def __init__(
        self,
        ik_public: bytes,
        spk_public: bytes,
        signature: bytes,
        op_key_public: bytes,
        verify_signature_public_key: bytes,
    ):
        self.ik_public = X25519PublicKey.from_public_bytes(ik_public)
        self.spk_public = X25519PublicKey.from_public_bytes(spk_public)
        self.signature = signature
        self.op_key_public = X25519PublicKey.from_public_bytes(op_key_public)
        self.verify_signature_public_key = verify_signature_public_key

    def export_keys(self) -> dict:
        return {
            "ik_public": self.ik_public.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
            "spk_public": self.spk_public.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
            "signature": self.signature,
            "op_key_public": self.op_key_public.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
            "verify_signature_public_key": self.verify_signature_public_key,
        }

    def verify_signature(self) -> bool:
        return verify_public_key(
            verify_signature_public_key=self.verify_signature_public_key,
            signed_public_key=self.signature,
        )


class PreKeyBundlePrivate(PrivateKey):
    """In the example given in the signal documentation, this would be the bob side of things"""

    def __init__(
        self,
        ik_private: X25519PrivateKey,
        ik_public: X25519PublicKey,
        spk_private: X25519PrivateKey,
        spk_public: X25519PublicKey,
        op_key_private: list,
    ):
        self.ik_private = ik_private
        self.ik_public = ik_public
        self.spk_private = spk_private
        self.spk_public = spk_public
        self.signature, self.verify_signature_public_key = sign_public_key(
            seed=ik_private.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            ),
            public_key=self.spk_public.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
        )
        self.op_key_private = op_key_private

    def publish_keys(self) -> PreKeyBundlePublic:
        one_time_key: X25519PrivateKey = None
        try:
            one_time_key = self.op_key_private[0]
        except IndexError:
            raise OneTimeKeysListEmpty

        keys = {
            "ik_public": self.ik_public.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
            "spk_public": self.spk_public.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
            "signature": self.signature,
            "op_key_public": one_time_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
            "verify_signature_public_key": self.verify_signature_public_key,
        }
        return PreKeyBundlePublic(**keys)

    def dump_keys(
        self, mode: ImportExportMode, location: Optional[str] = None
    ) -> Optional[dict]:
        keys = {
            "ik_private": self.ik_private.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            ),
            "ik_public": self.ik_public.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
            "spk_private": self.spk_private.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            ),
            "spk_public": self.spk_public.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
            "op_key_private": [
                key.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                )
                for key in self.op_key_private
            ],
        }
        if mode == ImportExportMode.file:
            with open(location, "wb") as pre_keys:
                pickle.dump(keys, pre_keys)
            return

        return keys

    @staticmethod
    def load_data(
        mode: ImportExportMode,
        location: Optional[str] = None,
        keys_dictionary: dict = None,
    ) -> PreKeyBundlePrivate:
        keys_dict: dict = keys_dictionary
        if mode == ImportExportMode.file:
            try:
                with open(location, "rb") as pre_keys:
                    keys_dict = pickle.load(pre_keys)
            except IOError:
                raise FileLocationNotValid

        key_list = [
            "ik_private",
            "ik_public",
            "spk_private",
            "spk_public",
            "op_key_private",
        ]
        if keys_dict is None or set(keys_dict.keys()) != set(key_list):
            raise KeysNotFound
        else:
            keys_dict["ik_private"] = X25519PrivateKey.from_private_bytes(
                keys_dict["ik_private"]
            )
            keys_dict["ik_public"] = X25519PublicKey.from_public_bytes(
                keys_dict["ik_public"]
            )
            keys_dict["spk_private"] = X25519PrivateKey.from_private_bytes(
                keys_dict["spk_private"]
            )
            keys_dict["spk_public"] = X25519PublicKey.from_public_bytes(
                keys_dict["spk_public"]
            )
            keys_dict["op_key_private"] = [
                X25519PrivateKey.from_private_bytes(key)
                for key in keys_dict["op_key_private"]
            ]

        return PreKeyBundlePrivate(**keys_dict)


def generate_keys():
    key_private = X25519PrivateKey.generate()
    return key_private, key_private.public_key()
