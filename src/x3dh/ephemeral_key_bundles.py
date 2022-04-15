from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from src.x3dh.abstract_class import PublicKey, PrivateKey
from src.x3dh.pre_key_bundles import PreKeyBundlePrivate, generate_keys


class EphemeralKeyBundlePublic(PublicKey):
    """ enter keys in RAW bytes format"""

    def __init__(self, IK_public: bytes, ephemeral_key_public: bytes):
        self.IK_public = X25519PublicKey.from_public_bytes(IK_public)
        self.ephemeral_key_public = X25519PublicKey.from_public_bytes(ephemeral_key_public)

    def export_keys(self) -> dict:
        return {
            'IK_public': self.IK_public.public_bytes(serialization.Encoding.Raw,
                                                     serialization.PublicFormat.Raw),
            'ephemeral_key_public': self.ephemeral_key_public.public_bytes(serialization.Encoding.Raw,
                                                                           serialization.PublicFormat.Raw)
        }


class EphemeralKeyBundlePrivate(PrivateKey):
    """In the example given in the signal documentation, this would be the alice side of things"""

    def __init__(self, IK_public: X25519PublicKey, IK_private: X25519PrivateKey,
                 ephemeral_key_public: X25519PublicKey, ephemeral_key_private: X25519PrivateKey):
        self.IK_private = IK_private
        self.IK_public = IK_public
        self.ephemeral_key_private = ephemeral_key_private
        self.ephemeral_key_public = ephemeral_key_public

    def publish_keys(self) -> EphemeralKeyBundlePublic:
        keys = {
            'IK_public': self.IK_public.public_bytes(serialization.Encoding.Raw,
                                                     serialization.PublicFormat.Raw),
            'ephemeral_key_public': self.ephemeral_key_public.public_bytes(serialization.Encoding.Raw,
                                                                           serialization.PublicFormat.Raw)
        }
        return EphemeralKeyBundlePublic(**keys)

    @staticmethod
    def load_data(location: str) -> EphemeralKeyBundlePrivate:
        pre_key_bundle_private = PreKeyBundlePrivate.load_data(location=location)
        onetime_key = pre_key_bundle_private.OP_key_private[0]
        pre_key_bundle_private.OP_key_private.pop(0)

        pre_key_bundle_private.dump_keys(location)
        return EphemeralKeyBundlePrivate(IK_private=pre_key_bundle_private.IK_private,
                                         IK_public=pre_key_bundle_private.IK_public, ephemeral_key_private=onetime_key,
                                         ephemeral_key_public=onetime_key.public_key())


def create_new_ephemeral_key_bundle() -> EphemeralKeyBundlePrivate:
    IK_keys = generate_keys()
    epk_keys = generate_keys()
    return EphemeralKeyBundlePrivate(IK_public=IK_keys[1], IK_private=IK_keys[0], ephemeral_key_private=epk_keys[0],
                                     ephemeral_key_public=epk_keys[1])
