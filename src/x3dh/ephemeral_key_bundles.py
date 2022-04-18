from __future__ import annotations

from typing import Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from src.x3dh.interface import PublicKey, PrivateKey, ImportExportMode
from src.x3dh.pre_key_bundles import PreKeyBundlePrivate


class EphemeralKeyBundlePublic(PublicKey):
    """enter keys in RAW bytes format"""

    def __init__(self, ik_public: bytes, ephemeral_key_public: bytes):
        self.ik_public = X25519PublicKey.from_public_bytes(ik_public)
        self.ephemeral_key_public = X25519PublicKey.from_public_bytes(
            ephemeral_key_public
        )

    def export_keys(self) -> dict:
        return {
            "ik_public": self.ik_public.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
            "ephemeral_key_public": self.ephemeral_key_public.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
        }


class EphemeralKeyBundlePrivate(PrivateKey):
    """In the example given in the signal documentation, this would be the alice side of things
    to use this class, load the pre key bundle stored in the system to and then use. Not advisable to
    to use the create ephemeral function in factory method as a new identity key is generated.
    the function create_new_ephemeral_key_bundle is only used to tests the system"""

    def __init__(
        self,
        ik_public: X25519PublicKey,
        ik_private: X25519PrivateKey,
        ephemeral_key_public: X25519PublicKey,
        ephemeral_key_private: X25519PrivateKey,
    ):
        self.ik_private = ik_private
        self.ik_public = ik_public
        self.ephemeral_key_private = ephemeral_key_private
        self.ephemeral_key_public = ephemeral_key_public

    def publish_keys(self) -> EphemeralKeyBundlePublic:
        keys = {
            "ik_public": self.ik_public.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
            "ephemeral_key_public": self.ephemeral_key_public.public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            ),
        }
        return EphemeralKeyBundlePublic(**keys)

    @staticmethod
    def load_data(
        mode: ImportExportMode,
        location: Optional[str] = None,
        keys_dictionary: dict = None,
    ) -> EphemeralKeyBundlePrivate:
        pre_key_bundle_private = PreKeyBundlePrivate.load_data(
            mode=mode, location=location, keys_dictionary=keys_dictionary
        )
        onetime_key = pre_key_bundle_private.op_key_private[0]
        pre_key_bundle_private.op_key_private.pop(0)

        if mode == ImportExportMode.file:
            pre_key_bundle_private.dump_keys(mode=mode, location=location)
        return EphemeralKeyBundlePrivate(
            ik_private=pre_key_bundle_private.ik_private,
            ik_public=pre_key_bundle_private.ik_public,
            ephemeral_key_private=onetime_key,
            ephemeral_key_public=onetime_key.public_key(),
        )
