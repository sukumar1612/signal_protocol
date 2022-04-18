import warnings
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from src.x3dh.abstract_class import ImportExportMode
from src.x3dh.ephemeral_key_bundles import EphemeralKeyBundlePrivate
from src.x3dh.pre_key_bundles import generate_keys, PreKeyBundlePrivate


class CreateKeys:
    @staticmethod
    def create_new_pre_key_bundle(number_of_onetime_pre_keys: int):
        OP_key_private = [X25519PrivateKey.generate() for count in range(number_of_onetime_pre_keys)]
        IK_keys = generate_keys()
        SPK_keys = generate_keys()
        pre_key_bundle_private = PreKeyBundlePrivate(IK_public=IK_keys[1], IK_private=IK_keys[0],
                                                     SPK_private=SPK_keys[0],
                                                     SPK_public=SPK_keys[1], OP_key_private=OP_key_private)
        return pre_key_bundle_private

    @staticmethod
    def create_new_ephemeral_key_bundle() -> EphemeralKeyBundlePrivate:
        warnings.warn("This function is only used to test the system, do not use in production")
        IK_keys = generate_keys()
        epk_keys = generate_keys()
        return EphemeralKeyBundlePrivate(IK_public=IK_keys[1], IK_private=IK_keys[0], ephemeral_key_private=epk_keys[0],
                                         ephemeral_key_public=epk_keys[1])

    @staticmethod
    def load_ephemeral_key_bundle_from_pre_key_bundle(mode: ImportExportMode, location: Optional[str] = None,
                                                      keys_dictionary: dict = None) -> EphemeralKeyBundlePrivate:
        return EphemeralKeyBundlePrivate.load_data(mode=mode, location=location, keys_dictionary=keys_dictionary)

    @staticmethod
    def load_pre_key_bundle(mode: ImportExportMode, location: Optional[str] = None,
                            keys_dictionary: dict = None):
        return PreKeyBundlePrivate.load_data(mode=mode, location=location, keys_dictionary=keys_dictionary)


def add_new_onetime_keys(keys: PreKeyBundlePrivate, number_of_onetime_pre_keys: int):
    for count in range(number_of_onetime_pre_keys):
        keys.OP_key_private.append(X25519PrivateKey.generate())
