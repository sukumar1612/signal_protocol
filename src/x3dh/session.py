from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.x3dh.key_bundles import PreKeyBundlePrivate, PreKeyBundlePublic, EphemeralKeyBundlePrivate, \
    create_new_pre_key_bundle, EphemeralKeyBundlePublic, create_new_ephemeral_key_bundle


def key_derivation_function(shared_key: bytes):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=128,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)


def generate_shared_key_from_ephemeral_key(pre_key_bundle_private: PreKeyBundlePrivate,
                                           ephemeral_key_bundle_public: EphemeralKeyBundlePublic):
    DH1 = pre_key_bundle_private.IK_private.exchange(ephemeral_key_bundle_public.ephemeral_key_public)
    DH2 = pre_key_bundle_private.SPK_private.exchange(ephemeral_key_bundle_public.ephemeral_key_public)
    DH3 = pre_key_bundle_private.SPK_private.exchange(ephemeral_key_bundle_public.IK_public)
    DH4 = pre_key_bundle_private.OP_key_private[0].exchange(ephemeral_key_bundle_public.ephemeral_key_public)
    pre_key_bundle_private.OP_key_private.pop(0)

    return key_derivation_function(DH1 + DH2 + DH3 + DH4)


def generate_shared_key_from_pre_key_bundle(pre_key_bundle_public: PreKeyBundlePublic,
                                            ephemeral_key_bundle_private: EphemeralKeyBundlePrivate):
    DH1 = ephemeral_key_bundle_private.ephemeral_key_private.exchange(pre_key_bundle_public.IK_public)
    DH2 = ephemeral_key_bundle_private.ephemeral_key_private.exchange(pre_key_bundle_public.SPK_public)
    DH3 = ephemeral_key_bundle_private.IK_private.exchange(pre_key_bundle_public.SPK_public)
    DH4 = ephemeral_key_bundle_private.ephemeral_key_private.exchange(pre_key_bundle_public.OP_key_public)

    return key_derivation_function(DH1 + DH2 + DH3 + DH4)


if __name__ == '__main__':
    # alice
    alice = create_new_ephemeral_key_bundle()
    alice_ephemeral_keys = alice.publish_keys()
    # bob
    bob = create_new_pre_key_bundle(number_of_onetime_pre_keys=10)
    bob_pre_key_bundle = bob.publish_keys()
    # key exchange
    x1 = generate_shared_key_from_ephemeral_key(pre_key_bundle_private=bob,
                                                ephemeral_key_bundle_public=alice_ephemeral_keys)
    x2 = generate_shared_key_from_pre_key_bundle(pre_key_bundle_public=bob_pre_key_bundle,
                                                 ephemeral_key_bundle_private=alice)

    print(x1)
    print(x2)
    print(x1 == x2)
