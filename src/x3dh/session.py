from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.x3dh.key_bundles import PreKeyBundlePrivate, PreKeyBundlePublic, EphemeralKeyBundle, create_new_pre_key_bundle


def key_derivation_function(shared_key: bytes):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=128,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)


def generate_shared_key_from_ephemeral_key(pre_key_bundle: PreKeyBundlePrivate, IK_public: X25519PublicKey,
                                           ephemeral_public_key: X25519PublicKey):
    DH1 = pre_key_bundle.IK_private.exchange(ephemeral_public_key)
    DH2 = pre_key_bundle.SPK_private.exchange(ephemeral_public_key)
    DH3 = pre_key_bundle.SPK_private.exchange(IK_public)
    DH4 = pre_key_bundle.OP_key_private[0].exchange(ephemeral_public_key)
    pre_key_bundle.OP_key_private.pop(0)

    return key_derivation_function(DH1 + DH2 + DH3 + DH4)


def generate_shared_key_from_pre_key_bundle(pre_key_bundle: PreKeyBundlePublic,
                                            ephemeral_key_bundle: EphemeralKeyBundle):
    DH1 = ephemeral_key_bundle.ephemeral_key_private.exchange(pre_key_bundle.IK_public)
    DH2 = ephemeral_key_bundle.ephemeral_key_private.exchange(pre_key_bundle.SPK_public)
    DH3 = ephemeral_key_bundle.IK_private.exchange(pre_key_bundle.SPK_public)
    DH4 = ephemeral_key_bundle.ephemeral_key_private.exchange(pre_key_bundle.OP_key_public)

    return key_derivation_function(DH1 + DH2 + DH3 + DH4)


if __name__ == '__main__':
    # alice
    alice = EphemeralKeyBundle()
    # bob
    bob = create_new_pre_key_bundle(number_of_onetime_pre_keys=10)
    bob_pre_key_bundle = bob.publish_keys()
    # key exchange
    x1 = generate_shared_key_from_ephemeral_key(pre_key_bundle=bob, IK_public=alice.IK_public,
                                                ephemeral_public_key=alice.ephemeral_key_public)
    x2 = generate_shared_key_from_pre_key_bundle(pre_key_bundle=bob_pre_key_bundle, ephemeral_key_bundle=alice)

    print(x1)
    print(x2)
    print(x1 == x2)
