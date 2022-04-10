import enum
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.x3dh.key_bundles import PreKeyBundlePrivate, PreKeyBundlePublic, EphemeralKeyBundlePrivate, \
    create_new_pre_key_bundle, EphemeralKeyBundlePublic, create_new_ephemeral_key_bundle, generate_keys


class Mode(enum.Enum):
    alice = "alice"
    bob = "bob"


def key_derivation_function(shared_key: bytes, salt: bytes = None):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=128,
        salt=None,
        info=b'handshake data',
    ).derive(shared_key)


class Session:
    def __init__(self, pre_key_bundle, ephemeral_key_bundle, mode: Mode):
        self.mode = mode
        self.shared_key: bytes = None
        self.salt: bytes = None
        self.DH_key_private, self.DH_key_public = generate_keys()
        if self.mode == Mode.alice:
            self.shared_key = Session.generate_shared_key_from_pre_key_bundle(
                pre_key_bundle_public=pre_key_bundle, ephemeral_key_bundle_private=ephemeral_key_bundle)
        else:
            self.shared_key = Session.generate_shared_key_from_ephemeral_key(pre_key_bundle_private=pre_key_bundle,
                                                                             ephemeral_key_bundle_public=ephemeral_key_bundle)

    @staticmethod
    def generate_shared_key_from_pre_key_bundle(pre_key_bundle_public: PreKeyBundlePublic,
                                                ephemeral_key_bundle_private: EphemeralKeyBundlePrivate):
        DH1 = ephemeral_key_bundle_private.ephemeral_key_private.exchange(pre_key_bundle_public.IK_public)
        DH2 = ephemeral_key_bundle_private.ephemeral_key_private.exchange(pre_key_bundle_public.SPK_public)
        DH3 = ephemeral_key_bundle_private.IK_private.exchange(pre_key_bundle_public.SPK_public)
        DH4 = ephemeral_key_bundle_private.ephemeral_key_private.exchange(pre_key_bundle_public.OP_key_public)

        return key_derivation_function(DH1 + DH2 + DH3 + DH4)

    @staticmethod
    def generate_shared_key_from_ephemeral_key(pre_key_bundle_private: PreKeyBundlePrivate,
                                               ephemeral_key_bundle_public: EphemeralKeyBundlePublic):
        DH1 = pre_key_bundle_private.IK_private.exchange(ephemeral_key_bundle_public.ephemeral_key_public)
        DH2 = pre_key_bundle_private.SPK_private.exchange(ephemeral_key_bundle_public.ephemeral_key_public)
        DH3 = pre_key_bundle_private.SPK_private.exchange(ephemeral_key_bundle_public.IK_public)
        DH4 = pre_key_bundle_private.OP_key_private[0].exchange(ephemeral_key_bundle_public.ephemeral_key_public)
        pre_key_bundle_private.OP_key_private.pop(0)

        return key_derivation_function(DH1 + DH2 + DH3 + DH4)

    def symmetric_key_ratchet(self):
        self.shared_key = key_derivation_function(self.shared_key, self.salt)

    def double_ratchet(self, public_key: X25519PublicKey):
        self.salt = self.DH_key_private.exchange(public_key)
        self.symmetric_key_ratchet()

    def update_diffie_hellman_keys(self):
        self.DH_key_private, self.DH_key_public = generate_keys()

    def get_shared_key(self):
        m = hashlib.sha256()
        m.update(self.shared_key)
        return m.digest()

    def encrypt_message(self, message: str):
        cipher = Cipher(algorithms.AES(self.get_shared_key()), modes.ECB())
        encryptor = cipher.encryptor()
        return encryptor.update(message.encode('utf-8')) + encryptor.finalize()

    def decrypt_message(self, message: bytes):
        cipher = Cipher(algorithms.AES(self.get_shared_key()), modes.ECB())
        decrypter = cipher.decryptor()
        return (decrypter.update(message) + decrypter.finalize()).decode('utf-8')


if __name__ == '__main__':
    # alice
    alice = create_new_ephemeral_key_bundle()
    alice_ephemeral_keys = alice.publish_keys()
    # bob
    bob = create_new_pre_key_bundle(number_of_onetime_pre_keys=10)
    bob_pre_key_bundle = bob.publish_keys()
    # key exchange
    x1 = Session(pre_key_bundle=bob, ephemeral_key_bundle=alice_ephemeral_keys, mode=Mode.bob)
    x2 = Session(pre_key_bundle=bob_pre_key_bundle, ephemeral_key_bundle=alice, mode=Mode.alice)

    for i in range(10):
        x1.double_ratchet(x2.DH_key_public)
        x2.double_ratchet(x1.DH_key_public)

        x1.update_diffie_hellman_keys()
        x2.update_diffie_hellman_keys()

        print(x1.shared_key)
        print(x2.shared_key)
        print(x1.shared_key == x2.shared_key)
