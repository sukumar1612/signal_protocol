import enum
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from exceptions.keys_exception import InvalidMode
from src.x3dh.ephemeral_key_bundles import (
    EphemeralKeyBundlePublic,
    EphemeralKeyBundlePrivate,
)
from src.x3dh.pre_key_bundles import (
    PreKeyBundlePrivate,
    PreKeyBundlePublic,
    generate_keys,
)


class Mode(enum.Enum):
    alice = "alice"
    bob = "bob"


def key_derivation_function(shared_key: bytes, salt: bytes = None):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=128,
        salt=salt,
        info=b"handshake data",
    ).derive(shared_key)


class GenerateSession:
    @staticmethod
    def generate_shared_key_from_pre_key_bundle(
        pre_key_bundle_public: PreKeyBundlePublic,
        ephemeral_key_bundle_private: EphemeralKeyBundlePrivate,
    ):
        DH1 = ephemeral_key_bundle_private.ephemeral_key_private.exchange(
            pre_key_bundle_public.ik_public
        )
        DH2 = ephemeral_key_bundle_private.ephemeral_key_private.exchange(
            pre_key_bundle_public.spk_public
        )
        DH3 = ephemeral_key_bundle_private.ik_private.exchange(
            pre_key_bundle_public.spk_public
        )
        DH4 = ephemeral_key_bundle_private.ephemeral_key_private.exchange(
            pre_key_bundle_public.op_key_public.pop(0)
        )

        if pre_key_bundle_public.verify_signature():
            print("valid signature")

        return key_derivation_function(DH1 + DH2 + DH3 + DH4)

    @staticmethod
    def generate_shared_key_from_ephemeral_key(
        pre_key_bundle_private: PreKeyBundlePrivate,
        ephemeral_key_bundle_public: EphemeralKeyBundlePublic,
    ):
        DH1 = pre_key_bundle_private.ik_private.exchange(
            ephemeral_key_bundle_public.ephemeral_key_public
        )
        DH2 = pre_key_bundle_private.spk_private.exchange(
            ephemeral_key_bundle_public.ephemeral_key_public
        )
        DH3 = pre_key_bundle_private.spk_private.exchange(
            ephemeral_key_bundle_public.ik_public
        )
        DH4 = pre_key_bundle_private.op_key_private[0].exchange(
            ephemeral_key_bundle_public.ephemeral_key_public
        )
        pre_key_bundle_private.op_key_private.pop(0)

        return key_derivation_function(DH1 + DH2 + DH3 + DH4)


class Session:
    def __init__(self, pre_key_bundle, ephemeral_key_bundle, mode: Mode):
        self.mode = mode
        self.shared_key: bytes = b""
        self.salt: bytes = b""
        self.ratchet_count: int = 0
        self.dh_key_private, self.dh_key_public = generate_keys()
        if self.mode == Mode.alice:
            self.shared_key = GenerateSession.generate_shared_key_from_pre_key_bundle(
                pre_key_bundle_public=pre_key_bundle,
                ephemeral_key_bundle_private=ephemeral_key_bundle,
            )
        elif self.mode == Mode.bob:
            self.shared_key = GenerateSession.generate_shared_key_from_ephemeral_key(
                pre_key_bundle_private=pre_key_bundle,
                ephemeral_key_bundle_public=ephemeral_key_bundle,
            )
        else:
            raise InvalidMode

    def get_shared_key(self):
        sha = hashlib.sha256()
        sha.update(self.shared_key)
        return sha.digest()

    def symmetric_key_ratchet(self):
        self.ratchet_count += 1
        self.shared_key = key_derivation_function(self.shared_key, self.salt)

    def double_ratchet(self, public_key: X25519PublicKey):
        self.salt = self.dh_key_private.exchange(public_key)
        self.ratchet_count = 0
        self.symmetric_key_ratchet()

    def update_diffie_hellman_keys(self):
        self.dh_key_private, self.dh_key_public = generate_keys()

    def encrypt_message(self, message: str):
        cipher = Cipher(algorithms.AES(self.get_shared_key()), modes.ECB())
        encryptor = cipher.encryptor()
        return encryptor.update(message.encode("utf-8")) + encryptor.finalize()

    def decrypt_message(self, message: bytes):
        cipher = Cipher(algorithms.AES(self.get_shared_key()), modes.ECB())
        decrypter = cipher.decryptor()
        return decrypter.update(message) + decrypter.finalize()
