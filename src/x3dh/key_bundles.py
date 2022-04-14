import pickle

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from src.EdDSA.signature import sign_public_key, verify_public_key


class EphemeralKeyBundlePublic:
    """ enter keys in RAW bytes format"""
    def __init__(self, IK_public: bytes, ephemeral_key_public: bytes):
        self.IK_public = X25519PublicKey.from_public_bytes(IK_public)
        self.ephemeral_key_public = X25519PublicKey.from_public_bytes(ephemeral_key_public)

    def export(self):
        return {
            'IK_public': self.IK_public.public_bytes(serialization.Encoding.Raw,
                                                     serialization.PublicFormat.Raw),
            'ephemeral_key_public': self.ephemeral_key_public.public_bytes(serialization.Encoding.Raw,
                                                                           serialization.PublicFormat.Raw)
        }


class EphemeralKeyBundlePrivate:
    """In the example given in the signal documentation, this would be the alice side of things"""

    def __init__(self, IK_public: X25519PublicKey, IK_private: X25519PrivateKey):
        self.IK_private = IK_private
        self.IK_public = IK_public
        self.ephemeral_key_private, self.ephemeral_key_public = generate_keys()

    def publish_keys(self):
        keys = {
            'IK_public': self.IK_public.public_bytes(serialization.Encoding.Raw,
                                                     serialization.PublicFormat.Raw),
            'ephemeral_key_public': self.ephemeral_key_public.public_bytes(serialization.Encoding.Raw,
                                                                           serialization.PublicFormat.Raw)
        }
        return EphemeralKeyBundlePublic(**keys)


class PreKeyBundlePublic:
    """ enter keys in RAW bytes format"""

    def __init__(self, IK_public: bytes, SPK_public: bytes, signature: bytes, OP_key_public: bytes,
                 verify_signature_public_key: bytes):
        self.IK_public = X25519PublicKey.from_public_bytes(IK_public)
        self.SPK_public = X25519PublicKey.from_public_bytes(SPK_public)
        self.signature = signature
        self.OP_key_public = X25519PublicKey.from_public_bytes(OP_key_public)
        self.verify_signature_public_key = verify_signature_public_key

    def export_keys(self):
        return {
            'IK_public': self.IK_public.public_bytes(serialization.Encoding.Raw,
                                                     serialization.PublicFormat.Raw),
            'SPK_public': self.SPK_public.public_bytes(serialization.Encoding.Raw,
                                                       serialization.PublicFormat.Raw),
            'signature': self.signature,
            'one_time_key': self.OP_key_public.public_bytes(serialization.Encoding.Raw,
                                                            serialization.PublicFormat.Raw),
        }

    def verify_signature(self):
        return verify_public_key(verify_signature_public_key=self.verify_signature_public_key,
                                 signed_public_key=self.signature)


class PreKeyBundlePrivate:
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
        one_time_key = self.OP_key_private[0]
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

    def dump_keys(self, location):
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
        with open(location, 'wb') as pre_keys:
            pickle.dump(keys, pre_keys)

    @staticmethod
    def load_data(location: str):
        keys = None
        with open(location, 'rb') as pre_keys:
            keys = pickle.load(pre_keys)
        if keys is not None:
            keys['IK_private'] = X25519PrivateKey.from_private_bytes(keys['IK_private'])
            keys['IK_public'] = X25519PublicKey.from_public_bytes(keys['IK_public'])
            keys['SPK_private'] = X25519PrivateKey.from_private_bytes(keys['SPK_private'])
            keys['SPK_public'] = X25519PublicKey.from_public_bytes(keys['SPK_public'])
            keys['OP_key_private'] = [X25519PrivateKey.from_private_bytes(key) for key in keys['OP_key_private']]
        return PreKeyBundlePrivate(**keys)


def create_new_ephemeral_key_bundle():
    IK_keys = generate_keys()
    return EphemeralKeyBundlePrivate(IK_public=IK_keys[1], IK_private=IK_keys[0])


def create_new_pre_key_bundle(number_of_onetime_pre_keys: int):
    OP_key_private = [X25519PrivateKey.generate() for count in range(number_of_onetime_pre_keys)]
    IK_keys = generate_keys()
    SPK_keys = generate_keys()
    pre_key_bundle_private = PreKeyBundlePrivate(IK_private=IK_keys[0], IK_public=IK_keys[1], SPK_private=SPK_keys[0],
                                                 SPK_public=SPK_keys[1], OP_key_private=OP_key_private)
    return pre_key_bundle_private


def generate_keys():
    key_private = X25519PrivateKey.generate()
    return key_private, key_private.public_key()


if __name__ == "__main__":
    x = create_new_pre_key_bundle(number_of_onetime_pre_keys=10)
    print(x.publish_keys().export_keys())
    x.dump_keys(location='pre_key.bundle')
    print(PreKeyBundlePrivate.load_data(location='pre_key.bundle').publish_keys().export_keys())
