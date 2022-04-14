from typing import Optional

import nacl.bindings
from nacl import encoding
from nacl import exceptions as exc
from nacl.public import (
    PrivateKey as _Curve25519_PrivateKey,
    PublicKey as _Curve25519_PublicKey,
)
from nacl.utils import StringFixer, random


class SignedMessage(bytes):
    _signature: bytes
    _message: bytes

    @classmethod
    def from_parts(
            cls, signature: bytes, message: bytes, combined: bytes
    ) -> "SignedMessage":
        obj = cls(combined)
        obj._signature = signature
        obj._message = message
        return obj

    @property
    def signature(self) -> bytes:
        return self._signature

    @property
    def message(self) -> bytes:
        return self._message


class VerifyKey(encoding.Encodable, StringFixer):
    def __init__(
            self, key: bytes, encoder: encoding.Encoder = encoding.RawEncoder
    ):
        key = encoder.decode(key)
        if not isinstance(key, bytes):
            raise exc.TypeError("VerifyKey must be created from 32 bytes")

        if len(key) != nacl.bindings.crypto_sign_PUBLICKEYBYTES:
            raise exc.ValueError(
                "The key must be exactly %s bytes long"
                % nacl.bindings.crypto_sign_PUBLICKEYBYTES,
            )

        self._key = key

    def __bytes__(self) -> bytes:
        return self._key

    def __hash__(self) -> int:
        return hash(bytes(self))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return False
        return nacl.bindings.sodium_memcmp(bytes(self), bytes(other))

    def __ne__(self, other: object) -> bool:
        return not (self == other)

    def verify(
            self,
            smessage: bytes,
            signature: Optional[bytes] = None,
            encoder: encoding.Encoder = encoding.RawEncoder,
    ) -> bytes:
        if signature is not None:
            if not isinstance(signature, bytes):
                raise exc.TypeError(
                    "Verification signature must be created from %d bytes"
                    % nacl.bindings.crypto_sign_BYTES,
                )

            if len(signature) != nacl.bindings.crypto_sign_BYTES:
                raise exc.ValueError(
                    "The signature must be exactly %d bytes long"
                    % nacl.bindings.crypto_sign_BYTES,
                )

            smessage = signature + encoder.decode(smessage)
        else:
            smessage = encoder.decode(smessage)

        return nacl.bindings.crypto_sign_open(smessage, self._key)

    def to_curve25519_public_key(self) -> _Curve25519_PublicKey:
        raw_pk = nacl.bindings.crypto_sign_ed25519_pk_to_curve25519(self._key)
        return _Curve25519_PublicKey(raw_pk)


class SigningKey(encoding.Encodable, StringFixer):
    def __init__(
            self,
            seed: bytes,
            encoder: encoding.Encoder = encoding.RawEncoder,
    ):
        seed = encoder.decode(seed)
        if not isinstance(seed, bytes):
            raise exc.TypeError(
                "SigningKey must be created from a 32 byte seed"
            )

        if len(seed) != nacl.bindings.crypto_sign_SEEDBYTES:
            raise exc.ValueError(
                "The seed must be exactly %d bytes long"
                % nacl.bindings.crypto_sign_SEEDBYTES
            )

        public_key, secret_key = nacl.bindings.crypto_sign_seed_keypair(seed)

        self.seed = seed
        self._signing_key = secret_key
        self.verify_key = VerifyKey(public_key)

    def __bytes__(self) -> bytes:
        return self.seed

    def __hash__(self) -> int:
        return hash(bytes(self))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return False
        return nacl.bindings.sodium_memcmp(bytes(self), bytes(other))

    def __ne__(self, other: object) -> bool:
        return not (self == other)

    @classmethod
    def generate(cls) -> "SigningKey":
        return cls(
            random(nacl.bindings.crypto_sign_SEEDBYTES),
            encoder=encoding.RawEncoder,
        )

    def sign(
            self,
            message: bytes,
            encoder: encoding.Encoder = encoding.RawEncoder,
    ) -> SignedMessage:

        raw_signed = nacl.bindings.crypto_sign(message, self._signing_key)

        crypto_sign_BYTES = nacl.bindings.crypto_sign_BYTES
        signature = encoder.encode(raw_signed[:crypto_sign_BYTES])
        message = encoder.encode(raw_signed[crypto_sign_BYTES:])
        signed = encoder.encode(raw_signed)

        return SignedMessage.from_parts(signature, message, signed)

    def to_curve25519_private_key(self) -> _Curve25519_PrivateKey:
        sk = self._signing_key
        raw_private = nacl.bindings.crypto_sign_ed25519_sk_to_curve25519(sk)
        return _Curve25519_PrivateKey(raw_private)


def sign_public_key(seed: bytes, public_key: bytes) -> tuple:
    signing_key = SigningKey(seed=seed)
    signed = signing_key.sign(b"Attack at Dawn")
    verify_key = signing_key.verify_key
    verify_key_bytes = verify_key.encode()

    return signed, verify_key_bytes


def verify_public_key(verify_signature_public_key: bytes, signed_public_key: bytes) -> bool:
    verify_key = VerifyKey(verify_signature_public_key)
    verify_key.verify(signed_public_key)

    return True
