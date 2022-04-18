from src.EdDSA.signature_algorithm import SigningKey, VerifyKey


def sign_public_key(seed: bytes, public_key: bytes) -> tuple:
    signing_key = SigningKey(seed=seed)
    signed = signing_key.sign(b"Attack at Dawn")
    verify_key = signing_key.verify_key
    verify_key_bytes = verify_key.encode()

    return signed, verify_key_bytes


def verify_public_key(
    verify_signature_public_key: bytes, signed_public_key: bytes
) -> bool:
    verify_key = VerifyKey(verify_signature_public_key)
    verify_key.verify(signed_public_key)

    return True
