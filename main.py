from src.x3dh.key_bundles import create_new_ephemeral_key_bundle, create_new_pre_key_bundle
from src.x3dh.session import Session, Mode

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

    for count in range(10):
        x1.double_ratchet(x2.DH_key_public)
        x2.double_ratchet(x1.DH_key_public)

        x1.update_diffie_hellman_keys()
        x2.update_diffie_hellman_keys()

        print(x1.shared_key)
        print(x2.shared_key)
        print(x1.shared_key == x2.shared_key)

        print()
        msg = x1.encrypt_message("a secret message")
        print(msg)
        print(x2.decrypt_message(msg))
        print()
        print("--------------------------------------------")
