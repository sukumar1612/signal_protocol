from src.x3dh.ephemeral_key_bundles import create_new_ephemeral_key_bundle
from src.x3dh.pre_key_bundles import create_new_pre_key_bundle
from src.x3dh.session import Session, Mode

if __name__ == '__main__':
    # alice
    # alice = create_new_pre_key_bundle(number_of_onetime_pre_keys=10)
    # alice = EphemeralKeyBundlePrivate.load_data('key.txt')
    # alice.dump_keys('key.txt')
    alice = create_new_ephemeral_key_bundle()
    alice_ephemeral_keys = alice.publish_keys()

    # bob
    # bob = PreKeyBundlePrivate.load_data('key1.txt')
    bob = create_new_pre_key_bundle(number_of_onetime_pre_keys=10)
    # bob.dump_keys('key1.txt')
    bob_pre_key_bundle = bob.publish_keys()

    # key exchange
    # bob
    x1 = Session(pre_key_bundle=bob, ephemeral_key_bundle=alice_ephemeral_keys, mode=Mode.bob)
    # alice
    x2 = Session(pre_key_bundle=bob_pre_key_bundle, ephemeral_key_bundle=alice, mode=Mode.alice)

    for i in range(20):
        print(x1.shared_key)
        print(x2.shared_key)
        print(x1.shared_key == x2.shared_key)
        print(x1.ratchet_count)

        if i % 4 == 0:
            x1.double_ratchet(x2.DH_key_public)
            x2.double_ratchet(x1.DH_key_public)

            x1.update_diffie_hellman_keys()
            x2.update_diffie_hellman_keys()
        else:
            x1.symmetric_key_ratchet()
            x2.symmetric_key_ratchet()

        print()
        msg = x1.encrypt_message("a secret message")
        print(msg)
        print(x2.decrypt_message(msg))
        print()
        print("--------------------------------------------")

    '''x1.double_ratchet(x2.DH_key_public)
    x2.double_ratchet(x1.DH_key_public)

    x1.update_diffie_hellman_keys()
    x2.update_diffie_hellman_keys()
    msg: bytes = None
    for count in range(4):
        x1.symmetric_key_ratchet()
        print()
        msg = x1.encrypt_message("a secret message")
        print(msg)
    print(x1.message_count)
    for count in range(x1.message_count-1):
        x2.symmetric_key_ratchet()

    print(x2.decrypt_message(msg))
    '''
