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

