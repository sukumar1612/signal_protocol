import os
import unittest

from src.x3dh.interface import ImportExportMode
from src.x3dh.factory import CreateKeys
from src.x3dh.session import Mode, Session


class TestSession(unittest.TestCase):
    @staticmethod
    def create_keys():
        alice = CreateKeys.create_new_pre_key_bundle(number_of_onetime_pre_keys=10)
        alice.dump_keys(mode=ImportExportMode.file, location="key.txt")

        bob = CreateKeys.create_new_pre_key_bundle(number_of_onetime_pre_keys=10)
        bob.dump_keys(mode=ImportExportMode.file, location="key1.txt")

    def setUp(self):
        TestSession.create_keys()

        self.alice = CreateKeys.load_ephemeral_key_bundle_from_pre_key_bundle(
            mode=ImportExportMode.file, location="key.txt"
        )
        self.alice_ephemeral_keys = self.alice.publish_keys()

        self.bob = CreateKeys.load_pre_key_bundle(
            mode=ImportExportMode.file, location="key1.txt"
        )
        self.bob_pre_key_bundle = self.bob.publish_keys()

        self.alice_session = Session(
            pre_key_bundle=self.bob_pre_key_bundle,
            ephemeral_key_bundle=self.alice,
            mode=Mode.alice,
        )
        self.bob_session = Session(
            pre_key_bundle=self.bob,
            ephemeral_key_bundle=self.alice_ephemeral_keys,
            mode=Mode.bob,
        )

    def tearDown(self):
        os.remove("key.txt")
        os.remove("key1.txt")

    def test_if_shared_key_is_equal(self):
        self.assertTrue(self.alice_session.shared_key == self.bob_session.shared_key)

    def test_double_ratchet(self):
        for i in range(20):
            if i % 4 == 0:
                self.alice_session.double_ratchet(self.bob_session.DH_key_public)
                self.bob_session.double_ratchet(self.alice_session.DH_key_public)

                self.alice_session.update_diffie_hellman_keys()
                self.bob_session.update_diffie_hellman_keys()
            else:
                self.alice_session.symmetric_key_ratchet()
                self.bob_session.symmetric_key_ratchet()

            msg1 = b"a secret message"
            msg = self.alice_session.encrypt_message("a secret message")
            msg = self.bob_session.decrypt_message(msg)
            self.assertTrue(msg1 == msg)
            self.assertTrue(
                self.alice_session.shared_key == self.bob_session.shared_key
            )


if __name__ == "__main__":
    unittest.main()
