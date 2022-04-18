import os
import unittest

from cryptography.hazmat.primitives import serialization

from src.x3dh.abstract_class import ImportExportMode
from src.x3dh.factory import CreateKeys


class TestEphemeralKeyBundles(unittest.TestCase):
    def setUp(self):
        self.alice = CreateKeys.create_new_pre_key_bundle(number_of_onetime_pre_keys=10)
        self.alice.dump_keys(mode=ImportExportMode.file, location="key1.txt")

    def tearDown(self):
        os.remove("key1.txt")

    def test_export_public_key(self):
        self.assertTrue(type(self.alice.publish_keys().export_keys()) == dict)

    def test_dump_and_load_data_from_file(self):
        alice1 = CreateKeys.load_ephemeral_key_bundle_from_pre_key_bundle(mode=ImportExportMode.file,
                                                                          location="key1.txt")
        self.assertTrue(
            alice1.IK_private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                            serialization.NoEncryption()) == self.alice.IK_private.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption()))

    def test_dump_and_load_data_from_dictionary(self):
        alice1 = CreateKeys.load_ephemeral_key_bundle_from_pre_key_bundle(mode=ImportExportMode.dictionary,
                                                                          keys_dictionary=self.alice.dump_keys(
                                                                              mode=ImportExportMode.dictionary))
        self.assertTrue(
            alice1.IK_private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                            serialization.NoEncryption()) == self.alice.IK_private.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption()))


if __name__ == '__main__':
    unittest.main()
