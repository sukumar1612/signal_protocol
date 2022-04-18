import os
import unittest

from src.x3dh.abstract_class import ImportExportMode
from src.x3dh.factory import CreateKeys


class TestPreKeyBundles(unittest.TestCase):
    def setUp(self):
        self.bob = CreateKeys.create_new_pre_key_bundle(number_of_onetime_pre_keys=10)
        self.bob.dump_keys(mode=ImportExportMode.file, location="key1.txt")

    def tearDown(self):
        os.remove("key1.txt")

    def test_export_public_key(self):
        self.assertTrue(type(self.bob.publish_keys().export_keys()) == dict)

    def test_dump_and_load_data_from_file(self):
        bob1 = CreateKeys.load_pre_key_bundle(mode=ImportExportMode.file, location="key1.txt")
        self.assertTrue(
            bob1.dump_keys(mode=ImportExportMode.dictionary) == self.bob.dump_keys(mode=ImportExportMode.dictionary))

    def test_dump_and_load_data_from_dictionary(self):
        bob1 = CreateKeys.load_pre_key_bundle(mode=ImportExportMode.dictionary,
                                              keys_dictionary=self.bob.dump_keys(mode=ImportExportMode.dictionary))

        self.assertTrue(
            bob1.dump_keys(mode=ImportExportMode.dictionary) == self.bob.dump_keys(mode=ImportExportMode.dictionary))


if __name__ == '__main__':
    unittest.main()
