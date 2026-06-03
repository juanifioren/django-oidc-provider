from django.test import TestCase

from oidc_provider.lib.utils.client_credentials import hash_secret
from oidc_provider.lib.utils.client_credentials import verify_secret


class HashSecretTest(TestCase):
    def test_returns_different_value_from_plaintext(self):
        hashed = hash_secret("mysecret")
        self.assertNotEqual(hashed, "mysecret")

    def test_returns_string(self):
        self.assertIsInstance(hash_secret("mysecret"), str)

    def test_two_calls_produce_different_hashes(self):
        self.assertNotEqual(hash_secret("mysecret"), hash_secret("mysecret"))


class VerifySecretTest(TestCase):
    def test_correct_plaintext_returns_true(self):
        hashed = hash_secret("correct")
        self.assertTrue(verify_secret("correct", hashed))

    def test_wrong_plaintext_returns_false(self):
        hashed = hash_secret("correct")
        self.assertFalse(verify_secret("wrong", hashed))

    def test_empty_plaintext_returns_false(self):
        hashed = hash_secret("correct")
        self.assertFalse(verify_secret("", hashed))

    def test_invalid_hash_returns_false(self):
        self.assertFalse(verify_secret("anything", "not-a-valid-hash"))
