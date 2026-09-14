import unittest
from ctf_copilot.crypto.rsa import solve

class RsaTests(unittest.TestCase):
    def test_small_factor_rsa(self):
        # 61 * 53, e=17, plaintext 65
        self.assertIn("Recovered plaintext", solve("n = 3233\ne = 17\nc = 2790"))

    def test_small_exponent(self):
        self.assertIn("Plaintext bytes", solve("n = 9999999967\ne = 3\nc = 274625"))
