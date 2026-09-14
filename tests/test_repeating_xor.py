import unittest
from ctf_copilot.crypto.repeating_xor import crack

class RepeatingXorTests(unittest.TestCase):
    def test_repeating_key_xor(self):
        text=(b'this is a secret message with normal english words and spaces. ' * 8 + b'flag{repeating_xor_test}')
        key=b'ICE'; cipher=bytes(x^key[i%len(key)] for i,x in enumerate(text)).hex()
        rows=crack(cipher)
        self.assertTrue(rows)
        self.assertTrue(all(len(candidate[1]) >= 2 for candidate in rows))
