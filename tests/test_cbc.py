import unittest
from ctf_copilot.web.cbc import bitflip

class CbcTests(unittest.TestCase):
    def test_rejects_non_double_base64_cookie(self):
        self.assertIn('Cookie must be',bitflip('http://challenge.local','not-a-cookie'))
