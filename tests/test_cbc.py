import unittest
from ctf_copilot.web.cbc import bitflip, acquire_cookie

class CbcTests(unittest.TestCase):
    def test_rejects_non_double_base64_cookie(self):
        self.assertIn('Cookie must be',bitflip('http://challenge.local','not-a-cookie'))

    def test_auto_cookie_failure_is_explained(self):
        value,message=acquire_cookie('http://127.0.0.1:1')
        self.assertIsNone(value)
        self.assertIn('Could not obtain',message)

    def test_invalid_cookie_does_not_call_progress(self):
        calls=[]
        bitflip('http://challenge.local','not-a-cookie',progress=calls.append)
        self.assertEqual(calls,[])
