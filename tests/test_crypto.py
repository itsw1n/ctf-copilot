import unittest
from ctf_copilot.crypto.analyzer import analyze
from ctf_copilot.crypto.encodings.base import decode

class CryptoTests(unittest.TestCase):
    def test_caesar_flag_is_ranked_first(self):
        result=analyze("b'wpjvJAM{jhlzhy_k3jy9wa3k_h47j6k69}'")
        self.assertTrue(result)
        self.assertEqual(result[0].output,'picoCTF{caesar_d3cr9pt3d_a47c6d69}')
        self.assertEqual(result[0].chain[-1].kind,'caesar')

    def test_recursive_hex_base64(self):
        result=analyze('5a6d78685a3374305a584e3066513d3d')
        self.assertTrue(result)
        self.assertEqual(result[0].output,'flag{test}')
        self.assertEqual([x.kind for x in result[0].chain],['hex','base64'])

    def test_hex_manual(self):
        self.assertEqual(decode('hex','48656c6c6f'),'Hello')

    def test_base64_ciphertext_plus_is_not_url_decoded(self):
        value='TTgwdUplNXhvMUxXS2hWdmhwZkNYeTZrTTFkNll1SjdhbTBhUXVyd2krdFFkdkg0'
        rows=analyze(value)
        self.assertEqual([x.kind for x in rows[0].chain],['base64'])
        self.assertIn('+',rows[0].output)

if __name__=='__main__': unittest.main()
