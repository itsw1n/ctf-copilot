import unittest

from ctf_copilot.crypto.auto import analyze_target
from ctf_copilot.crypto.classical.affine import decrypt as affine_decrypt
from ctf_copilot.crypto.classical.transposition import rail_fence_decrypt
from ctf_copilot.crypto.classical.vigenere import decrypt as vigenere_decrypt
from ctf_copilot.crypto.rsa_engine import render_rsa
from ctf_copilot.shared.flags import find_flags, validate_flags


class ExpandedCryptoTests(unittest.TestCase):
    def test_classical_direct_helpers(self):
        self.assertEqual(vigenere_decrypt("LXFOPVEFRNHR", "LEMON"), "ATTACKATDAWN")
        self.assertEqual(affine_decrypt("IHHWVCSWFRCP", 5, 8), "AFFINECIPHER")
        self.assertEqual(rail_fence_decrypt("WECRLTEERDSOEEFEAOCAIVDEN", 3), "WEAREDISCOVEREDFLEEATONCE")

    def test_common_modulus_rsa(self):
        n, message = 3233, 65
        first = f"n=3233\ne=17\nc={pow(message, 17, n)}"
        second = f"n=3233\ne=7\nc={pow(message, 7, n)}"
        output = render_rsa([first, second])
        self.assertIn("common-modulus attack", output)
        self.assertIn("Plaintext bytes: b'A'", output)

    def test_analyze_handles_layered_value_without_hash_noise(self):
        output = analyze_target("5a6d78685a3374305a584e3066513d3d")
        self.assertIn("flag{test}", output)
        self.assertNotIn("HASH IDENTIFICATION", output)

    def test_placeholder_is_not_flag(self):
        self.assertEqual(find_flags("picoCTF{...}"), [])
        confirmed, candidates = validate_flags("picoCTF{real_flag}", source_kind="source")
        self.assertEqual(confirmed, [])
        self.assertEqual(candidates, ["picoCTF{real_flag}"])


if __name__ == "__main__":
    unittest.main()
