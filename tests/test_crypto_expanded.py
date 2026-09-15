import base64
import unittest

from ctf_copilot.crypto.auto import analyze_target
from ctf_copilot.crypto.classical.affine import decrypt as affine_decrypt
from ctf_copilot.crypto.classical.transposition import rail_fence_decrypt
from ctf_copilot.crypto.classical.vigenere import decrypt as vigenere_decrypt
from ctf_copilot.crypto.normalization import parse_bytes
from ctf_copilot.crypto.rsa_engine import render_rsa
from ctf_copilot.crypto.scoring import has_known_flag
from ctf_copilot.crypto.xor.engine import single
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

    def test_parse_bytes_integer_before_hex(self):
        self.assertEqual(parse_bytes("65"), b"A")
        number = 12345678
        expected = number.to_bytes(max(1, (number.bit_length() + 7) // 8), "big")
        self.assertEqual(parse_bytes("12345678"), expected)
        self.assertEqual(parse_bytes("65", fmt="hex"), bytes.fromhex("65"))
        self.assertEqual(parse_bytes("65", fmt="decimal"), b"A")

    def test_triple_layer_base64_hex_base64(self):
        flag = "flag{triple_layer_ok}"
        once = base64.b64encode(flag.encode()).decode()
        twice = once.encode().hex()
        outer = base64.b64encode(twice.encode()).decode()
        output = analyze_target(outer)
        self.assertIn(flag, output)

    def test_wiener_small_d(self):
        p, q, d, message = 1009, 1013, 5, 65
        n = p * q
        phi = (p - 1) * (q - 1)
        e = pow(d, -1, phi)
        c = pow(message, e, n)
        output = render_rsa([f"n={n}\ne={e}\nc={c}"])
        self.assertIn("Wiener", output)

    def test_hastad_broadcast_e3(self):
        pairs = [(1019, 1021), (1031, 1033), (1039, 1049)]
        moduli = [p * q for p, q in pairs]
        message, exponent = 65, 3
        records = [f"n={n}\ne={exponent}\nc={pow(message, exponent, n)}" for n in moduli]
        output = render_rsa(records)
        self.assertIn("broadcast", output.lower())

    def test_shared_prime_gcd(self):
        shared, q1, q2, e, message = 1019, 1021, 1031, 65537, 66
        n1, n2 = shared * q1, shared * q2
        first = f"n={n1}\ne={e}\nc={pow(message, e, n1)}"
        second = f"n={n2}\ne={e}\nc={pow(message, e, n2)}"
        output = render_rsa([first, second])
        self.assertIn("shared-prime", output.lower())

    def test_aes_ecb_round_trip(self):
        try:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad
        except ImportError:
            self.skipTest("PyCryptodome is required for AES round-trip")
        from ctf_copilot.crypto.block import decrypt

        key = b"YELLOW SUBMARINE"
        plaintext = b"flag{aes_ecb_ok}"
        ciphertext = AES.new(key, AES.MODE_ECB).encrypt(pad(plaintext, 16))
        result = decrypt(ciphertext.hex(), "aes", "ecb", key.hex())
        self.assertTrue(result.verified)
        self.assertEqual(result.plaintext, plaintext)

    def test_block_cbc_missing_iv(self):
        from ctf_copilot.crypto.block import decrypt

        with self.assertRaisesRegex(ValueError, "--iv"):
            decrypt("00112233445566778899aabbccddeeff", "aes", "cbc", b"YELLOW SUBMARINE".hex())

    def test_xor_single_random_hex_has_no_flag(self):
        rows = single("deadbeefcafebabe1234567890abcdef11223344")
        self.assertTrue(rows)
        self.assertFalse(any(has_known_flag(row.plaintext) for row in rows))


if __name__ == "__main__":
    unittest.main()
