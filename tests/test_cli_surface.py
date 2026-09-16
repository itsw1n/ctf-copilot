"""CLI surface tests: specialists hidden from --help but still runnable."""
from __future__ import annotations

import io
import re
import unittest
from contextlib import redirect_stdout

from ctf_copilot.cli import build_parser
from ctf_copilot.commands_text import HIDDEN_COMMANDS, render_commands


HIDDEN_ARGV = [
    ["crypto", "decode", "aGk=", "--kind", "base64"],
    ["crypto", "caesar", "abc"],
    ["crypto", "jwt", "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.c2ln"],
    ["crypto", "hash", "5f4dcc3b5aa765d61d8327deb882cf99"],
    ["crypto", "rsa", "n=55 e=3 c=8"],
    ["crypto", "inspect", "flag{test}"],
    ["web", "endpoints", "http://example.test/"],
    ["web", "js", "http://example.test/app.js"],
    ["web", "params", "http://example.test/?a=1"],
    ["web", "headers", "http://example.test/"],
    ["web", "map", "http://example.test/"],
    ["web", "jwt", "eyJhbGciOiJub25lIn0.e30.c2ln"],
    ["forensics", "evidence", "x.bin"],
]


def _help_text(argv: list[str]) -> str:
    parser = build_parser()
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            parser.parse_args([*argv, "--help"])
    except SystemExit as exc:
        self_code = exc.code
        assert self_code == 0, f"help exited {self_code} for {argv}"
    return buf.getvalue()


class CliSurfaceTests(unittest.TestCase):
    def test_hidden_commands_still_parse(self):
        parser = build_parser()
        for argv in HIDDEN_ARGV:
            with self.subTest(argv=argv):
                ns = parser.parse_args(argv)
                self.assertTrue(callable(ns.fn), f"{argv} must still parse")

    def test_hidden_absent_from_category_help(self):
        cases = (
            (("crypto",), ("decode", "caesar", "jwt", "hash", "rsa", "inspect")),
            (("web",), ("endpoints", "js", "params", "headers", "map", "jwt")),
            (("forensics",), ("evidence",)),
        )
        for argv, names in cases:
            with self.subTest(argv=argv):
                text = _help_text(list(argv))
                for name in names:
                    self.assertNotRegex(text, rf"(?m)^\s+{re.escape(name)}\s",
                                        f"{name} must be hidden from {' '.join(argv)} --help")
                    self.assertNotIn(name, text.split("...", 1)[0].split("{")[-1],
                                     f"{name} must be hidden from usage line")

    def test_primaries_still_listed(self):
        text = _help_text(["crypto"])
        for name in ("analyze", "xor", "vigenere", "block", "template"):
            self.assertIn(name, text)
        text = _help_text(["web"])
        for name in ("analyze", "source", "compare", "test", "cbc-bitflip"):
            self.assertIn(name, text)
        text = _help_text(["forensics"])
        for name in ("triage", "metadata", "archive", "recurse", "pcap", "stego"):
            self.assertIn(name, text)

    def test_direct_hidden_help_still_renders(self):
        text = _help_text(["crypto", "hash"])
        self.assertIn("hash", text.lower())

    def test_core_guide_hides_specialists(self):
        core = render_commands(use_color=False)
        for full in HIDDEN_COMMANDS:
            self.assertNotIn(full, core, f"core guide must not list {full}")
        self.assertIn("ctf commands --all", core)

    def test_all_guide_lists_specialists(self):
        full = render_commands(use_color=False, show_all=True)
        for leaf in HIDDEN_COMMANDS:
            self.assertIn(leaf, full, f"--all guide must list {leaf}")

    def test_commands_all_flag_parses(self):
        ns = build_parser().parse_args(["commands", "--all"])
        self.assertTrue(ns.show_all)
        ns2 = build_parser().parse_args(["commands"])
        self.assertFalse(ns2.show_all)


if __name__ == "__main__":
    unittest.main()
