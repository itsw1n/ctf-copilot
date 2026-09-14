import unittest
from ctf_copilot.cli import build_parser

class CliTests(unittest.TestCase):
    def test_top_level_commands_parse(self):
        parser=build_parser()
        for argv in [
            ['crypto','hash','5f4dcc3b5aa765d61d8327deb882cf99'],
            ['forensics','triage','x.bin'],
            ['reverse','triage','chall'],
            ['pwn','cyclic','create','20'],
            ['network','dns','example.com'],
            ['flags','scan','flag{test}'],
        ]:
            ns=parser.parse_args(argv)
            self.assertTrue(callable(ns.fn))
    def test_supports_color_respects_flag_and_env(self):
        from ctf_copilot.shared.style import supports_color, c
        self.assertFalse(supports_color(True))
        self.assertIn("\x1b[", c("x", "1", enabled=True))
        self.assertEqual(c("x", "1", enabled=False), "x")

    def test_render_commands_plain_and_color(self):
        from ctf_copilot.commands_text import render_commands
        plain = render_commands(use_color=False)
        self.assertNotIn("\x1b[", plain)
        self.assertIn("ctf solve <target>", plain)
        self.assertIn("ctf crypto analyze <text>", plain)
        self.assertIn("ctf forensics triage <file>", plain)
        colored = render_commands(use_color=True)
        self.assertIn("\x1b[", colored)
        self.assertIn("ctf solve <target>", colored)

if __name__=='__main__': unittest.main()
