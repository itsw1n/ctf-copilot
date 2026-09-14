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

if __name__=='__main__': unittest.main()
