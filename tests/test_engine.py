import json
import tempfile
import unittest
from pathlib import Path

from ctf_copilot.engine import initial_report, render_report
from ctf_copilot.cli import build_parser
from ctf_copilot.solve import solve
from ctf_copilot.solve import _password_candidates


class EngineTests(unittest.TestCase):
    def test_description_and_custom_flag(self):
        report = initial_report("hello", "the answer is SCHOOL{ok}", r"SCHOOL\{[^}]+\}")
        self.assertEqual(report.status, "flag-found")
        self.assertIn("SCHOOL{ok}", report.flags)

    def test_web_has_explainable_next_action(self):
        text = render_report(initial_report("http://challenge.local"))
        self.assertIn("Tool used:", text)
        self.assertIn("ctf web analyze", text)
        self.assertIn("No flag found", text)

    def test_new_cli_options_parse(self):
        ns = build_parser().parse_args(["solve", "x.txt", "--description", "decode", "--workspace", "demo"])
        self.assertEqual(ns.workspace, "demo")

    def test_solve_report_uses_actual_decode_output(self):
        text=solve('666c61677b6c6f6f705f746573747d')
        self.assertIn('flag{loop_test}',text)
        self.assertIn('Status: flag-found',text)

    def test_explicit_password_candidates_only(self):
        self.assertEqual(_password_candidates('password: ctf_2026'), ['ctf_2026'])


if __name__ == "__main__":
    unittest.main()
