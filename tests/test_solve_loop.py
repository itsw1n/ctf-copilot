"""Solve orchestration loop tests (Task 17, Phase 11).

Bounded, mocked, offline. No active probes from solve.
"""
import base64
import binascii
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


def _b64_of_hex(flag: str) -> str:
    hexed = binascii.hexlify(flag.encode()).decode()
    return base64.b64encode(hexed.encode()).decode()


class SolveLoopTests(unittest.TestCase):
    def test_text_layered_flag_solves(self):
        from ctf_copilot.solve import solve
        flag = "flag{layered_loop_ok}"
        layered = _b64_of_hex(flag)
        out = solve(layered)
        self.assertIn(flag, out)
        self.assertIn("Status: flag-found", out)

    def test_file_triage_artifact_enqueued(self):
        from ctf_copilot.solve import solve
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "clue.txt"
            target.write_text("hello flag{file_triage_ok} world", encoding="utf-8")
            ws = os.path.join(d, "ws1")
            out = solve(str(target), workspace=ws)
            self.assertIn("flag{file_triage_ok}", out)
            self.assertIn("Status: flag-found", out)
            wdir = Path(ws)
            # flat workspace: report at root, artifacts flat with artifact-XXX names
            report = wdir / "solve-report.json"
            self.assertTrue(report.exists(), f"missing {report}; got {list(wdir.iterdir())}")
            arts = [p for p in wdir.iterdir() if p.name.startswith("artifact-")]
            self.assertTrue(arts, "expected at least one flat artifact")

    def test_input_related_rsa_pair_solves(self):
        from ctf_copilot.solve import solve
        # Shared-prime pair: n1=p*q1, n2=p*q2, same e, plaintext is a flag.
        # 48-bit primes keep the test fast; GCD needs no factoring.
        def _next_prime(n):
            def _is_prime(x):
                if x < 2:
                    return False
                small = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
                for s in small:
                    if x % s == 0:
                        return x == s
                d = x - 1
                r = 0
                while d % 2 == 0:
                    d //= 2
                    r += 1
                for a in (2, 7, 61):
                    if a % x == 0:
                        continue
                    v = pow(a, d, x)
                    if v in (1, x - 1):
                        continue
                    for _ in range(r - 1):
                        v = (v * v) % x
                        if v == x - 1:
                            break
                    else:
                        return False
                return True
            if n % 2 == 0:
                n += 1
            while not _is_prime(n):
                n += 2
            return n

        base = (1 << 48) + 12345
        p = _next_prime(base)
        q1 = _next_prime(p + 1000003)
        q2 = _next_prime(q1 + 1000033)
        n1, n2 = p * q1, p * q2
        e = 65537
        flag = "flag{rsa1}"
        m = int.from_bytes(flag.encode(), "big")
        self.assertLess(m, min(n1, n2), "test primes too small for flag int")
        c1, c2 = pow(m, e, n1), pow(m, e, n2)
        with tempfile.TemporaryDirectory() as d:
            t1 = Path(d) / "rsa1.txt"
            t2 = Path(d) / "rsa2.txt"
            t1.write_text(f"n = {n1}\ne = {e}\nc = {c1}\n", encoding="utf-8")
            t2.write_text(f"n = {n2}\ne = {e}\nc = {c2}\n", encoding="utf-8")
            out = solve(str(t1), inputs=[str(t2)])
            self.assertIn(flag, out)
            self.assertIn("Status: flag-found", out)

    def test_budget_fast_stops_quickly(self):
        from ctf_copilot.solve import solve
        from ctf_copilot.analysis.budget import AnalysisBudget
        self.assertEqual(AnalysisBudget.named("fast").max_depth, 3)
        self.assertEqual(AnalysisBudget.named("balanced").max_depth, 5)
        self.assertEqual(AnalysisBudget.named("deep").max_depth, 7)
        out = solve("hello world, no flag here", budget="fast")
        self.assertNotIn("Status: flag-found", out)
        # budget profile recorded in workspace report
        with tempfile.TemporaryDirectory() as d:
            ws = os.path.join(d, "wsfast")
            solve("hello world, no flag here", workspace=ws, budget="fast")
            import json
            rep = json.loads((Path(ws) / "solve-report.json").read_text(encoding="utf-8"))
            self.assertEqual(rep.get("budget", {}).get("profile"), "fast")
            self.assertTrue(rep.get("stop_reason"))

    def test_no_http_requests_from_solve(self):
        from ctf_copilot import solve as solve_mod
        # Non-URL solve must not touch the network at all.
        with mock.patch("urllib.request.urlopen") as uo, \
             mock.patch("ctf_copilot.web.analyzer.analyze") as wa:
            out = solve_mod.solve("hello plain text, nothing encoded")
            self.assertEqual(uo.call_count, 0)
            self.assertEqual(wa.call_count, 0)
            self.assertNotIn("Status: flag-found", out)
        # URL solve uses passive analyze with crawl=0 only, never probes.
        fake_info = {
            "status": 200, "final": "http://example.test/", "final_url": "http://example.test/",
            "headers": {}, "history": [], "redirect_chain": [],
            "comments": [], "forms": [], "scripts": [], "links": [], "endpoints": [],
            "script_endpoints": {}, "script_texts": {}, "sourcemaps": {},
            "cookies": [], "cookie_details": [], "cookie_flags": [], "jwt": [],
            "secrets": [], "tech_hints": [], "security_audit": [], "auth_hints": [],
            "robots": "", "sitemap": "", "security_txt": "", "crawled": ["http://example.test/"],
            "ledger": [],
        }
        with mock.patch("ctf_copilot.web.analyzer.analyze", return_value=fake_info) as wa, \
             mock.patch("ctf_copilot.web.playbook.map_target", return_value="map") as mt:
            # probes must never be called from solve; guard by patching to raise
            with mock.patch("ctf_copilot.web.session.WebSession.get",
                            side_effect=AssertionError("active probe from solve")):
                # web.analyzer.analyze is mocked so no session use; map_target also mocked
                out = solve_mod.solve("http://example.test/")
                self.assertEqual(wa.call_count, 1)
                _, kwargs = wa.call_args
                self.assertIn("crawl", kwargs)
                self.assertEqual(kwargs["crawl"], 0)
                self.assertEqual(mt.call_count, 0, "solve must not call active web map/probes")

    def test_placeholder_not_flag_found(self):
        from ctf_copilot.solve import solve
        for ph in ("flag{placeholder}", "flag{example}", "flag{xxx}", "ctf{flag here}"):
            out = solve(ph)
            self.assertNotIn("Status: flag-found", out, f"placeholder {ph} must not solve")

    def test_dedup_same_input_twice_no_infinite_loop(self):
        from ctf_copilot.solve import solve
        flag = "flag{dedup_ok}"
        layered = _b64_of_hex(flag)
        out = solve(layered, inputs=["text:" + layered, layered])
        self.assertIn(flag, out)
        self.assertIn("Status: flag-found", out)

    def test_cli_input_budget_options(self):
        from ctf_copilot.cli import build_parser
        ns = build_parser().parse_args(["solve", "target.txt"])
        self.assertEqual(ns.budget, "balanced")
        self.assertEqual(ns.input, [])
        ns = build_parser().parse_args(
            ["solve", "target.txt", "--input", "a.txt", "--input", "text:hello", "--budget", "fast"])
        self.assertEqual(ns.input, ["a.txt", "text:hello"])
        self.assertEqual(ns.budget, "fast")


if __name__ == "__main__":
    unittest.main()
