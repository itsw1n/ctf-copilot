"""Single-source-of-truth flag-prefix tests (no permanent DICT in builtins)."""
from __future__ import annotations

import base64
import io
import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path


def _write_config(directory: str, prefixes=None, patterns=None) -> str:
    path = os.path.join(directory, "config.toml")
    lines = ["[flags]"]
    if prefixes is not None:
        lines.append("prefixes = [" + ", ".join(f'"{p}"' for p in prefixes) + "]")
    if patterns is not None:
        lines.append("patterns = [" + ", ".join(f'"{p}"' for p in patterns) + "]")
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


class _ConfigMixin:
    def setUp(self):
        self._tmp = tempfile.mkdtemp(prefix="ctf-flags-")
        from ctf_copilot.shared import flags as F
        self.F = F
        F.reload_flag_config(None)

    def tearDown(self):
        self.F.reload_flag_config(None)

    def use_config(self, prefixes=None, patterns=None):
        path = _write_config(self._tmp, prefixes, patterns)
        self.F.reload_flag_config(path)
        return path


class SharedMatcherTests(_ConfigMixin, unittest.TestCase):
    def test_builtin_prefixes_still_work(self):
        self.assertIn("flag{abc}", self.F.find_flags("see flag{abc} here"))
        self.assertIn("picoCTF{abc}", self.F.find_flags("picoCTF{abc}"))
        c, _ = self.F.validate_flags("ctf{abc}", source_kind="extracted")
        self.assertIn("ctf{abc}", c)  # ctf validation fix: must confirm

    def test_generic_unknown_is_candidate_only(self):
        found = self.F.find_flags("see XYZ{hello} here")
        self.assertIn("XYZ{hello}", found)
        c, cand = self.F.validate_flags("XYZ{hello}", source_kind="decoded")
        self.assertEqual(c, [])
        self.assertIn("XYZ{hello}", cand)

    def test_placeholders_rejected(self):
        for text in ("flag{...}", "flag{flag_here}", "flag{redacted}", "flag{}"):
            self.assertEqual(self.F.find_flags(f"got {text}"), [], text)

    def test_configured_prefix_recognized_as_known(self):
        self.use_config(prefixes=["DICT"])
        self.assertIn("DICT", self.F.known_prefixes())
        self.assertIn("DICT{hello}", self.F.find_flags("got DICT{hello}"))
        self.assertTrue(self.F.has_known_flag("x DICT{hello} y"))
        c, _ = self.F.validate_flags("DICT{hello}", source_kind="decoded")
        self.assertIn("DICT{hello}", c)
        # unconfigured generic stays weaker
        c2, cand2 = self.F.validate_flags("XYZ{hello}", source_kind="decoded")
        self.assertEqual(c2, [])
        self.assertIn("XYZ{hello}", cand2)

    def test_unconfigured_dict_is_only_generic(self):
        found = self.F.find_flags("got DICT{hello}")
        self.assertIn("DICT{hello}", found)  # generic fallback sees it
        self.assertFalse(self.F.has_known_flag("got DICT{hello}"))
        c, _ = self.F.validate_flags("DICT{hello}", source_kind="decoded")
        self.assertEqual(c, [])


class DefaultPathTests(_ConfigMixin, unittest.TestCase):
    def test_default_path_is_repo_root_config(self):
        from ctf_copilot.shared.flags import default_config_path
        expected = Path(__file__).resolve().parent.parent / "config.toml"
        self.assertEqual(default_config_path(), expected)
        self.assertTrue(expected.is_file(), "repo-root config.toml must exist")

    def test_default_root_config_keeps_builtins(self):
        # shipped config.toml has empty prefixes/patterns -> builtins work
        self.assertIn("flag{abc}", self.F.find_flags("flag{abc}"))
        self.assertEqual(self.F.get_flag_config_warnings(), [])


class ConfigRobustnessTests(_ConfigMixin, unittest.TestCase):
    def test_missing_and_empty_config_use_builtins(self):
        self.F.reload_flag_config(os.path.join(self._tmp, "does-not-exist.toml"))
        self.assertIn("flag{abc}", self.F.find_flags("flag{abc}"))
        self.assertEqual(self.F.get_flag_config_warnings(), [])
        empty = os.path.join(self._tmp, "empty.toml")
        Path(empty).write_text("", encoding="utf-8")
        self.F.reload_flag_config(empty)
        self.assertIn("flag{abc}", self.F.find_flags("flag{abc}"))

    def test_malformed_toml_warns_without_crash(self):
        bad = os.path.join(self._tmp, "bad.toml")
        Path(bad).write_text("[flags\nprefixes = [", encoding="utf-8")
        self.F.reload_flag_config(bad)
        self.assertIn("flag{abc}", self.F.find_flags("flag{abc}"))
        warns = self.F.get_flag_config_warnings()
        self.assertTrue(any("malformed" in w.lower() for w in warns), warns)

    def test_duplicates_whitespace_regex_chars_safe(self):
        self.use_config(prefixes=["  DICT ", "dict", "A+B"])
        prefixes = self.F.known_prefixes()
        self.assertEqual(prefixes.count("DICT"), 1)
        self.assertIn("A+B{x}", self.F.find_flags("got A+B{x}"))
        # "A+B" is regex-escaped: it must not act as pattern "A+B" (no match
        # for "AAAB" via the configured prefix); generic fallback may still
        # list AAAB{x} as a lower-confidence candidate.
        c, _ = self.F.validate_flags("A+B{x}", source_kind="decoded")
        self.assertIn("A+B{x}", c)
        # AAAB{x} must only ever be the generic fallback, never confirmed
        # via the escaped "A+B" prefix.
        c2, cand2 = self.F.validate_flags("AAAB{x}", source_kind="decoded")
        self.assertEqual(c2, [])
        self.assertIn("AAAB{x}", cand2)

    def test_custom_patterns_match_non_brace_format(self):
        self.use_config(prefixes=[], patterns=["BSIT-2026-[A-F0-9]+"])
        self.assertIn("BSIT-2026-A8F91B", self.F.find_flags("leak BSIT-2026-A8F91B ok"))
        c, _ = self.F.validate_flags("BSIT-2026-A8F91B", source_kind="extracted")
        self.assertIn("BSIT-2026-A8F91B", c)

    def test_invalid_custom_pattern_does_not_break(self):
        self.use_config(prefixes=["DICT"], patterns=["([unclosed", "BSIT-2026-[A-F0-9]+"])
        self.assertIn("DICT{ok}", self.F.find_flags("DICT{ok}"))
        self.assertIn("BSIT-2026-A8F91B", self.F.find_flags("BSIT-2026-A8F91B"))
        warns = self.F.get_flag_config_warnings()
        self.assertTrue(any("invalid custom pattern" in w for w in warns), warns)

    def test_warnings_emitted_once_not_from_hot_path(self):
        bad = os.path.join(self._tmp, "bad2.toml")
        Path(bad).write_text("[flags\nprefixes = [", encoding="utf-8")
        self.F.reload_flag_config(bad)
        first = self.F.emit_flag_config_warnings_once()
        self.assertTrue(first)
        self.assertEqual(self.F.emit_flag_config_warnings_once(), [])
        # hot path: 1000 scoring calls stay silent and stable
        import contextlib
        from ctf_copilot.crypto.scoring import quality
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            for _ in range(1000):
                quality("some random text without flags")
        self.assertEqual(buf.getvalue(), "")


class DelegationTests(_ConfigMixin, unittest.TestCase):
    def test_no_local_flag_regex_outside_shared(self):
        import pathlib
        root = pathlib.Path(__file__).resolve().parent.parent / "ctf_copilot"
        offenders = []
        for p in root.rglob("*.py"):
            if p.name == "flags.py" and p.parent.name == "shared":
                continue
            try:
                text = p.read_text(encoding="utf-8")
            except OSError:
                continue
            if "re.compile" in text and ("picoCTF" in text or "HTB" in text):
                offenders.append(str(p))
        self.assertEqual(offenders, [], f"independent flag regex copies: {offenders}")

    def test_flags_scan_uses_config(self):
        self.use_config(prefixes=["DICT"])
        from ctf_copilot.flags.scanner import scan
        rows = scan("leak DICT{scan_ok} and XYZ{hi}", None)
        flags = [f for _, f in rows]
        self.assertIn("DICT{scan_ok}", flags)
        self.assertIn("XYZ{hi}", flags)  # generic fallback preserved

    def test_crypto_scoring_config_beats_generic(self):
        from ctf_copilot.crypto.scoring import has_known_flag, quality
        self.use_config(prefixes=["DICT"])
        self.assertTrue(has_known_flag("result DICT{winner}"))
        self.assertGreater(quality("DICT{winner}"), quality("XYZ{winner}"))

    def test_xor_result_detects_configured_flag(self):
        self.use_config(prefixes=["DICT"])
        from ctf_copilot.crypto.xor.engine import single
        plain = "DICT{xor_ok}"
        blob = bytes(b ^ 0x42 for b in plain.encode()).hex()
        rows = single(blob)
        self.assertTrue(rows)
        best = max(rows, key=lambda r: r.score)
        self.assertIn("DICT{xor_ok}", self.F.find_flags(best.plaintext))

    def test_rsa_plaintext_gate_confirms_configured(self):
        self.use_config(prefixes=["DICT"])
        c, _ = self.F.validate_flags("DICT{rsa_ok}", source_kind="decrypted")
        self.assertIn("DICT{rsa_ok}", c)

    def test_idor_comparison_catches_configured_flag(self):
        self.use_config(prefixes=["DICT"])
        from ctf_copilot.web.probes import idor

        class FakeResp:
            status = status_code = 200
            headers = {}
            text = ""
            history = []
            truncated = False
            ms = 1.0
            bytes = 0

            def __init__(self, url, text):
                self.url = url
                self.text = text

        bodies = {
            "http://example.test/item?id=1": "user one profile",
            "http://example.test/item?id=2": "user two DICT{other_user}",
        }

        class FakeSession:
            def __init__(self):
                self.ledger = []

            def can_fetch(self, url):
                return True

            def get(self, url, params=None, **kw):
                return FakeResp(url, bodies.get(url, "none"))

        rows = idor.probe("http://example.test/item?id=1", session=FakeSession())
        self.assertTrue(rows)
        self.assertIn("deterministic", rows[0].lower())
        self.assertIn("flag pattern", rows[0].lower())


class CategoryCoverageTests(_ConfigMixin, unittest.TestCase):
    def _tmp_file(self, suffix, data: bytes) -> str:
        fd, name = tempfile.mkstemp(suffix=suffix, dir=self._tmp)
        os.close(fd)
        Path(name).write_bytes(data)
        return name

    def test_forensics_triage_confirms_configured(self):
        self.use_config(prefixes=["DICT"])
        from ctf_copilot.forensics.pipeline import triage_file
        path = self._tmp_file(".txt", b"secret value DICT{forensic_ok} end")
        findings, _, _ = triage_file(path)
        all_flags = [f for x in findings for f in (x.flags or [])]
        self.assertIn("DICT{forensic_ok}", all_flags)

    def test_archive_recursion_confirms_configured(self):
        self.use_config(prefixes=["DICT"])
        from ctf_copilot.forensics.pipeline import triage_file
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as z:
            z.writestr("flag.txt", "DICT{nested_ok}")
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w") as z:
            z.writestr("inner.zip", inner.getvalue())
        path = self._tmp_file(".zip", outer.getvalue())
        findings, _, _ = triage_file(path)
        all_flags = [f for x in findings for f in (x.flags or [])]
        self.assertIn("DICT{nested_ok}", all_flags)

    def test_pcap_payload_path_uses_shared(self):
        self.use_config(prefixes=["DICT"])
        # pcap.summarize shells to tshark; the payload-flag gate is find_flags.
        self.assertIn("DICT{stream_ok}", self.F.find_flags("GET /download DICT{stream_ok}"))
        import ctf_copilot.forensics.pcap as pcap
        import inspect
        self.assertIn("find_flags", inspect.getsource(pcap))

    def test_web_response_uses_shared(self):
        self.use_config(prefixes=["DICT"])
        html = "<html><!-- note --><p>hello DICT{web_ok}</p></html>"
        self.assertIn("DICT{web_ok}", self.F.find_flags(html))

    def test_reverse_pwn_network_misc_use_shared(self):
        import inspect
        from ctf_copilot.reverse import strings as rstrings, triage as rtriage
        from ctf_copilot.pwn import triage as ptriage
        from ctf_copilot.network import commands as ncmd
        from ctf_copilot.misc import commands as mcmd
        for mod in (rstrings, rtriage, ptriage, ncmd, mcmd):
            self.assertIn("shared", inspect.getsource(mod),
                          f"{mod.__name__} must consume shared/flags")
        self.assertIn("DICT{rev_ok}", self.F.find_flags("strings dump DICT{rev_ok}"))

    def test_solve_direct_input_confirms_configured(self):
        self.use_config(prefixes=["DICT"])
        from ctf_copilot.solve import solve
        out = solve("DICT{direct_ok_123}")
        self.assertIn("flag-found", out)
        self.assertIn("DICT{direct_ok_123}", out)

    def test_solve_decode_chain_confirms_configured(self):
        self.use_config(prefixes=["DICT"])
        from ctf_copilot.solve import solve
        encoded = base64.b64encode(b"DICT{chain_ok_456}").decode()
        out = solve(encoded)
        self.assertIn("flag-found", out)
        self.assertIn("DICT{chain_ok_456}", out)

    def test_solve_workspace_report_contains_configured(self):
        self.use_config(prefixes=["DICT"])
        from ctf_copilot.solve import solve
        ws = os.path.join(self._tmp, "ws1")
        solve("DICT{workspace_ok_789}", workspace=ws)
        report = json.loads(Path(ws, "solve-report.json").read_text(encoding="utf-8"))
        blob = json.dumps(report)
        self.assertIn("DICT{workspace_ok_789}", blob)


if __name__ == "__main__":
    unittest.main()
