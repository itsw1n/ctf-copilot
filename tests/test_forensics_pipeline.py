"""Task 9 TDD tests: forensics pipeline + safe archives (offline)."""
from __future__ import annotations

import io
import os
import tempfile
import unittest
import zipfile
from pathlib import Path

from ctf_copilot.analysis.budget import AnalysisBudget


def _tmp_file(suffix: str, data: bytes) -> str:
    fd, name = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    Path(name).write_bytes(data)
    return name


class TestPipeline(unittest.TestCase):
    def test_magic_mismatch_detection(self):
        from ctf_copilot.forensics.pipeline import triage_file
        # PNG magic but .jpg extension
        data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64 + b"hello world"
        path = _tmp_file(".jpg", data)
        try:
            findings, artifacts, render = triage_file(path)
            blob = " ".join([f.observation + " " + f.why for f in findings]) + " " + render
            self.assertIn("mismatch", blob.lower())
        finally:
            os.unlink(path)

    def test_utf16_flag_found(self):
        from ctf_copilot.forensics.pipeline import triage_file
        flag = "flag{utf16_test_123}"
        data = "hello ".encode("utf-16le") + flag.encode("utf-16le")
        path = _tmp_file(".bin", data)
        try:
            findings, artifacts, render = triage_file(path)
            all_flags = []
            for f in findings:
                all_flags.extend(f.flags)
            self.assertIn(flag, all_flags + [render])
        finally:
            os.unlink(path)

    def test_appended_data_detected(self):
        from ctf_copilot.forensics.pipeline import triage_file
        png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("a.txt", b"hi")
        data = png + buf.getvalue()
        path = _tmp_file(".png", data)
        try:
            findings, artifacts, render = triage_file(path)
            blob = " ".join([f.observation + " " + f.why for f in findings]) + " " + render
            low = blob.lower()
            self.assertTrue("append" in low or "embed" in low or "zip" in low)
        finally:
            os.unlink(path)

    def test_nested_zip_recursion_finds_inner_flag(self):
        from ctf_copilot.forensics.pipeline import triage_file
        flag = "flag{nested_inner_456}"
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as z:
            z.writestr("flag.txt", flag)
        outer = io.BytesIO()
        with zipfile.ZipFile(outer, "w") as z:
            z.writestr("inner.zip", inner.getvalue())
        path = _tmp_file(".zip", outer.getvalue())
        try:
            findings, artifacts, render = triage_file(path)
            all_flags = []
            for f in findings:
                all_flags.extend(f.flags)
            self.assertIn(flag, all_flags + [render])
        finally:
            os.unlink(path)


class TestSafeArchives(unittest.TestCase):
    def _make_zip(self, entries: dict[str, bytes], encrypt_name: str | None = None) -> str:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            for name, data in entries.items():
                if encrypt_name and name == encrypt_name:
                    zi = zipfile.ZipInfo(name)
                    zi.flag_bits |= 0x1  # encrypted flag
                    z.writestr(zi, data)
                else:
                    z.writestr(name, data)
        fd, name = tempfile.mkstemp(suffix=".zip")
        os.close(fd)
        Path(name).write_bytes(buf.getvalue())
        return name

    def test_zipslip_rejected(self):
        from ctf_copilot.shared import archives as A
        path = self._make_zip({"../../evil.txt": b"evil", "ok.txt": b"ok"})
        outdir = tempfile.mkdtemp()
        try:
            # backward-compat extract must refuse traversal
            ok, msg = A.extract(path, outdir)
            self.assertFalse(ok)
            self.assertIn("travers", msg.lower() + "unsafe" + "reject")
            # ensure no escape file created next to archive parent
            self.assertFalse(Path(outdir, "evil.txt").exists())
        finally:
            os.unlink(path)

    def test_size_bomb_rejected(self):
        from ctf_copilot.shared import archives as A
        from ctf_copilot.analysis.budget import AnalysisBudget
        # normal small zip, but tiny budget override forces advertised-size rejection
        path = self._make_zip({"big.bin": b"A" * 5000})
        outdir = tempfile.mkdtemp()
        try:
            budget = AnalysisBudget.named("balanced")
            budget.max_file_bytes = 1024
            budget.max_total_bytes = 2048
            try:
                ok, msg = A.extract(path, outdir, budget=budget)
            except TypeError:
                ok, msg = A.extract(path, outdir)
            self.assertFalse(ok)
            low = msg.lower()
            self.assertTrue("size" in low or "bomb" in low or "large" in low or "exceed" in low or "limit" in low)
        finally:
            os.unlink(path)

    def _make_encrypted_zip(self, name: str, data: bytes) -> str:
        import re
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr(name, data)
        raw = bytearray(buf.getvalue())
        for m in re.finditer(b"PK\x03\x04", bytes(raw)):
            raw[m.start() + 6] |= 0x01
        for m in re.finditer(b"PK\x01\x02", bytes(raw)):
            raw[m.start() + 8] |= 0x01
        fd, path = tempfile.mkstemp(suffix=".zip")
        os.close(fd)
        Path(path).write_bytes(bytes(raw))
        return path

    def test_encrypted_reports_without_extraction(self):
        from ctf_copilot.shared import archives as A
        path = self._make_encrypted_zip("secret.txt", b"flag{enc}")
        outdir = tempfile.mkdtemp()
        try:
            self.assertNotEqual(A.detect_crypto(path), "none")
            entries = A.list_entries(path)
            # stdlib path must report encryption even without 7z
            self.assertTrue(entries and any(e.get("encrypted") for e in entries))
            ok, msg = A.extract(path, outdir)
            self.assertFalse(ok)
            self.assertIn("encrypt", msg.lower() + "password")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
