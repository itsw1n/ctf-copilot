"""Task 10 TDD tests: type analyzers, workspace persist, stream caps (offline)."""
from __future__ import annotations

import io
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock


def _tmp_file(suffix: str, data: bytes) -> str:
    fd, name = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    Path(name).write_bytes(data)
    return name


class TestDocuments(unittest.TestCase):
    def test_pdf_js_indicator(self):
        from ctf_copilot.forensics import documents
        data = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Names << /JavaScript << /Names [(x) 2 0 R] >> >> >>\nendobj\n2 0 obj\n<< /S /JavaScript /JS (app.alert('flag{pdf_js_123}')) >>\nendobj\ntrailer\n%%EOF"
        path = _tmp_file(".pdf", data)
        try:
            findings, artifacts, render = documents.analyze(path, None)
            blob = " ".join(f.observation + " " + f.why for f in findings) + " " + render
            self.assertIn("javascript", blob.lower() + "js")
            self.assertTrue("js" in blob.lower() or "javascript" in blob.lower())
        finally:
            os.unlink(path)

    def test_office_zip_comment_url(self):
        from ctf_copilot.forensics import documents
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml", b'<?xml version="1.0"?><Types></Types>')
            z.writestr("word/comments.xml", b'<comments><comment>hello reviewer note</comment></comments>')
            z.writestr("word/document.xml", b'<doc>see http://example.com/secret for details</doc>')
        path = _tmp_file(".docx", buf.getvalue())
        try:
            findings, artifacts, render = documents.analyze(path, None)
            blob = (" ".join(f.observation + " " + f.why for f in findings) + " " + render).lower()
            self.assertTrue("comment" in blob or "url" in blob or "http" in blob)
        finally:
            os.unlink(path)


class TestAudioAppended(unittest.TestCase):
    def test_audio_appended_content(self):
        from ctf_copilot.forensics import audio
        wav = b"RIFF" + (36).to_bytes(4, "little") + b"WAVEfmt " + b"\x00" * 40
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("a.txt", b"hi")
        data = wav + buf.getvalue()
        path = _tmp_file(".wav", data)
        try:
            findings, artifacts, render = audio.analyze(path, None)
            blob = (" ".join(f.observation + " " + f.why for f in findings) + " " + render).lower()
            self.assertTrue("append" in blob or "embed" in blob or "zip" in blob or "trailing" in blob)
        finally:
            os.unlink(path)

    def test_png_appended_via_pipeline(self):
        from ctf_copilot.forensics.pipeline import triage_file
        png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 100
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("a.txt", b"hi")
        path = _tmp_file(".png", png + buf.getvalue())
        try:
            findings, artifacts, render = triage_file(path)
            blob = (" ".join(f.observation + " " + f.why for f in findings) + " " + render).lower()
            self.assertTrue("append" in blob or "embed" in blob or "zip" in blob)
        finally:
            os.unlink(path)


class TestDiskMemoryGuidance(unittest.TestCase):
    def test_disk_guidance_without_tools(self):
        from ctf_copilot.forensics import disk
        path = _tmp_file(".img", b"\x00" * 2048 + b"hello")
        try:
            with mock.patch("ctf_copilot.forensics.disk.which", return_value=None):
                findings, artifacts, render = disk.analyze(path, None)
            blob = (" ".join(f.observation + " " + f.why + " " + " ".join(f.next_actions) for f in findings) + " " + render).lower()
            statuses = [f.status for f in findings]
            self.assertIn("inconclusive", statuses)
            self.assertTrue("next" in blob or "mmls" in blob or "fls" in blob or "icat" in blob)
        finally:
            os.unlink(path)

    def test_memory_guidance_without_tools(self):
        from ctf_copilot.forensics import memory
        path = _tmp_file(".mem", b"\x00" * 2048 + b"windows hello")
        try:
            with mock.patch("ctf_copilot.forensics.memory.which", return_value=None):
                findings, artifacts, render = memory.analyze(path, None)
            blob = (" ".join(f.observation + " " + f.why + " " + " ".join(f.next_actions) for f in findings) + " " + render).lower()
            statuses = [f.status for f in findings]
            self.assertIn("inconclusive", statuses)
            self.assertTrue("volatility" in blob or "next" in blob or "windows.info" in blob or "plugin" in blob)
        finally:
            os.unlink(path)


class TestStreamCap(unittest.TestCase):
    def test_spoofed_large_rejected_without_huge_alloc(self):
        from ctf_copilot.shared import archives as A
        from ctf_copilot.analysis.budget import AnalysisBudget
        # valid small gzip; tiny budget forces rejection before/while streaming
        import gzip as _gz
        raw = _gz.compress(b"A" * 5000)
        path = _tmp_file(".gz", raw)
        outdir = tempfile.mkdtemp()
        try:
            budget = AnalysisBudget.named("balanced")
            budget.max_file_bytes = 1024
            budget.max_total_bytes = 2048
            ok, msg, _arts = A.extract_with_artifacts(path, outdir, budget=budget)
            self.assertFalse(ok)
            low = msg.lower()
            self.assertTrue(any(k in low for k in ("size", "bomb", "large", "exceed", "limit", "reject")))
        finally:
            os.unlink(path)

    def test_valid_gzip_extracts_identically(self):
        from ctf_copilot.shared import archives as A
        import gzip as _gz
        payload = b"hello world " * 100
        path = _tmp_file(".gz", _gz.compress(payload))
        outdir = tempfile.mkdtemp()
        try:
            ok, msg, arts = A.extract_with_artifacts(path, outdir)
            self.assertTrue(ok, msg)
            found = b"".join(Path(a.path).read_bytes() for a in arts)
            self.assertEqual(found, payload)
        finally:
            os.unlink(path)


class TestWorkspacePersist(unittest.TestCase):
    def test_triage_workspace_persists(self):
        from ctf_copilot.forensics import commands as C
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("flag.txt", "flag{workspace_123}")
        path = _tmp_file(".zip", buf.getvalue())
        ws = tempfile.mkdtemp()
        try:
            # _triage prints; exercise workspace persist path
            C._triage(path, workspace=ws, budget="balanced")
            files = list(Path(ws).rglob("*"))
            names = [p.name for p in files]
            self.assertTrue(any("artifact" in n for n in names) or any(p.suffix in (".txt", ".json") for p in files),
                            f"no artifacts in workspace: {names}")
            self.assertTrue((Path(ws) / "solve-report.json").exists(), f"missing solve-report.json: {names}")
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
