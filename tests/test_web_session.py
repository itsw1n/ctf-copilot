"""Tests for Task 13: WebSession + differential engine (mocked transport, no live HTTP)."""
from __future__ import annotations

import types
import unittest
from unittest.mock import MagicMock, patch

from ctf_copilot.web.session import (
    WebSession,
    parse_header,
    parse_cookie,
)
from ctf_copilot.web import differential as diff


def _fake_resp(status=200, url="http://example.test/", text="hello", headers=None, history=None, final_url=None):
    m = MagicMock()
    m.status_code = status
    m.url = final_url or url
    m.headers = headers or {"Content-Type": "text/html"}
    m.history = []
    for h_url in (history or []):
        h = MagicMock()
        h.url = h_url
        h.status_code = 302
        m.history.append(h)
    m.text = text
    m.content = text.encode()
    # streaming interface
    m.iter_content.return_value = [text.encode()[i:i + 1024] for i in range(0, len(text.encode()), 1024)] or [b""]
    return m


class SessionTests(unittest.TestCase):
    def _session(self, **kw):
        kw.setdefault("base_url", "http://example.test/")
        kw.setdefault("max_requests", 100)
        return WebSession(**kw)

    def test_header_cookie_parsing(self):
        self.assertEqual(parse_header("X-Api: 123"), ("X-Api", "123"))
        self.assertEqual(parse_header("Authorization:Bearer abc"), ("Authorization", "Bearer abc"))
        self.assertEqual(parse_cookie("session=abc123"), ("session", "abc123"))
        self.assertEqual(parse_cookie("a=b=c"), ("a", "b=c"))

    def test_cookie_persistence(self):
        s = self._session(cookies={"sid": "1"})
        self.assertIn("sid", s.session.cookies)
        # second: cookies set via constructor persist; also ensure session object reused
        with patch.object(s.session, "request", return_value=_fake_resp()) as req:
            s.get("/")
            s.get("/other")
            self.assertEqual(req.call_count, 2)
        self.assertEqual(s.session.cookies.get("sid"), "1")

    def test_same_origin_block(self):
        s = self._session()
        self.assertTrue(s.can_fetch("http://example.test/page"))
        self.assertTrue(s.can_fetch("/relative"))
        self.assertFalse(s.can_fetch("http://evil.test/steal"))
        with self.assertRaises(ValueError):
            s.get("http://evil.test/steal")

    def test_size_cap_truncation(self):
        s = self._session(max_bytes=10)
        big = "A" * 5000
        with patch.object(s.session, "request", return_value=_fake_resp(text=big)):
            r = s.get("/")
            self.assertTrue(r.truncated)
            self.assertLessEqual(len(r.content), 10 + 1024)  # chunk granularity allowed, but must be capped
            self.assertLessEqual(r.bytes, 10 + 1024)

    def test_redirect_history(self):
        s = self._session()
        resp = _fake_resp(url="http://example.test/a", final_url="http://example.test/b",
                           history=["http://example.test/a"], text="ok")
        with patch.object(s.session, "request", return_value=resp):
            r = s.get("/a")
            self.assertEqual(r.final_url, "http://example.test/b")
            self.assertIn("http://example.test/a", r.history)

    def test_ledger_and_max_requests(self):
        s = self._session(max_requests=2)
        with patch.object(s.session, "request", return_value=_fake_resp()):
            s.get("/1")
            s.get("/2")
            self.assertEqual(len(s.ledger), 2)
            for row in s.ledger:
                for k in ("method", "url", "status", "bytes", "ms"):
                    self.assertIn(k, row)
            with self.assertRaises(RuntimeError):
                s.get("/3")

    def test_budget_increment(self):
        budget = {"requests": 0}
        s = self._session(budget=budget)
        with patch.object(s.session, "request", return_value=_fake_resp()):
            s.get("/1")
            self.assertEqual(budget["requests"], 1)
        # object-style budget
        ns = types.SimpleNamespace(requests=0)
        s2 = self._session(budget=ns)
        with patch.object(s2.session, "request", return_value=_fake_resp()):
            s2.get("/1")
            self.assertEqual(ns.requests, 1)

    def test_csrf_merge(self):
        s = self._session()
        form_html = '<form><input type="hidden" name="csrf_token" value="TOK123"></form>'
        posted = {}

        def fake_request(method, url, **kw):
            if method == "GET":
                return _fake_resp(text=form_html, url=url)
            posted.update(kw.get("data") or {})
            return _fake_resp(text="ok", url=url)

        with patch.object(s.session, "request", side_effect=fake_request):
            r = s.post_form("/submit", {"user": "a"})
            self.assertEqual(posted.get("csrf_token"), "TOK123")
            self.assertEqual(posted.get("user"), "a")
            self.assertFalse(r.truncated)

    def test_csrf_explicit_wins(self):
        s = self._session()
        form_html = '<input type="hidden" name="csrf_token" value="SERVER">'
        posted = {}

        def fake_request(method, url, **kw):
            if method == "GET":
                return _fake_resp(text=form_html, url=url)
            posted.update(kw.get("data") or {})
            return _fake_resp(text="ok", url=url)

        with patch.object(s.session, "request", side_effect=fake_request):
            s.post_form("/submit", {"csrf_token": "MINE"})
            self.assertEqual(posted.get("csrf_token"), "MINE")

    def test_sanitization_redacts_secrets(self):
        s = self._session(headers={"Authorization": "Bearer supersecret12345", "X-Ok": "fine"},
                          cookies={"session": "verysecret"})
        red = s.sanitized_headers()
        blob = " ".join(red.values())
        self.assertNotIn("supersecret12345", blob)
        self.assertNotIn("verysecret", blob)
        self.assertIn("fine", blob)
        # prefix retained
        auth = red.get("Authorization", "")
        self.assertTrue(auth.startswith("Bear") or "***" in auth)


class DifferentialTests(unittest.TestCase):
    def _resp(self, **kw):
        base = dict(status=200, url="http://example.test/?q=1", final_url="http://example.test/?q=1",
                    headers={"content-type": "text/html"}, title="Hello",
                    body_text="hello world", body_len=11, ms=5.0)
        base.update(kw)
        return diff.BoundedResponse(**base)

    def test_compare_status_len_title_redirect(self):
        a = self._resp()
        b = self._resp(status=500, body_text="x" * 100, body_len=100, title="Error", final_url="http://example.test/err")
        out = diff.compare(a, b)
        self.assertTrue(out["status_changed"])
        self.assertEqual(out["len_delta"], 89)
        self.assertTrue(out["title_changed"])
        self.assertTrue(out["redirect_changed"])
        self.assertLess(out["similarity"], 0.5)

    def test_error_signatures(self):
        a = self._resp(body_text="normal page", body_len=11)
        b = self._resp(body_text="You have an error in your SQL syntax near 'x'; mysql said hi", body_len=60)
        out = diff.compare(a, b)
        joined = " ".join(out["error_signatures"]).lower()
        self.assertIn("sql", joined)

    def test_reflection_marker(self):
        a = self._resp(body_text="hello", body_len=5)
        b = self._resp(body_text="hello MARKER_XYZ", body_len=16)
        out = diff.compare(a, b, reflection_marker="MARKER_XYZ")
        self.assertIn("MARKER_XYZ", " ".join(out["error_signatures"] + out.get("keywords_present", [])) + str(out))

    def test_normalizes_csrf_noise(self):
        t1 = '<input type="hidden" name="csrf_token" value="abcdef0123456789abcdef"> hello 2026-09-15 nonce="zz"'
        t2 = '<input type="hidden" name="csrf_token" value="999999ffffffffff000000"> hello 2025-01-02 nonce="qq"'
        a = self._resp(body_text=t1, body_len=len(t1))
        b = self._resp(body_text=t2, body_len=len(t2))
        out = diff.compare(a, b)
        self.assertGreater(out["similarity"], 0.9)

    def test_header_diffs(self):
        a = self._resp(headers={"content-type": "text/html", "server": "nginx"})
        b = self._resp(headers={"content-type": "text/html", "server": "apache"})
        out = diff.compare(a, b)
        self.assertIn("server", out["header_diffs"])

    def test_timing_opt_in(self):
        a = self._resp(ms=5.0)
        b = self._resp(ms=500.0)
        out = diff.compare(a, b)
        self.assertNotIn("timing_ms", out)
        out2 = diff.compare(a, b, include_timing=True)
        self.assertIn("timing_ms", out2)

    def test_fetch_bounded_uses_session(self):
        s = WebSession("http://example.test/")
        html = "<html><head><title>Hi</title></head><body>body here</body></html>"
        with patch.object(s.session, "request", return_value=_fake_resp(text=html)):
            br = diff.fetch_bounded(s, "GET", "/page")
            self.assertEqual(br.status, 200)
            self.assertEqual(br.title, "Hi")
            self.assertIn("body here", br.body_text)
            self.assertEqual(br.url, "http://example.test/page")


if __name__ == "__main__":
    unittest.main()
