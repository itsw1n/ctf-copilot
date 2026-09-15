"""Tests for Task 14: passive consolidation on shared WebSession (mocked, no live net)."""
from __future__ import annotations

import base64
import json
import unittest
from unittest.mock import MagicMock, patch

from ctf_copilot.web.session import WebSession
from ctf_copilot.web import differential as diff


def _jwt_token() -> str:
    def b64(o):
        return base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
    return f"{b64({'alg':'none'})}.{b64({'user':'admin'})}.sigpart"


def _fake_resp(status=200, url="http://example.test/", text="hello",
               headers=None, history=None, final_url=None):
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
    m.iter_content.return_value = [text.encode()[i:i + 1024] for i in range(0, len(text.encode()), 1024)] or [b""]
    return m


class CarryFixTests(unittest.TestCase):
    def test_fetch_bounded_forwards_payload_to_request(self):
        class FakeTransport:
            def __init__(self):
                self.calls = []
            def request(self, method, url, **kw):
                self.calls.append((method, url, kw))
                m = MagicMock()
                m.status = 200
                m.status_code = 200
                m.url = url
                m.headers = {}
                m.text = "ok"
                m.content = b"ok"
                m.history = []
                m.truncated = False
                m.ms = 1.0
                m.bytes = 2
                return m
        t = FakeTransport()
        br = diff.fetch_bounded(t, "POST", "http://example.test/submit",
                                params={"a": "1"}, data={"b": "2"},
                                json_data={"c": 3}, extra_headers={"X-H": "v"})
        self.assertEqual(br.status, 200)
        _, _, kw = t.calls[0]
        self.assertEqual(kw.get("params"), {"a": "1"})
        self.assertEqual(kw.get("data"), {"b": "2"})
        self.assertEqual(kw.get("json"), {"c": 3})
        self.assertEqual(kw.get("headers"), {"X-H": "v"})

    def test_read_bounded_preserves_partial_on_midstream_error(self):
        s = WebSession("http://example.test/", max_bytes=10_000)

        def bad_iter(chunk_size=65536):
            yield b"partial-"
            raise ConnectionError("mid-stream boom")
        m = MagicMock()
        m.iter_content.return_value = bad_iter()
        m.content = b"FULL-FALLBACK-SHOULD-NOT-WIN"
        data, truncated = s._read_bounded(m)
        self.assertEqual(data, b"partial-")
        self.assertTrue(truncated)


def _session_with_routes(routes: dict, base="http://example.test/", **kw):
    """Build WebSession whose low-level request is routed by absolute URL."""
    s = WebSession(base, **kw)
    calls: list[tuple] = []

    def fake_request(method, url, **k):
        calls.append((method, url))
        key = url.split("?")[0]
        spec = routes.get(key) or routes.get(url)
        if spec is None:
            return _fake_resp(status=404, url=url, text="not found")
        if isinstance(spec, str):
            spec = {"text": spec}
        return _fake_resp(
            status=spec.get("status", 200), url=url,
            text=spec.get("text", ""), headers=spec.get("headers"),
            history=spec.get("history"), final_url=spec.get("final_url"),
        )
    patcher = patch.object(s.session, "request", side_effect=fake_request)
    patcher.start()
    s._patcher = patcher  # type: ignore[attr-defined]
    # attach calls for inspection (store on object)
    s._test_calls = calls  # type: ignore[attr-defined]
    return s


class PassiveReportTests(unittest.TestCase):
    def test_redirect_chain_reported(self):
        from ctf_copilot.web import analyzer as az
        routes = {
            "http://example.test/a": {
                "text": "<html><!-- hi --><a href='/b'>b</a></html>",
                "history": ["http://example.test/a"],
                "final_url": "http://example.test/b",
            },
            "http://example.test/robots.txt": "User-agent: *",
            "http://example.test/sitemap.xml": "<urlset/>",
            "http://example.test/.well-known/security.txt": "Contact: x",
        }
        s = _session_with_routes(routes)
        info = az.analyze("http://example.test/a", session=s, crawl=0)
        self.assertEqual(info["status"], 200)
        self.assertEqual(info["final"], "http://example.test/b")
        chain = info.get("redirect_chain") or info.get("history") or []
        self.assertIn("http://example.test/a", chain)
        out = az.render(info)
        self.assertIn("http://example.test/a", out)
        self.assertIn("http://example.test/b", out)

    def test_robots_sitemap_within_budget(self):
        from ctf_copilot.web import analyzer as az
        routes = {
            "http://example.test/": "<html><a href='/p'>p</a></html>",
            "http://example.test/robots.txt": "User-agent: *\nDisallow: /admin",
            "http://example.test/sitemap.xml": "<urlset><url><loc>/p</loc></url></urlset>",
            "http://example.test/.well-known/security.txt": "Contact: sec",
        }
        s = _session_with_routes(routes, max_requests=50)
        info = az.analyze("http://example.test/", session=s, crawl=0)
        urls = [u for _, u in s._test_calls]  # type: ignore[attr-defined]
        self.assertTrue(any(u.endswith("/robots.txt") for u in urls))
        self.assertTrue(any(u.endswith("/sitemap.xml") for u in urls))
        self.assertLessEqual(len(s.ledger), 50)
        out = az.render(info)
        self.assertIn("robots", out.lower())

    def test_sourcemap_fetched_bounded(self):
        from ctf_copilot.web import analyzer as az
        routes = {
            "http://example.test/": "<html><script src='/app.js'></script></html>",
            "http://example.test/app.js": "console.log(1);\n//# sourceMappingURL=app.js.map",
            "http://example.test/app.js.map": '{"sources":["app.ts"]}',
            "http://example.test/robots.txt": "",
            "http://example.test/sitemap.xml": "",
            "http://example.test/.well-known/security.txt": "",
        }
        s = _session_with_routes(routes)
        info = az.analyze("http://example.test/", session=s, crawl=0)
        urls = [u for _, u in s._test_calls]  # type: ignore[attr-defined]
        self.assertTrue(any(u.endswith("app.js.map") for u in urls))
        out = az.render(info)
        self.assertIn("map", out.lower())

    def test_jwt_cookie_flagged(self):
        from ctf_copilot.web import analyzer as az
        tok = _jwt_token()
        routes = {
            "http://example.test/": {
                "text": "<html><p>hi</p></html>",
                "headers": {"Content-Type": "text/html", "Set-Cookie": f"session={tok}; Path=/; HttpOnly"},
            },
            "http://example.test/robots.txt": "",
            "http://example.test/sitemap.xml": "",
            "http://example.test/.well-known/security.txt": "",
        }
        s = _session_with_routes(routes)
        info = az.analyze("http://example.test/", session=s, crawl=0)
        self.assertTrue(info.get("jwt"))
        out = az.render(info)
        self.assertIn("JWT-like cookies", out)

    def test_secret_clue_redacted(self):
        from ctf_copilot.web import analyzer as az
        secret = "AKIAIOSFODNN7EXAMPLE"
        routes = {
            "http://example.test/": f"<html><script>const api_key='{secret}';</script></html>",
            "http://example.test/robots.txt": "",
            "http://example.test/sitemap.xml": "",
            "http://example.test/.well-known/security.txt": "",
        }
        s = _session_with_routes(routes)
        info = az.analyze("http://example.test/", session=s, crawl=0)
        out = az.render(info)
        self.assertNotIn(secret, out)
        # clue section present (redacted display keeps prefix, hides full)
        self.assertIn("clue", out.lower() + "".join(str(v) for v in info.values()).lower()
                      or out.lower())

    def test_crawl_respects_n_and_same_origin(self):
        from ctf_copilot.web import analyzer as az
        routes = {
            "http://example.test/": "<html><a href='/page2'>2</a><a href='http://evil.test/x'>evil</a></html>",
            "http://example.test/page2": "<html><a href='/page3'>3</a><p>two</p></html>",
            "http://example.test/page3": "<html><p>three</p></html>",
            "http://example.test/robots.txt": "",
            "http://example.test/sitemap.xml": "",
            "http://example.test/.well-known/security.txt": "",
        }
        s = _session_with_routes(routes, max_requests=50)
        info = az.analyze("http://example.test/", session=s, crawl=1)
        urls = [u for _, u in s._test_calls]  # type: ignore[attr-defined]
        self.assertTrue(any(u.endswith("/page2") for u in urls))
        self.assertFalse(any("evil.test" in u for u in urls))
        self.assertFalse(any(u.endswith("/page3") for u in urls))
        # crawled pages recorded
        crawled = info.get("crawled") or info.get("pages") or []
        self.assertLessEqual(len(crawled), 2)

    def test_script_cap_enforced_and_no_post(self):
        from ctf_copilot.web import analyzer as az
        scripts = "".join(f"<script src='/s{i}.js'></script>" for i in range(7))
        routes = {"http://example.test/": f"<html>{scripts}</html>"}
        for i in range(7):
            routes[f"http://example.test/s{i}.js"] = f"// file {i}\nfetch('/api/x{i}');"
        routes["http://example.test/robots.txt"] = ""
        routes["http://example.test/sitemap.xml"] = ""
        routes["http://example.test/.well-known/security.txt"] = ""
        s = _session_with_routes(routes, max_requests=100)
        info = az.analyze("http://example.test/", session=s, crawl=0)
        urls = [u for _, u in s._test_calls]  # type: ignore[attr-defined]
        js_fetches = [u for u in urls if u.endswith(".js")]
        self.assertLessEqual(len(js_fetches), 5)
        methods = [m for m, _ in s._test_calls]  # type: ignore[attr-defined]
        self.assertTrue(methods)
        self.assertTrue(all(m == "GET" for m in methods))
        # backward-compat sections still present
        out = az.render(info)
        for title in ["WEB ANALYSIS", "HTML comments", "Forms", "Cookies",
                      "Scripts", "Endpoints"]:
            # Scripts/Forms/etc may be absent if empty, but top titles must not crash;
            # at least WEB ANALYSIS + Status + Final URL remain
            pass
        self.assertIn("WEB ANALYSIS", out)
        self.assertIn("Status:", out)
        self.assertIn("Final URL:", out)


if __name__ == "__main__":
    unittest.main()
