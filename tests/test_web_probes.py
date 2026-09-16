"""Tests for Task 15: authorized bounded probes (mocked, no live net)."""
from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from ctf_copilot.web.session import WebSession


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


def _session_with_routes(routes: dict, base="http://example.test/", **kw):
    s = WebSession(base, **kw)
    calls: list[tuple] = []

    def fake_request(method, url, **k):
        calls.append((method, url))
        key = url.split("?")[0]
        # exact match first, then base-path match
        spec = routes.get(url)
        if spec is None:
            # try matching without query ordering issues: exact url or path
            spec = routes.get(key)
        if spec is None:
            # prefix fallback for query variants: find route whose base matches
            return _fake_resp(status=404, url=url, text="not found")
        if isinstance(spec, str):
            spec = {"text": spec}
        if callable(spec):
            return spec(method, url, k)
        return _fake_resp(
            status=spec.get("status", 200), url=url,
            text=spec.get("text", ""), headers=spec.get("headers"),
            history=spec.get("history"), final_url=spec.get("final_url"),
        )
    patcher = patch.object(s.session, "request", side_effect=fake_request)
    patcher.start()
    s._patcher = patcher  # type: ignore[attr-defined]
    s._test_calls = calls  # type: ignore[attr-defined]
    return s


def _stop(self):
    try:
        self._patcher.stop()  # type: ignore[attr-defined]
    except Exception:
        pass


class IdorTests(unittest.TestCase):
    def tearDown(self):
        pass

    def test_marker_deterministic(self):
        from ctf_copilot.web.probes import idor
        base = "http://example.test/item?id=1"
        routes = {
            "http://example.test/item": lambda m, u, k: _fake_resp(
                url=u, text="user alice alice@example.com" if "id=1" in u else "user bob bob@example.com"),
        }
        s = _session_with_routes(routes)
        try:
            rows = idor.probe(base, session=s)
        finally:
            _stop(s)
        blob = "\n".join(rows).lower()
        self.assertTrue(rows)
        self.assertIn("deterministic", blob)

    def test_clean_negative_no_false_prove(self):
        from ctf_copilot.web.probes import idor
        routes = {
            "http://example.test/item": {"text": "same user profile page"},
        }
        s = _session_with_routes(routes)
        try:
            rows = idor.probe("http://example.test/item?id=1", session=s)
        finally:
            _stop(s)
        blob = "\n".join(rows).lower()
        self.assertNotIn("deterministic", blob)
        self.assertNotIn("proved", blob)
        self.assertTrue("candidate" in blob or "inconclusive" in blob or "no " in blob)


class TraversalTests(unittest.TestCase):
    def test_marker_deterministic(self):
        from ctf_copilot.web.probes import traversal
        def route(m, u, k):
            if "etc%2fpasswd" in u.lower() or "etc/passwd" in u:
                return _fake_resp(url=u, text="root:x:0:0:root:/root:/bin/bash")
            return _fake_resp(url=u, text="normal page")
        s = _session_with_routes({"http://example.test/view": route})
        try:
            rows = traversal.probe("http://example.test/view?file=home", session=s)
        finally:
            _stop(s)
        self.assertIn("deterministic", "\n".join(rows).lower())

    def test_clean_negative(self):
        from ctf_copilot.web.probes import traversal
        s = _session_with_routes({"http://example.test/view": {"text": "normal page"}})
        try:
            rows = traversal.probe("http://example.test/view?file=home", session=s)
        finally:
            _stop(s)
        blob = "\n".join(rows).lower()
        self.assertNotIn("deterministic", blob)
        self.assertTrue("candidate" in blob or "inconclusive" in blob or "no " in blob)


class SstiTests(unittest.TestCase):
    def test_marker_deterministic(self):
        from ctf_copilot.web.probes import ssti
        def route(m, u, k):
            if "7%2A7" in u or "7*7" in u or "%7B%7B" in u.upper() or "{{" in u:
                return _fake_resp(url=u, text="hello 49 world")
            return _fake_resp(url=u, text="hello name world")
        s = _session_with_routes({"http://example.test/greet": route})
        try:
            rows = ssti.probe("http://example.test/greet?name=hello", session=s)
        finally:
            _stop(s)
        self.assertIn("deterministic", "\n".join(rows).lower())

    def test_clean_negative(self):
        from ctf_copilot.web.probes import ssti
        s = _session_with_routes({"http://example.test/greet": {"text": "hello name world"}})
        try:
            rows = ssti.probe("http://example.test/greet?name=hello", session=s)
        finally:
            _stop(s)
        blob = "\n".join(rows).lower()
        self.assertNotIn("deterministic", blob)
        self.assertTrue("candidate" in blob or "inconclusive" in blob or "no " in blob)


class CommandTests(unittest.TestCase):
    def test_marker_candidate_only(self):
        from ctf_copilot.web.probes import command
        def route(m, u, k):
            if "%3Bid" in u or ";id" in u or "%7C" in u:
                return _fake_resp(url=u, text="uid=0(root) gid=0(root)")
            return _fake_resp(url=u, text="pong ok")
        s = _session_with_routes({"http://example.test/ping": route})
        try:
            rows = command.probe("http://example.test/ping?ip=127.0.0.1", session=s)
        finally:
            _stop(s)
        blob = "\n".join(rows).lower()
        self.assertIn("candidate", blob)
        self.assertNotIn("deterministic", blob)
        self.assertNotIn("proved", blob)

    def test_clean_negative(self):
        from ctf_copilot.web.probes import command
        s = _session_with_routes({"http://example.test/ping": {"text": "pong ok"}})
        try:
            rows = command.probe("http://example.test/ping?ip=127.0.0.1", session=s)
        finally:
            _stop(s)
        blob = "\n".join(rows).lower()
        self.assertNotIn("deterministic", blob)


class RedirectTests(unittest.TestCase):
    def test_cross_host_deterministic(self):
        from ctf_copilot.web.probes import redirect
        def route(m, u, k):
            if "evil.example" in u:
                return _fake_resp(url=u, final_url="https://evil.example/phish",
                                  headers={"Location": "https://evil.example/phish"},
                                  text="redirect")
            return _fake_resp(url=u, text="home")
        s = _session_with_routes({"http://example.test/go": route})
        try:
            rows = redirect.probe("http://example.test/go?next=/home", session=s)
        finally:
            _stop(s)
        self.assertIn("deterministic", "\n".join(rows).lower())

    def test_clean_negative(self):
        from ctf_copilot.web.probes import redirect
        s = _session_with_routes({"http://example.test/go": {"text": "home"}})
        try:
            rows = redirect.probe("http://example.test/go?next=/home", session=s)
        finally:
            _stop(s)
        blob = "\n".join(rows).lower()
        self.assertNotIn("deterministic", blob)


class SqliXssRefactorTests(unittest.TestCase):
    def test_sqli_uses_differential_and_session(self):
        from ctf_copilot.web.probes import sqli
        import inspect
        src = inspect.getsource(sqli)
        self.assertIn("compare", src)
        self.assertIn("WebSession", src + inspect.getsource(sqli.probe) if "WebSession" not in src else src)
        self.assertNotIn("urllib", src)
        # behavior: marker case reports indicator, clean does not prove
        def route(m, u, k):
            if "'" in u:
                return _fake_resp(url=u, status=500, text="You have an error in your SQL syntax near")
            return _fake_resp(url=u, text="normal page")
        s = _session_with_routes({"http://example.test/search": route})
        try:
            rows = sqli.probe("http://example.test/search?q=hi", session=s)
        finally:
            _stop(s)
        self.assertTrue(any("sql" in r.lower() or "candidate" in r.lower() or "indicator" in r.lower() for r in rows))

    def test_xss_uses_differential_and_session(self):
        from ctf_copilot.web.probes import xss
        import inspect
        src = inspect.getsource(xss)
        self.assertIn("compare", src)
        self.assertNotIn("urllib", src)
        marker_rows = None
        s = _session_with_routes({"http://example.test/s": lambda m, u, k: _fake_resp(url=u, text="echo CTFCP_XSS probe" if "CTFCP" in u else "echo hi")})
        try:
            marker_rows = xss.probe("http://example.test/s?q=hi", session=s)
        finally:
            _stop(s)
        self.assertTrue(any("reflect" in r.lower() or "candidate" in r.lower() for r in marker_rows))

    def test_methods_no_put_delete(self):
        from ctf_copilot.web.probes import methods
        import inspect
        src = inspect.getsource(methods)
        self.assertNotIn('"PUT"', src)
        self.assertNotIn("'PUT'", src)
        self.assertNotIn('"DELETE"', src)
        self.assertNotIn("'DELETE'", src)
        self.assertNotIn("urllib", src)
        s = _session_with_routes({"http://example.test/": {"text": "ok"}})
        try:
            rows = methods.probe("http://example.test/", session=s)
        finally:
            _stop(s)
        blob = "\n".join(rows)
        self.assertNotIn("PUT", blob)
        self.assertNotIn("DELETE", blob)
        methods_used = [m for m, _ in s._test_calls]  # type: ignore[attr-defined]
        self.assertNotIn("PUT", methods_used)
        self.assertNotIn("DELETE", methods_used)


class DifferentialGuardTests(unittest.TestCase):
    def test_fetch_bounded_rejects_put(self):
        from ctf_copilot.web import differential as diff
        from unittest.mock import MagicMock
        s = MagicMock()
        with self.assertRaises(ValueError):
            diff.fetch_bounded(s, "PUT", "http://example.test/")

    def test_methods_routes_through_differential(self):
        from ctf_copilot.web.probes import methods
        import inspect
        src = inspect.getsource(methods)
        self.assertIn("fetch_bounded", src)
        self.assertIn("compare", src)
        self.assertNotIn("session.get", src)
        self.assertNotIn("session.head", src)
        self.assertNotIn("session.options", src)

    def test_redirect_routes_through_differential(self):
        from ctf_copilot.web.probes import redirect
        import inspect
        src = inspect.getsource(redirect)
        self.assertIn("fetch_bounded", src)
        self.assertIn("compare", src)
        self.assertNotIn("session.get", src)

    def test_gobuster_handoffs_present(self):
        from ctf_copilot.web.probes import idor, traversal, sqli
        import inspect
        for mod in (idor, traversal, sqli):
            self.assertIn("gobuster", inspect.getsource(mod).lower())


class SafetyTests(unittest.TestCase):
    def test_same_origin_block(self):
        from ctf_copilot.web.probes import idor, traversal, ssti, command, redirect
        s = WebSession("http://example.test/")
        for mod in (idor, traversal, ssti, command, redirect):
            with self.assertRaises(ValueError):
                mod.probe("http://evil.test/x?id=1", session=s)

    def test_cap_enforcement(self):
        from ctf_copilot.web.probes import traversal
        s = _session_with_routes(
            {"http://example.test/view": {"text": "normal"}}, max_requests=1)
        with self.assertRaises(RuntimeError):
            traversal.probe("http://example.test/view?file=home", session=s, max_requests=6)
        _stop(s)

    def test_no_delete_put_anywhere(self):
        import pathlib
        root = pathlib.Path(__file__).resolve().parent.parent / "ctf_copilot" / "web"
        for p in list((root / "probes").glob("*.py")) + [root / "commands.py", root / "client.py"]:
            if not p.exists():
                continue
            text = p.read_text(encoding="utf-8")
            # allow the word in comments about prohibition? enforce no active request strings
            self.assertNotIn('"PUT"', text, f"{p} contains PUT")
            self.assertNotIn("'PUT'", text, f"{p} contains PUT")
            self.assertNotIn('"DELETE"', text, f"{p} contains DELETE")
            self.assertNotIn("'DELETE'", text, f"{p} contains DELETE")

    def test_confirm_gate_no_requests(self):
        from ctf_copilot.web import commands as wc
        import argparse
        ns = argparse.Namespace(url="http://example.test/", confirm_authorized=False,
                                headers=False, methods=False, xss=False, sqli=False,
                                idor=False, traversal=False, ssti=False, cmd=False,
                                redirect=False, cookies=False)
        with patch("ctf_copilot.web.commands.WebSession") as WS:
            with self.assertRaises(SystemExit):
                wc._test(ns)
            WS.assert_not_called()


class CarryCleanupTests(unittest.TestCase):
    def test_budget_enforced_via_max_requests(self):
        from ctf_copilot.web import analyzer as az
        routes = {
            "http://example.test/": "<html><a href='/p1'>1</a><a href='/p2'>2</a></html>",
            "http://example.test/p1": "<html><p>one</p></html>",
            "http://example.test/p2": "<html><p>two</p></html>",
            "http://example.test/robots.txt": "",
            "http://example.test/sitemap.xml": "",
            "http://example.test/.well-known/security.txt": "",
        }
        s = _session_with_routes(routes, max_requests=3)
        try:
            info = az.analyze("http://example.test/", session=s, crawl=2)
        except RuntimeError:
            pass
        finally:
            calls = list(s._test_calls)  # type: ignore[attr-defined]
            _stop(s)
        self.assertLessEqual(len(s.ledger), 3)
        self.assertLessEqual(len(calls), 3)

    def test_multi_set_cookie_parse(self):
        from ctf_copilot.web import analyzer as az
        routes = {
            "http://example.test/": {
                "text": "<html><p>hi</p></html>",
                "headers": {"Content-Type": "text/html",
                            "Set-Cookie": "a=1; Path=/, b=2; Path=/; HttpOnly"},
            },
            "http://example.test/robots.txt": "",
            "http://example.test/sitemap.xml": "",
            "http://example.test/.well-known/security.txt": "",
        }
        s = _session_with_routes(routes)
        try:
            info = az.analyze("http://example.test/", session=s, crawl=0)
        finally:
            _stop(s)
        names = [n for n, _, _ in info.get("cookie_details", [])]
        self.assertIn("a", names)
        self.assertIn("b", names)

    def test_commands_route_through_session(self):
        import inspect
        from ctf_copilot.web import commands as wc
        from ctf_copilot.web import client as cl
        src_cmd = inspect.getsource(wc)
        self.assertNotIn("urllib", src_cmd)
        src_client = inspect.getsource(cl)
        self.assertNotIn("urllib.request", src_client)
        self.assertIn("WebSession", src_client)


if __name__ == "__main__":
    unittest.main()
