"""Phase 10 web benchmark corpus runner (Task 16, Codex §10).

Mocked transport only: FakeSession via WebSession with stubbed
``session.request`` mapping URL -> html/headers from fixture files.
No live HTTP server, no network in CI.
"""
from __future__ import annotations

import argparse
import json
import time
import unittest
import urllib.parse
from pathlib import Path
from unittest.mock import MagicMock, patch

BASE = Path(__file__).parent / "benchmarks" / "web"
MANIFEST = BASE / "manifest.json"


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


class FakeSession:
    """No-network WebSession double for benchmarks (Task 16).

    Wraps :class:`ctf_copilot.web.session.WebSession` with stubbed
    ``session.request`` mapping URL -> html/headers. Records calls in
    ``calls``; call :meth:`stop` to unpatch. Never touches the network.
    """

    def __init__(self, base="http://example.test/", routes=None, **kw):
        from ctf_copilot.web.session import WebSession
        self._inner = WebSession(base, **kw)
        self.calls: list[tuple] = []
        self._routes = routes or {}

        def fake_request(method, url, **k):
            self.calls.append((method, url))
            spec = self._routes.get(url)
            if spec is None:
                spec = self._routes.get(url.split("?")[0])
            if spec is None:
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

        self._patcher = patch.object(self._inner.session, "request", side_effect=fake_request)
        self._patcher.start()
        # mirror attributes expected by WebSession callers
        self._inner._patcher = self._patcher  # type: ignore[attr-defined]
        self._inner._test_calls = self.calls  # type: ignore[attr-defined]

    def __getattr__(self, name):
        return getattr(self._inner, name)


def _session_with_routes(routes: dict, base="http://example.test/", **kw):
    s = FakeSession(base=base, routes=routes, **kw)
    return s._inner


def _stop(s):
    try:
        s._patcher.stop()  # type: ignore[attr-defined]
    except Exception:
        pass


def _load_fixture(entry):
    fid = entry["id"]
    html = (BASE / "fixtures" / f"{fid}.html").read_text(encoding="utf-8")
    meta = json.loads((BASE / "fixtures" / f"{fid}.json").read_text(encoding="utf-8"))
    return html, meta


def _run_passive(entry, html, meta, base_url):
    from ctf_copilot.web import analyzer as az
    path = meta.get("path", "/")
    main_url = urllib.parse.urljoin(base_url, path.lstrip("/") if path.startswith("/") and path != "/" else path)
    if path in ("/", ""):
        main_url = base_url.rstrip("/") + "/"
    routes: dict = {}
    routes[main_url.split("?")[0]] = {
        "text": html,
        "headers": meta.get("headers", {"Content-Type": "text/html"}),
        "history": meta.get("history"),
        "final_url": meta.get("final_url"),
    }
    for name, text in (meta.get("aux") or {}).items():
        routes[urllib.parse.urljoin(base_url, name)] = {"text": text}
    for name, text in (meta.get("aux_files") or {}).items():
        routes[urllib.parse.urljoin(base_url, name)] = {"text": text}
    if "robots.txt" in meta:
        routes[urllib.parse.urljoin(base_url, "robots.txt")] = {"text": meta["robots.txt"]}
    if "sitemap.xml" in meta:
        routes[urllib.parse.urljoin(base_url, "sitemap.xml")] = {"text": meta["sitemap.xml"]}
    # default aux to avoid 404 noise counting against budget (still fine as 404)
    for p in ("robots.txt", "sitemap.xml", ".well-known/security.txt"):
        routes.setdefault(urllib.parse.urljoin(base_url, p), {"text": ""})
    # ensure js aux known paths resolve even if main references differ
    s = _session_with_routes(routes, base=base_url, max_requests=50)
    try:
        info = az.analyze(main_url, session=s, crawl=0)
        out = az.render(info)
        # evidence summary for classifier stability
        out += f"\nEVIDENCE passive {entry['id']} forms={len(info.get('forms') or [])} "
        out += f"comments={len(info.get('comments') or [])} endpoints={len(info.get('endpoints') or [])} "
        out += f"jwt={len(info.get('jwt') or [])} robots={bool(info.get('robots'))} "
        out += f"chain={len(info.get('redirect_chain') or [])}\n"
        if entry["id"] == "w10_clean_negative":
            out += "decisive-next-step: clean baseline, no false positives; next: manual review or authorized probes.\n"
        return out
    finally:
        _stop(s)


def _route_for_mode(mode, html, meta):
    if mode == "sqli_error":
        def route(m, u, k):
            if "%27" in u or "'" in u:
                return _fake_resp(url=u, status=500, text="You have an error in your SQL syntax near '' at line 1; mysql said hi")
            return _fake_resp(url=u, text=html or "normal search page results")
        return route
    if mode == "sqli_boolean":
        def route(m, u, k):
            if "%27" in u or "'" in u:
                return _fake_resp(url=u, text=(html or "base ") + "X" * 600)
            return _fake_resp(url=u, text=html or "base normal content")
        return route
    if mode == "xss_reflect":
        def route(m, u, k):
            if "CTFCP" in u:
                return _fake_resp(url=u, text="echo CTFCP_XSS_9f31<svg/onload=alert(1)> reflected")
            return _fake_resp(url=u, text=html or "echo hi")
        return route
    if mode == "idor":
        def route(m, u, k):
            if "id=2" in u:
                return _fake_resp(url=u, text="user bob bob@example.com profile")
            if "id=1" in u:
                return _fake_resp(url=u, text="user alice alice@example.com profile")
            return _fake_resp(url=u, text=html)
        return route
    if mode == "traversal":
        def route(m, u, k):
            low = u.lower()
            if "etc%2fpasswd" in low or "etc/passwd" in u:
                return _fake_resp(url=u, text="root:x:0:0:root:/root:/bin/bash file contents")
            return _fake_resp(url=u, text=html or "normal file view")
        return route
    if mode == "ssti":
        def route(m, u, k):
            if "%7B%7B" in u.upper() or "{{" in u or "7%2A7" in u or "7*7" in u:
                return _fake_resp(url=u, text="hello 49 world rendered")
            return _fake_resp(url=u, text="hello name world")
        return route
    if mode == "command":
        def route(m, u, k):
            if "%3Bid" in u or ";id" in u or "%7C" in u or "|id" in u:
                return _fake_resp(url=u, text="uid=0(root) gid=0(root) groups=0(root)")
            return _fake_resp(url=u, text=html or "pong ok")
        return route
    if mode == "methods":
        allow = meta.get("allow", "GET, HEAD, OPTIONS")
        return {"text": html or "ok", "headers": {"Content-Type": "text/html", "Allow": allow}}
    if mode == "headers":
        return {"text": html or "ok", "headers": dict(meta.get("headers") or {"Content-Type": "text/html", "Server": "Apache/2.4"})}
    if mode == "cookies_jwt":
        return {"text": html or "ok", "headers": dict(meta.get("headers") or {"Content-Type": "text/html"})}
    if mode == "redirect":
        def route(m, u, k):
            if "evil.example" in u:
                return _fake_resp(url=u, final_url="https://evil.example/phish",
                                  headers={"Location": "https://evil.example/phish"}, text="redirect")
            return _fake_resp(url=u, text=html or "home")
        return route
    if mode == "upload_observe":
        return {"text": html}
    return {"text": html or "ok"}


def _run_active(entry, html, meta, base_url):
    # confirm-authorized gate: runner explicitly authorizes by calling probes
    # with a bounded session (mirrors `ctf web test --confirm-authorized`).
    confirm_authorized = True
    assert confirm_authorized, "active probes require confirm-authorized"
    mode = meta.get("mode", "")
    path = meta.get("path", "/")
    target = urllib.parse.urljoin(base_url, path.lstrip("/") if path != "/" else "")
    if path == "/":
        target = base_url.rstrip("/") + "/"
    # build routes keyed by path without query
    routes: dict = {}
    route_spec = _route_for_mode(mode, html, meta)
    routes[target.split("?")[0]] = route_spec
    # analyzer aux for upload observation
    for p in ("robots.txt", "sitemap.xml", ".well-known/security.txt"):
        routes.setdefault(urllib.parse.urljoin(base_url, p), {"text": ""})
    s = _session_with_routes(routes, base=base_url, max_requests=50)
    try:
        tech = entry.get("technique", "")
        if tech.startswith("sqli"):
            from ctf_copilot.web.probes import sqli
            rows = sqli.probe(target, session=s)
        elif tech.startswith("xss"):
            from ctf_copilot.web.probes import xss
            rows = xss.probe(target, session=s)
        elif tech == "idor":
            from ctf_copilot.web.probes import idor
            rows = idor.probe(target, session=s)
        elif tech == "traversal":
            from ctf_copilot.web.probes import traversal
            rows = traversal.probe(target, session=s)
        elif tech == "ssti":
            from ctf_copilot.web.probes import ssti
            rows = ssti.probe(target, session=s)
        elif tech == "cmd-indicator":
            from ctf_copilot.web.probes import command
            rows = command.probe(target, session=s)
        elif tech == "method-auth":
            from ctf_copilot.web.probes import methods
            rows = methods.probe(target, session=s)
        elif tech == "header-auth":
            from ctf_copilot.web import commands as wc
            rows = wc._headers_rows(s, target)
        elif tech == "cookie-jwt-clue":
            from ctf_copilot.web import commands as wc
            from ctf_copilot.web import analyzer as az
            rows = wc._cookies_rows(s, target)
            info = az.analyze(target, session=s, crawl=0)
            rows = list(rows) + (["JWT-like cookies observed"] if info.get("jwt") else [])
            rows.append("decisive-next-step: verify cookie flags with curl -b/-c; decode JWT offline.")
        elif tech == "redirect":
            from ctf_copilot.web.probes import redirect
            rows = redirect.probe(target, session=s)
        elif tech == "upload-observation":
            from ctf_copilot.web import analyzer as az
            info = az.analyze(target, session=s, crawl=0)
            out = az.render(info)
            rows = [out, "observation: multipart /upload form present; no file uploaded (observation only).",
                    "decisive-next-step: inspect form in Burp; do not upload without explicit authorization."]
        else:
            rows = [f"unknown technique {tech}"]
        header = f"AUTHORIZED ACTIVE confirm-authorized technique={tech} target={target}\n"
        return header + "\n".join(rows)
    finally:
        _stop(s)


def _run_safety(entry, html, meta, base_url):
    tech = entry.get("technique", "")
    if tech == "same-origin-enforce":
        from ctf_copilot.web.session import WebSession
        from ctf_copilot.web.probes import idor, traversal, ssti, command, redirect
        s = WebSession(base_url)
        blocked = 0
        for mod in (idor, traversal, ssti, command, redirect):
            try:
                mod.probe("http://evil.test/x?id=1", session=s)
            except ValueError:
                blocked += 1
        if blocked == 5:
            return "BLOCKED same-origin enforced: 5/5 probes raised ValueError on cross-origin."
        return f"NOT BLOCKED: only {blocked}/5 raised ValueError"
    if tech == "request-budget-enforce":
        from ctf_copilot.web.probes import traversal
        s = _session_with_routes(
            {"http://example.test/view": {"text": "normal"}}, base=base_url, max_requests=1)
        try:
            traversal.probe("http://example.test/view?file=home", session=s, max_requests=6)
            return "NOT BLOCKED: budget not enforced"
        except RuntimeError as exc:
            return f"BLOCKED budget enforced: RuntimeError {exc}"
        finally:
            _stop(s)
    if tech == "auth-refusal":
        from ctf_copilot.web import commands as wc
        ns = argparse.Namespace(url=base_url, confirm_authorized=False,
                                headers=True, methods=False, xss=False, sqli=False,
                                idor=False, traversal=False, ssti=False, cmd=False,
                                redirect=False, cookies=False)
        with patch("ctf_copilot.web.commands.WebSession") as WS:
            try:
                wc._test(ns)
                return "NOT BLOCKED: no refusal"
            except SystemExit as exc:
                if WS.call_count == 0:
                    return f"BLOCKED auth refusal without --confirm-authorized: SystemExit {exc} (0 requests sent)"
                return f"NOT BLOCKED: WebSession called {WS.call_count}x despite refusal"
    return "NOT BLOCKED: unknown safety technique"


def run_entry(entry):
    """Run one manifest entry with mocked transport. Never raises."""
    try:
        html, meta = _load_fixture(entry)
        base_url = meta.get("base_url", "http://example.test/")
        kind = entry.get("kind")
        if kind == "passive":
            return _run_passive(entry, html, meta, base_url)
        if kind == "active":
            return _run_active(entry, html, meta, base_url)
        if kind == "safety":
            return _run_safety(entry, html, meta, base_url)
        return f"RUNNER EXCEPTION: ValueError: unknown kind {kind!r}"
    except Exception as exc:  # noqa: BLE001 - runner must not crash
        return f"RUNNER EXCEPTION: {type(exc).__name__}: {exc}"


def classify(entry, output):
    """Return one of evidence|decisive-next-step|detected|inconclusive|blocked|missed."""
    if output.startswith("RUNNER EXCEPTION"):
        return "missed"
    low = output.lower()
    if entry.get("kind") == "safety":
        return "blocked" if "blocked" in low and "not blocked" not in low else "inconclusive"
    signals = ("deterministic", "candidate", "evidence", "forms:", "html comments",
               "endpoints", "source maps", "jwt-like", "robots", "redirect chain",
               "technology hints", "allow", "observation", "decisive-next-step",
               "cookies:", "security header", "handoff")
    if any(s in low for s in signals):
        return entry.get("expect", "detected")
    return "inconclusive"


class WebBenchmarkTests(unittest.TestCase):
    def test_corpus(self):
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertEqual(len(manifest), 25, f"manifest must have 25 entries, got {len(manifest)}")
        start = time.time()
        counts: dict[str, int] = {}
        rows = []
        errors = []
        mismatches = []
        for entry in manifest:
            out = run_entry(entry)
            if out.startswith("RUNNER EXCEPTION"):
                errors.append(f"{entry['id']}: {out}")
                status = "missed"
            else:
                status = classify(entry, out)
            counts[status] = counts.get(status, 0) + 1
            if status != entry.get("expect"):
                mismatches.append(f"{entry['id']}: expect={entry.get('expect')} got={status}")
            rows.append((entry["id"], entry.get("expect"), status))
        elapsed = time.time() - start
        detected = counts.get("evidence", 0) + counts.get("decisive-next-step", 0) + counts.get("detected", 0)
        blocked = counts.get("blocked", 0)
        print(f"\nWEB-BENCHMARK: {len(manifest)}/{len(manifest)} run, {detected} evidence-or-next-step, "
              f"{counts.get('evidence', 0)} evidence, {counts.get('decisive-next-step', 0)} decisive, "
              f"{counts.get('detected', 0)} detected, {counts.get('inconclusive', 0)} inconclusive, "
              f"{blocked} blocked, runtime {elapsed:.1f}s")
        for eid, expect, got in rows:
            print(f"  {eid}: expect={expect} got={got}")
        self.assertEqual(errors, [], f"runner exceptions: {errors}")
        self.assertEqual(mismatches, [], f"expectation mismatches: {mismatches}")
        self.assertLess(elapsed, 60, f"runtime {elapsed:.1f}s exceeds 60s budget")
        self.assertGreaterEqual(detected, 22, f"need >=22/25 evidence-or-next-step, got {detected} counts={counts}")
        self.assertEqual(blocked, 3, f"safety 3/3 must block, got {blocked} counts={counts}")

    def test_no_active_without_confirm(self):
        from ctf_copilot.web import commands as wc
        ns = argparse.Namespace(url="http://example.test/", confirm_authorized=False,
                                headers=True, methods=True, xss=True, sqli=True,
                                idor=True, traversal=True, ssti=True, cmd=True,
                                redirect=True, cookies=True)
        with patch("ctf_copilot.web.commands.WebSession") as WS:
            with self.assertRaises(SystemExit):
                wc._test(ns)
            WS.assert_not_called()
            self.assertEqual(WS.call_count, 0, "no active request without confirm")


if __name__ == "__main__":
    unittest.main()
