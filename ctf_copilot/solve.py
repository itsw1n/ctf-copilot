from __future__ import annotations
from collections import deque
from pathlib import Path
import hashlib
import json
import re
from .crypto.analyzer import analyze as crypto_analyze
from .web.analyzer import render as web_render
from .shared.flags import emit_flag_config_warnings_once, find_flags, validate_flags
from .flags.scanner import scan as flag_scan
from .engine import Finding


def classify_file(p: Path) -> str:
    head=p.read_bytes()[:32]; suffix=p.suffix.lower()
    if head.startswith((b'\x7fELF',b'MZ')): return 'reverse/pwn'
    if suffix in {'.pcap','.pcapng'}: return 'forensics/pcap'
    if suffix in {'.zip','.7z','.rar','.tar','.gz'} or head.startswith(b'PK\x03\x04'): return 'forensics/archive'
    if suffix in {'.png','.jpg','.jpeg','.gif','.bmp','.webp','.pdf','.wav'} or head.startswith((b'\x89PNG\r\n\x1a\n',b'\xff\xd8\xff')): return 'forensics'
    if suffix in {'.py','.js','.txt','.md','.json','.xml','.html','.csv'}: return 'text/crypto'
    return 'generic-file'

def _finish(report, detail: str, flag_pattern: str | None, workspace: str | None) -> str:
    """Feed actual safe action output back into the report before rendering it."""
    confirmed, candidates = validate_flags(detail, pattern=flag_pattern, source_kind="decoded")
    merged = list(dict.fromkeys(list(getattr(report, "flags", []) or []) + confirmed))
    report.flags = merged
    try:
        existing = list(getattr(report, "flag_candidates", []) or [])
        report.flag_candidates = list(dict.fromkeys(existing + candidates))
    except Exception:
        pass
    report.status = 'flag-found' if report.flags else 'needs-next-step'
    # Keep findings list consistent for validated flags.
    if report.flags and not any(getattr(f, "flags", None) for f in report.findings):
        report.findings.append(Finding(report.category, 'offline playbook', 'Completed bounded first-pass actions', .8, 'Results below were produced without active probing.', flags=report.flags))
    elif not report.flags:
        report.findings.append(Finding(report.category, 'offline playbook', 'Completed bounded first-pass actions', .8, 'Results below were produced without active probing.', flags=[]))
    if workspace:
        try:
            _persist_flat(report, workspace)
        except Exception:
            from .workspace.manager import save_report
            save_report(workspace, report)
    from .engine import render_report
    return render_report(report) + '\n\n' + detail

def _password_candidates(description: str) -> list[str]:
    """Only accept explicit clue values; never run a wordlist/brute-force attack."""
    values = re.findall(r'(?i)(?:password|passphrase|key)\s*(?:is|=|:)\s*["\']?([A-Za-z0-9_@!#$%^&*.-]{3,80})', description)
    return list(dict.fromkeys(values))[:10]


def _evidence_kind(raw: str) -> tuple[str, str]:
    """Resolve --input/target values: text: forces literal, existing path wins, else literal."""
    if raw.startswith("text:"):
        return "text", raw[5:]
    p = Path(raw)
    try:
        if p.is_dir():
            return "dir", raw
        if p.is_file():
            return "file", raw
    except OSError:
        pass
    if raw.startswith(("http://", "https://")):
        return "url", raw
    return "text", raw


def _sha_repr(value: object) -> str:
    try:
        blob = value.encode() if isinstance(value, str) else repr(value).encode()
    except Exception:
        blob = repr(value).encode()
    return hashlib.sha256(blob).hexdigest()


def _resolve_workspace_dir(name: str) -> Path:
    from .workspace import manager
    s = str(name)
    p = Path(s)
    if p.is_absolute() or "/" in s or "\\" in s or s.startswith("."):
        p.mkdir(parents=True, exist_ok=True)
        return p
    return manager.new(s)


def _persist_flat(report, workspace: str | None):
    """Store report + artifacts flat with collision-safe artifact-XXX names.

    Flat layout: every artifact copies to ``artifact-NNN-<safe-base>`` in the
    workspace root (never nested). Parent links survive via
    ``Artifact.source_artifact`` and the ``parent`` field in solve-report.json.
    Simple NAME workspaces auto-create via workspace.manager; path-like names
    resolve as directories (recognized workspace paths reused in place).
    """
    if not workspace:
        return None
    import shutil
    ws = _resolve_workspace_dir(workspace)
    persisted = []
    index = 0

    def _next_dest(safe_base: str) -> Path:
        nonlocal index
        index += 1
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", safe_base) or "evidence"
        dest = ws / f"artifact-{index:03d}-{safe}"
        n = 0
        while dest.exists():
            n += 1
            dest = ws / f"artifact-{index:03d}-{n}-{safe}"
        return dest

    for art in list(getattr(report, "artifacts", []) or []):
        try:
            src = Path(getattr(art, "path", "") or "")
        except Exception:
            continue
        if not src.is_file() or src.is_symlink():
            continue
        try:
            if ws.resolve() in [src.resolve(), *src.resolve().parents]:
                # Already inside workspace: keep reference, ensure parent link.
                persisted.append(art)
                continue
        except Exception:
            pass
        try:
            dest = _next_dest(src.name)
            shutil.copy2(src, dest)
        except OSError:
            continue
        try:
            art.path = str(dest)
            art.source_artifact = getattr(art, "source_artifact", "") or "solve"
            persisted.append(art)
        except Exception:
            continue
    # Persist in-memory decoded values (path empty, kind decoded) as text files.
    for art in list(getattr(report, "artifacts", []) or []):
        if getattr(art, "path", ""):
            continue
        blob = getattr(art, "source", "") or ""
        if not blob or len(blob) > 200000:
            continue
        try:
            dest = _next_dest("decoded.txt")
            dest.write_text(blob, encoding="utf-8")
            art.path = str(dest)
            if art not in persisted:
                persisted.append(art)
        except OSError:
            continue
    # Deduplicate persisted entries by path.
    seen_paths = set()
    flat = []
    for art in persisted:
        if art.path in seen_paths:
            continue
        seen_paths.add(art.path)
        flat.append(art)
    # Include workspace-contained file artifacts not yet tracked (idempotent rescan).
    if not flat:
        for art in list(getattr(report, "artifacts", []) or []):
            try:
                pp = Path(getattr(art, "path", "") or "")
                if pp.is_file() and ws.resolve() in [pp.resolve(), *pp.resolve().parents]:
                    if pp.as_posix() not in seen_paths:
                        seen_paths.add(pp.as_posix())
                        flat.append(art)
            except Exception:
                continue
    report.artifacts = flat if flat else list(getattr(report, "artifacts", []) or [])
    # Record nesting/parent: previous report target if workspace already had one.
    parent = ""
    try:
        prev = ws / "solve-report.json"
        if prev.exists():
            try:
                old = json.loads(prev.read_text(encoding="utf-8"))
                if isinstance(old, dict) and old.get("target") != getattr(report, "target", ""):
                    parent = str(old.get("target") or "")
            except Exception:
                parent = ""
    except Exception:
        parent = ""
    try:
        data = report.to_dict()
    except Exception:
        data = {"target": getattr(report, "target", ""), "status": getattr(report, "status", "")}
    data["workspace"] = ws.name
    data["parent"] = parent
    try:
        (ws / "solve-report.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass
    return ws / "solve-report.json"


def _rsa_correlation_findings(rsa_ctx: list[str], pattern, artifact, depth: int,
                              primary_text: str = "", skip_no_weakness: bool = False):
    """Shared RSA correlation helper (deduped): bounded weakness analysis over
    target+inputs. Returns (findings, artifacts). Never raises."""
    from .analysis.models import Artifact as _Art
    from .analysis.models import Finding as _Find
    findings: list = []
    artifacts: list = []
    try:
        from .crypto.rsa_engine import analyze_rsa, parse_records
        from .crypto.normalization import readable
        if not rsa_ctx or not parse_records(rsa_ctx):
            return findings, artifacts
        for res in analyze_rsa(rsa_ctx)[:5]:
            try:
                ptext = readable(res.plaintext) if res.plaintext is not None else None
            except Exception:
                ptext = None
            if skip_no_weakness and not ptext and "No supported bounded weakness" in str(getattr(res, "evidence", "")):
                continue
            obs = f"{res.technique}: {res.evidence}"
            if ptext:
                obs += f" -> {ptext[:300]}"
            flags: list[str] = []
            if ptext:
                c, _cand = validate_flags(ptext, pattern=pattern, source_kind="decrypted")
                flags = c + [x for x in _cand if x not in c]
            findings.append(_Find("crypto", "rsa", obs[:800], 0.85 if flags else 0.6,
                                  "bounded RSA weakness analysis over target+inputs",
                                  ["verify recovered plaintext"], flags,
                                  "solved" if flags else "candidate", [res.evidence[:300]]))
            if ptext and primary_text and ptext != primary_text:
                digest = hashlib.sha256(ptext.encode()).hexdigest()
                artifacts.append(_Art("", "decoded", ptext[:200000], f"artifact-{digest[:12]}",
                                      "text/plain", len(ptext.encode()), digest,
                                      getattr(artifact, "id", "") or getattr(artifact, "path", ""),
                                      depth + 1, "crypto-rsa"))
    except Exception:
        pass
    return findings, artifacts


def _build_registry():
    """Analyzer registry for `ctf solve` evidence-queue loop.

    Ownership (no overlap): crypto-auto owns literal text/ints, forensics-triage
    owns files (plus RSA correlation over target+inputs), web-passive owns URLs
    (passive GET-only, crawl=0). No active web probes run from solve; extraction
    stays bounded via AnalysisBudget.
    """
    from .analysis.registry import AnalyzerRegistry, FunctionAnalyzer

    registry = AnalyzerRegistry()

    def _crypto_detect(value, context) -> float:
        if isinstance(value, Path):
            return 0.0
        text = str(value or "")
        if text.startswith(("http://", "https://")):
            return 0.0  # web-only: web-passive analyzer owns URLs
        p = Path(text)
        try:
            if p.is_file() or p.is_dir():
                return 0.0
        except OSError:
            pass
        return 0.9 if len(text.strip()) >= 2 else 0.0

    def _crypto_handle(value, context):
        from .analysis.models import Artifact as _Art
        from .analysis.models import Finding as _Find
        budget = context.get("budget")
        artifact = context.get("artifact")
        depth = int(getattr(artifact, "depth", 0) or 0)
        text = str(value or "")
        max_depth = min(int(getattr(budget, "max_depth", 5)), 6)
        findings: list = []
        artifacts: list = []
        try:
            results = crypto_analyze(text, max_depth=max(1, max_depth), branch_limit=8)
        except Exception as exc:
            findings.append(_Find("crypto", "crypto-auto", f"crypto probe failed: {exc}", 0.2, "guarded bounded decode", [], [], "inconclusive", [str(exc)[:300]]))
            return findings, artifacts
        # RSA over combined context (target + related inputs + description).
        extra = list(context.get("related_texts", []) or [])
        desc = str(context.get("description", "") or "")
        rsa_ctx = [text] + extra + ([desc] if desc else [])
        rf, ra = _rsa_correlation_findings(rsa_ctx, context.get("flag_pattern"), artifact, depth, primary_text=text)
        findings.extend(rf)
        artifacts.extend(ra)
        for r in results[:8]:
            try:
                chain = ' -> '.join(f'{x.kind}({x.parameter})' if x.parameter else x.kind for x in r.chain)
            except Exception:
                chain = "decode"
            out = str(getattr(r, "output", "") or "")
            confirmed, cands = validate_flags(out, pattern=context.get("flag_pattern"), source_kind="decoded")
            flags = confirmed + [x for x in cands if x not in confirmed]
            status = "solved" if confirmed else "candidate"
            findings.append(_Find("crypto", "crypto-auto", f"{chain}: {out[:400]}", 0.9 if confirmed else 0.6, "bounded layered-decode probe (max_depth<=6, branch<=8)", ["verify decoded flag"] if confirmed else ["inspect decoding chain"], flags, status, [chain[:300]]))
            if out and out != text and len(out) <= 200000:
                digest = hashlib.sha256(out.encode()).hexdigest()
                artifacts.append(_Art("", "decoded", out[:200000], f"artifact-{digest[:12]}", "text/plain", len(out.encode()), digest, getattr(artifact, "id", "") or getattr(artifact, "path", ""), depth + 1, "crypto-auto"))
        # Source literals stay candidates: report but never confirm here.
        try:
            src_flags = find_flags(text)
            if src_flags:
                findings.append(_Find("crypto", "source-literals", f"source literals (unconfirmed): {', '.join(src_flags[:5])}", 0.4, "source literals stay candidate until a decoding path validates them", ["decode or extract the source value"], src_flags, "candidate", src_flags[:5]))
        except Exception:
            pass
        return findings, artifacts

    def _forensics_detect(value, context) -> float:
        path = value if isinstance(value, Path) else Path(str(value or ""))
        try:
            return 1.0 if path.is_file() else 0.0
        except OSError:
            return 0.0

    def _forensics_handle(value, context):
        budget = context.get("budget")
        desc = str(context.get("description", "") or "")
        pattern = context.get("flag_pattern")
        from .forensics.pipeline import triage_file
        findings, artifacts, _render = triage_file(str(value), budget=budget, description=desc, flag_pattern=pattern)
        # RSA correlation across target + --inputs (shared-prime/common-modulus/etc).
        # triage_file only probes single-file crypto; solve must correlate related texts.
        try:
            ftext = Path(str(value)).read_text(errors="ignore")[:20000]
        except OSError:
            ftext = ""
        extra = list(context.get("related_texts", []) or [])
        rsa_ctx = ([ftext] if ftext else []) + extra + ([desc] if desc else [])
        # Ensure the current file text participates even if related_texts omitted it.
        if ftext and ftext not in rsa_ctx:
            rsa_ctx.insert(0, ftext)
        artifact = context.get("artifact")
        depth = int(getattr(artifact, "depth", 0) or 0)
        rf, ra = _rsa_correlation_findings(rsa_ctx, pattern, artifact, depth,
                                           primary_text=ftext, skip_no_weakness=True)
        findings.extend(rf)
        artifacts.extend(ra)
        return findings, artifacts

    def _web_detect(value, context) -> float:
        text = str(value if not isinstance(value, Path) else "") or ""
        return 0.95 if text.startswith(("http://", "https://")) else 0.0

    def _web_handle(value, context):
        from .analysis.models import Finding as _Find
        url = str(value)
        try:
            from .web import analyzer as _wa
            info = _wa.analyze(url, crawl=0)
        except Exception as exc:
            return [_Find("web", "web-passive", f"passive fetch failed: {exc}", 0.3, "passive GET-only; no probes from solve", ["verify URL is reachable; use `ctf web analyze` for detail"], [], "inconclusive", [url[:200]])], []
        blob = ""
        try:
            parts = [str(info.get("final", url))]
            for key in ("comments", "endpoints", "links"):
                for item in info.get(key, []) or []:
                    parts.append(str(item))
            blob = "\n".join(parts)
        except Exception:
            blob = url
        confirmed, cands = validate_flags(blob, pattern=context.get("flag_pattern"), source_kind="response")
        flags = confirmed + [x for x in cands if x not in confirmed]
        obs = web_render(info)[:3000]
        status = "solved" if confirmed else "candidate"
        return [_Find("web", "web-passive", obs[:800], 0.85 if confirmed else 0.55, "passive only: same-origin GET, crawl=0, no probes", ["use `ctf web analyze` for detail; active tests need --confirm-authorized"], flags, status, [url[:300]])], []

    registry.register(FunctionAnalyzer("crypto-auto", "crypto", _crypto_detect, _crypto_handle, cost=1, risk="safe"))
    registry.register(FunctionAnalyzer("forensics-triage", "forensics", _forensics_detect, _forensics_handle, cost=2, risk="safe"))
    registry.register(FunctionAnalyzer("web-passive", "web", _web_detect, _web_handle, cost=2, risk="safe"))
    return registry


def solve(target: str, description: str = '', flag_pattern: str | None = None, workspace: str | None = None, inputs: list[str] | None = None, budget: str = 'balanced') -> str:
    from .engine import initial_report, render_report
    from .analysis.budget import AnalysisBudget
    try:
        b = AnalysisBudget.named(budget or "balanced")
    except ValueError:
        b = AnalysisBudget.named("balanced")
    related = list(inputs or [])
    report = initial_report(target, description, flag_pattern)
    # Status flag-found requires >=1 validated flag; source literals stay candidate
    # unless they validate as direct input. Placeholders are already rejected.
    init_blob = "\n".join([str(target or ""), str(description or "")] + [str(x or "") for x in related])
    confirmed0, cands0 = validate_flags(init_blob, pattern=flag_pattern, source_kind="direct")
    if confirmed0:
        report.flags = list(dict.fromkeys(confirmed0))
        report.flag_candidates = list(dict.fromkeys(cands0))
        report.status = "flag-found"
        report.stop_reason = "flag validated in initial input"
        detail_lines = ["CTF SOLVE - EVIDENCE QUEUE", "===========================", f"Target: {target}", "", "Direct input validated as a flag; no further analysis needed."]
        detail = "\n".join(detail_lines)
        report.budget = b.snapshot()
        report.usage = b.usage()
        return _finish(report, detail, flag_pattern, workspace)
    # Reset premature flag-found from raw literals: only validated flags count.
    if report.status == "flag-found":
        report.status = "incomplete"
        report.flags = []
        try:
            report.flag_candidates = list(dict.fromkeys(cands0))
        except Exception:
            pass
    report.budget = b.snapshot()

    registry = _build_registry()
    # Related texts for RSA/XOR correlation (literals + file contents, bounded).
    related_texts: list[str] = []
    for raw in related:
        kind, val = _evidence_kind(str(raw))
        if kind == "text":
            related_texts.append(val[:20000])
        elif kind == "file":
            try:
                related_texts.append(Path(val).read_text(errors="ignore")[:20000])
            except OSError:
                continue

    # Evidence queue: (value, Artifact, detail_prefix)
    from .analysis.models import Artifact as _Art
    queue: deque = deque()
    seen: set[tuple[str, str]] = set()

    def _enqueue(value, kind: str, depth: int, source_label: str, size: int, digest: str):
        if depth > b.max_depth:
            return
        key = (digest, kind)
        if key in seen:
            return
        art = _Art(str(value)[:500] if kind in ("text", "url") else str(value), kind, source_label, f"artifact-{digest[:12]}", "text/plain" if kind in ("text", "decoded", "url") else kind, size, digest, source_label, depth)
        queue.append((value, art))

    initial_rows = [str(target)] + [str(x) for x in related]
    for raw in initial_rows:
        kind, val = _evidence_kind(raw)
        if kind == "file":
            try:
                data = Path(val).read_bytes()
                digest = hashlib.sha256(data).hexdigest()
                _enqueue(Path(val), "file", 0, "solve-target" if raw == str(target) else "solve-input", len(data), digest)
            except OSError as exc:
                report.findings.append(Finding(report.category, "triage", f"cannot read input: {exc}", 0.9, str(exc), [], [], "inconclusive", [raw[:200]]))
        elif kind == "dir":
            _enqueue(raw, "dir", 0, "solve-target", len(raw.encode()), _sha_repr(raw))
        elif kind == "url":
            _enqueue(val, "url", 0, "solve-target" if raw == str(target) else "solve-input", len(val.encode()), _sha_repr(val))
        else:
            _enqueue(val, "text", 0, "solve-target" if raw == str(target) else "solve-input", len(val.encode()), _sha_repr(val))

    from .analysis.models import Action as _Action
    detail_parts: list[str] = ["CTF SOLVE - EVIDENCE QUEUE", "===========================", f"Target: {target}", f"Budget: {b.profile} (depth<={b.max_depth}, artifacts<={b.max_artifacts})", ""]
    # Directory fast path: scan + handoff (bounded, no recursion beyond scan).
    p_target = Path(str(target))
    if p_target.is_dir():
        rows = flag_scan(str(p_target))
        lines = ['CTF SOLVE - DIRECTORY', '=====================', f'Path: {p_target}', f'Flag-like hits: {len(rows)}']
        lines += [f'  {path}: {flag}' for path, flag in rows[:50]]
        lines += ['', 'NEXT BEST ACTIONS', '  - Inspect suspicious files individually with `ctf solve <file>`.', '  - For extracted challenge trees, run `ctf flags scan <directory>`.']
        joined = "\n".join(lines)
        confirmed_d, _c = validate_flags(joined, pattern=flag_pattern, source_kind="extracted")
        if confirmed_d:
            report.flags = list(dict.fromkeys(confirmed_d))
            report.status = "flag-found"
            report.stop_reason = "flag validated in directory scan"
        else:
            report.stop_reason = "manual action required: inspect directory members individually"
        report.budget = b.snapshot()
        report.usage = b.usage()
        return _finish(report, joined, flag_pattern, workspace)

    validated: list[str] = []
    manual_hint = ""
    while queue and b.can_continue():
        value, artifact = queue.popleft()
        key = (artifact.sha256, artifact.kind)
        if key in seen or artifact.depth > b.max_depth:
            continue
        seen.add(key)
        size = int(getattr(artifact, "size", 0) or 0)
        if not b.consume_artifact(size):
            report.stop_reason = "artifact or byte budget exhausted"
            break
        report.artifacts.append(artifact)
        ctx = {"budget": b, "artifact": artifact, "description": description or "", "flag_pattern": flag_pattern, "related_texts": related_texts}
        applicable = registry.applicable(value, ctx)
        if not applicable:
            continue
        for _score, analyzer in applicable:
            if not b.can_continue():
                break
            import time as _t
            started = _t.monotonic()
            action = _Action(analyzer.name, analyzer.name, f"Analyze {str(getattr(artifact, 'path', ''))[:200]}", analyzer.cost, analyzer.risk, analyzer.name, "running")
            try:
                findings, children = analyzer.analyze(value, ctx)
                report.findings.extend(findings)
                action.status = "complete"
                # Flag validate after each analyzer.
                for f in findings or []:
                    for flag in list(getattr(f, "flags", []) or []):
                        # Re-validate: placeholders rejected; only decoded/extracted/response/direct confirm.
                        c, _ = validate_flags(flag, pattern=flag_pattern, source_kind="decoded" if analyzer.name == "crypto-auto" else ("extracted" if analyzer.name == "forensics-triage" else "response"))
                        for v in c:
                            if v not in validated and v not in report.flags:
                                validated.append(v)
                    # Encrypted-archive handoff (no cracking from solve).
                    try:
                        obs = f"{getattr(f, 'observation', '')} {getattr(f, 'tool', '')}".lower()
                        if "encrypt" in obs and "password" in obs:
                            manual_hint = "manual action required: archive password needed (no brute-force from solve)"
                    except Exception:
                        pass
                if validated:
                    report.flags = list(dict.fromkeys(list(report.flags or []) + validated))
                    report.flag_candidates = list(dict.fromkeys(list(getattr(report, "flag_candidates", []) or []) + cands0))
                    report.status = "flag-found"
                    report.stop_reason = "flag validated"
                    try:
                        report.budget = b.snapshot()
                        report.usage = b.usage()
                    except Exception:
                        pass
                    b.actions += 1
                    report.actions.append(action)
                    queue.clear()
                    break
                for child in children or []:
                    try:
                        cdepth = int(getattr(child, "depth", artifact.depth + 1) or artifact.depth + 1)
                    except Exception:
                        cdepth = artifact.depth + 1
                    if cdepth > b.max_depth:
                        continue
                    if len(seen) + len(queue) >= b.max_artifacts:
                        report.stop_reason = "artifact or byte budget exhausted"
                        break
                    ckind = str(getattr(child, "kind", "decoded") or "decoded")
                    cdigest = str(getattr(child, "sha256", "") or "")
                    cpath = str(getattr(child, "path", "") or "")
                    if cpath:
                        cval: object = Path(cpath) if Path(cpath).exists() else cpath
                        csize = int(getattr(child, "size", 0) or len(cpath.encode()))
                        if not cdigest:
                            cdigest = _sha_repr(cpath)
                    else:
                        blob = str(getattr(child, "source", "") or "")
                        if not blob:
                            continue
                        cval = blob
                        csize = len(blob.encode())
                        cdigest = cdigest or hashlib.sha256(blob.encode()).hexdigest()
                    child.depth = cdepth
                    child.size = csize
                    child.sha256 = cdigest
                    if not getattr(child, "source_artifact", ""):
                        child.source_artifact = getattr(artifact, "id", "") or getattr(artifact, "path", "")
                    key2 = (cdigest, ckind)
                    if key2 in seen:
                        continue
                    # Dedup by representation for decoded text.
                    if isinstance(cval, str):
                        dup = False
                        for s, _a in list(queue):
                            if isinstance(s, str) and _sha_repr(s) == cdigest:
                                dup = True
                                break
                        if dup:
                            continue
                    queue.append((cval, child))
            except Exception as exc:
                action.status = "error"
                action.purpose += f": {exc}"
            import time as _t2
            action.duration = round(_t2.monotonic() - started, 3)
            b.actions += 1
            report.actions.append(action)
            if validated:
                break
        # Render progress for this artifact (bounded).
        try:
            if isinstance(value, Path):
                detail_parts.append(f"[{artifact.kind}@{artifact.depth}] {value} (sha={artifact.sha256[:12]})")
            else:
                preview = str(value)[:200].replace("\n", " ")
                detail_parts.append(f"[{artifact.kind}@{artifact.depth}] {preview}")
        except Exception:
            pass
        if validated:
            break
    if validated:
        report.flags = list(dict.fromkeys(list(report.flags or []) + validated))
        report.status = "flag-found"
        if not report.stop_reason:
            report.stop_reason = "flag validated"
    elif not report.stop_reason:
        if not queue:
            report.stop_reason = manual_hint or "no supported action remains"
        elif not b.can_continue():
            # Distinguish time vs artifact exhaustion.
            if b.artifacts >= b.max_artifacts:
                report.stop_reason = "artifact or byte budget exhausted"
            else:
                report.stop_reason = "time budget exhausted"
        else:
            report.stop_reason = manual_hint or "no supported action remains"
    # Hypotheses: keep initial ones + add decode/extract hypothesis when useful.
    try:
        if report.category in ("crypto", "text", "reverse", "pwn") and not any("decod" in h.name.lower() for h in report.hypotheses):
            from .analysis.models import Hypothesis as _H
            report.hypotheses.append(_H("layered encoding or weak parameters", report.category, ["evidence queue"], 0.6, "ctf crypto analyze <value> --input <related>"))
    except Exception:
        pass
    report.budget = b.snapshot()
    try:
        report.usage = b.usage()
    except Exception:
        pass
    detail = "\n".join(detail_parts)
    # Append analyst-visible renders (bounded) for file/url/text paths already in findings.
    try:
        obs_lines = []
        for f in report.findings[-12:]:
            obs_lines.append(f"- [{getattr(f, 'status', '')}/{getattr(f, 'category', '')}] ({getattr(f, 'tool', '')}): {str(getattr(f, 'observation', ''))[:400]}")
            if getattr(f, "flags", None):
                obs_lines.append(f"    flags: {', '.join(list(f.flags)[:5])}")
        if obs_lines:
            detail += "\n\n[FINDINGS]\n" + "\n".join(obs_lines)
    except Exception:
        pass
    return _finish(report, detail, flag_pattern, workspace)
