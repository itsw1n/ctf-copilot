"""Document analyzer: PDF + Office, offline-safe, never executes macros/scripts."""
from __future__ import annotations

import re
import zipfile
from pathlib import Path

from ..analysis.budget import AnalysisBudget
from ..analysis.models import Artifact, Finding
from ..analysis.runner import artifact_for
from ..shared.flags import find_flags_bytes
from ..shared.tooling import run_tool, which


def _budget_or_default(budget):
    if budget is not None:
        return budget
    return AnalysisBudget.named("balanced")


def _timeout(b) -> int:
    try:
        rem = float(b.remaining)
    except Exception:
        rem = 45.0
    return max(1, min(45, int(rem) if rem > 0 else 45))


def _finding(category, tool, observation, confidence=0.5, why="", actions=None,
             flags=None, status="candidate", evidence=None, technique=""):
    return Finding(category, tool, observation, confidence, why, actions or [],
                   flags or [], technique, status, evidence or [])


URL_RE = re.compile(rb"https?://[^\s'\"<>]{4,120}")

OLE_MAGIC = b"\xd0\xcf\x11\xe0"
# Static macro/VBA keywords scanned in raw OLE bytes (never executed).
OLE_MACRO_KEYWORDS = (
    b"autoopen", b"autoclose", b"auto_open", b"document_open",
    b"workbook_open", b"vba", b"macro", b"olevba",
)


def _pdf_header_scan(data: bytes) -> list[str]:
    notes = []
    if data.startswith(b"%PDF-"):
        hdr = data[:32].decode("latin1", "ignore")
        notes.append(f"header={hdr.strip()}")
    for token, label in ((b"/JavaScript", "javascript"), (b"/JS", "js"),
                         (b"/EmbeddedFiles", "embedded-files"), (b"/OpenAction", "open-action"),
                         (b"/Launch", "launch-action"), (b"/ObjStm", "object-stream"),
                         (b"/XFA", "xfa-form"), (b"/AcroForm", "acroform")):
        if token in data:
            count = data.count(token)
            notes.append(f"{label} indicator ({token.decode()} x{count})")
    # metadata fields
    for field in (b"/Author", b"/Title", b"/Subject", b"/Keywords", b"/Creator"):
        if field in data:
            idx = data.find(field)
            snippet = data[idx:idx + 120].decode("latin1", "ignore").replace("\n", " ")
            notes.append(f"metadata {snippet[:100]}")
    return notes


def _office_zip_scan(path: Path, data: bytes) -> tuple[list[str], list[str], list[str]]:
    """Returns (comments, urls, embedded). Never executes macros."""
    comments: list[str] = []
    urls: list[str] = []
    embedded: list[str] = []
    try:
        if not zipfile.is_zipfile(path):
            return comments, urls, embedded
        with zipfile.ZipFile(path) as z:
            for info in z.infolist()[:200]:
                name = info.filename
                low = name.lower()
                if low.endswith((".bin", ".ole", ".emf", ".wmf")) or "embed" in low or "oleobject" in low:
                    embedded.append(name)
                if "comment" in low or "noteslide" in low or "sharedstrings" in low:
                    try:
                        with z.open(info) as fobj:
                            blob = fobj.read(200001)[:200000]
                        txt = blob.decode("utf-8", "ignore")
                        # crude comment text extraction
                        for m in re.findall(r"<[^>]*>([^<>]{4,200})", txt)[:10]:
                            m = m.strip()
                            if m and m not in comments:
                                comments.append(m[:160])
                    except Exception:
                        continue
            # URL scan across XML parts (bounded)
            try:
                for info in z.infolist()[:100]:
                    if info.is_dir() or info.file_size > 500000:
                        continue
                    if not info.filename.lower().endswith((".xml", ".rels", ".txt")):
                        continue
                    try:
                        with z.open(info) as fobj:
                            blob = fobj.read(300001)[:300000]
                    except Exception:
                        continue
                    for m in URL_RE.findall(blob)[:20]:
                        u = m.decode("latin1", "ignore")
                        if u not in urls:
                            urls.append(u)
            except Exception:
                pass
    except Exception:
        pass
    # raw fallback URL scan
    if not urls:
        for m in URL_RE.findall(data[:1000000])[:20]:
            u = m.decode("latin1", "ignore")
            if u not in urls:
                urls.append(u)
    return comments[:10], urls[:20], embedded[:20]


def _ole_macro_hint(data: bytes) -> list[str]:
    """Static OLE macro keyword hits from raw bytes. Never executes macros."""
    low = data.lower()
    hits: list[str] = []
    for kw in OLE_MACRO_KEYWORDS:
        if kw in low:
            label = kw.decode()
            if label not in hits:
                hits.append(label)
    return hits


def analyze(path, budget=None) -> tuple[list, list, str]:
    b = _budget_or_default(budget)
    p = Path(str(path))
    findings: list[Finding] = []
    artifacts: list[Artifact] = []
    if not p.is_file():
        f = _finding("forensics", "documents", f"Not a file: {p}", 1.0,
                     "input missing", [], [], "inconclusive", [str(p)])
        return [f], [], f"Not a file: {p}"
    try:
        art = artifact_for(str(p), kind="file", source="documents", depth=0)
        artifacts.append(art)
    except Exception as e:
        f = _finding("forensics", "documents", f"cannot read input: {e}", 0.9, str(e),
                     [], [], "inconclusive", [str(p)])
        return [f], [], f"cannot read input: {e}"
    try:
        data = p.read_bytes()[:8000000]
    except OSError as e:
        f = _finding("forensics", "documents", f"cannot read input: {e}", 0.9, str(e),
                     [], [], "inconclusive", [str(p)])
        return [f], artifacts, f"cannot read input: {e}"
    suffix = p.suffix.lower()
    is_pdf = data.startswith(b"%PDF-") or suffix == ".pdf"
    is_office = suffix in (".docx", ".xlsx", ".pptx", ".doc", ".xls", ".ppt", ".odt") or data.startswith(b"\xd0\xcf\x11\xe0")

    flags = find_flags_bytes(data)
    if flags:
        findings.append(_finding("forensics", "documents-flags", f"flag-like strings: {', '.join(flags[:5])}",
                                 0.7, "direct flag text in document bytes",
                                 ["verify flag context"], flags, "candidate", flags[:5]))

    if is_pdf:
        out_lines = ["DOCUMENT (PDF)", "=============="]
        # pdfinfo / pdfid if present
        ran = False
        for tool, args in (("pdfinfo", ["pdfinfo", str(p)]), ("pdfid", ["pdfid", str(p)])):
            if which(tool) and b.can_continue():
                _rc, txt = run_tool(args, timeout=_timeout(b), max_output=30000)
                out_lines += ["", f"[{tool}]", (txt or "(no output)")[:4000]]
                findings.append(_finding("forensics", tool, (txt or "(no output)")[:1500], 0.6,
                                         "pdf metadata/structure helper",
                                         ["inspect author/JS/embedded-file fields"], [], "detected", [(txt or "")[:300]]))
                ran = True
        notes = _pdf_header_scan(data)
        if notes:
            findings.append(_finding("forensics", "pdf-scan",
                                     "PDF indicators: " + "; ".join(notes[:12]), 0.75,
                                     "header/metadata/JS/embedded-file scan (no execution)",
                                     ["ctf forensics metadata <file>", "carve embedded files if indicated"],
                                     [], "detected", notes[:12]))
        else:
            findings.append(_finding("forensics", "pdf-scan", "no PDF JS/embedded indicators in header scan", 0.35,
                                     "static header scan only", ["inspect metadata/strings"], [], "inconclusive", ["header-scan"]))
        if not ran:
            findings.append(_finding("forensics", "pdf-tools", "pdfinfo/pdfid not installed; used header scan", 0.4,
                                     "offline fallback", ["install poppler-extra / pdfid for depth"], [], "inconclusive", ["fallback"]))
        render = "\n".join(out_lines + ["", "indicators: " + ("; ".join(notes) if notes else "(none)")])
        return findings, artifacts, render

    if is_office:
        out_lines = ["DOCUMENT (Office)", "================="]
        # olevba for macro hint (never executes)
        if which("olevba") and b.can_continue():
            _rc, txt = run_tool(["olevba", str(p)], timeout=_timeout(b), max_output=60000)
            out_lines += ["", "[olevba]", (txt or "(no output)")[:4000]]
            low = (txt or "").lower()
            if "macro" in low or "vba" in low or "autoopen" in low:
                findings.append(_finding("forensics", "olevba", (txt or "")[:1500], 0.8,
                                         "macro/VBA indicators (static, not executed)",
                                         ["never enable macros; inspect VBA source statically"], [], "detected", [(txt or "")[:300]]))
            else:
                findings.append(_finding("forensics", "olevba", "olevba: no macro indicators", 0.4,
                                         "static macro scan", [], [], "inconclusive", ["olevba"]))
        comments, urls, embedded = _office_zip_scan(p, data)
        # Offline OLE-header hint (static only, never exec): non-zip .doc
        # with macro keywords -> decisive-artifact finding from product.
        try:
            _is_zip = zipfile.is_zipfile(p)
        except Exception:
            _is_zip = False
        _is_ole = data.startswith(OLE_MAGIC)
        _ole_hits: list[str] = []
        if not _is_zip and (_is_ole or suffix in (".doc", ".xls", ".ppt", ".msg")):
            _ole_hits = _ole_macro_hint(data[:1_000_000])
            if _ole_hits:
                _obs = (f"OLE macro hint: OLE header={'yes' if _is_ole else 'no'}; "
                        f"macro/VBA keywords ({', '.join(_ole_hits[:8])}) in static scan (never executed)")
                findings.append(_finding("forensics", "ole-macro-hint", _obs, 0.8,
                                         "OLE-header + macro keyword static hint (never exec); olevba enhances depth",
                                         ["never enable macros; inspect VBA source statically with olevba"],
                                         [], "detected", _ole_hits[:8]))
                out_lines += ["", "[ole-hint]", _obs]
        if comments:
            findings.append(_finding("forensics", "office-comments", f"comments/notes: {'; '.join(comments[:5])}", 0.7,
                                     "ZIP/XML parse of comment parts", ["review hidden review notes"], [], "detected", comments[:5]))
        if urls:
            findings.append(_finding("forensics", "office-urls", f"embedded URLs: {'; '.join(urls[:8])}", 0.65,
                                     "static URL extraction from XML parts",
                                     ["fetch only if in scope; inspect link targets"], [], "detected", urls[:8]))
        if embedded:
            findings.append(_finding("forensics", "office-embedded", f"embedded objects: {'; '.join(embedded[:8])}", 0.7,
                                     "OLE/embedded object names in ZIP",
                                     ["carve embedded object; ctf forensics recurse <file>"], [], "detected", embedded[:8]))
        if not comments and not urls and not embedded and not _ole_hits:
            findings.append(_finding("forensics", "office-scan", "no comments/URLs/embedded objects in static ZIP/XML parse", 0.35,
                                     "never executes macros/scripts", ["inspect metadata/strings"], [], "inconclusive", ["static-parse"]))
        render = "\n".join(out_lines + ["", f"comments={len(comments)} urls={len(urls)} embedded={len(embedded)} ole_hits={','.join(_ole_hits[:8]) if _ole_hits else '(none)'}" ])
        return findings, artifacts, render

    f = _finding("forensics", "documents", "not a recognized PDF/Office document; static scan only", 0.3,
                 "magic/suffix did not match document types", ["ctf forensics triage <file>"], [], "inconclusive", [suffix])
    return findings + [f], artifacts, "DOCUMENT\n========\nnot a PDF/Office document"
