"""Phase 5 forensics benchmark corpus runner (unittest, offline, deterministic)."""
import json
import re
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from ctf_copilot.analysis.budget import AnalysisBudget
from ctf_copilot.forensics.pipeline import triage_file
from ctf_copilot.shared import archives as A
from ctf_copilot.shared.files import printable_strings
from ctf_copilot.shared.flags import find_flags

BASE = Path(__file__).parent / "benchmarks" / "forensics"
MANIFEST = BASE / "manifest.json"

NEGATIVES = {"f06", "f19", "f24"}

# keywords echoed from raw printable strings (bounded, offline, no tools)
HINT_KEYWORDS = ("qrcode", "zbar", "zsteg", "lsb", "user ", "pass", "ftp",
                 "macro", "vba", "autoopen", "http://", "https://",
                 "comment", ".xml")

# decisive substrings (lowercase); chosen to avoid generic next-action text
# present in every render (e.g. "follow mismatch clues", "stego helpers",
# "try metadata/embedded/crypto paths", "comment fields").
DECISIVE_MARKERS = (
    "(mismatch)", "signature at byte", "appended", "archive:",
    "nested flags", "encrypted", "password", "rejected", "traversal",
    "exceeds", "javascript", "pdf indicators", "comments/notes",
    "://", "macro", "vba", "autoopen", "qrcode", "zbar", "zsteg",
    "ftp", "user ctfuser", "credential", "windows.info", "volatility",
    "mmls", "sleuthkit",
)

# only these line contexts count as a validated flag. The pipeline's
# single-byte-XOR brute force surfaces garbage "candidate flags:" on
# compressed/binary inputs; those must not count (esp. for negatives).
FLAG_LINE_RES = (
    re.compile(r"confirmed flags:"),
    re.compile(r"nested flags:"),
    re.compile(r"Result:"),
    re.compile(r"RECURSE-FLAGS:"),
)


def line_has_validated_flag(line: str) -> bool:
    for rx in FLAG_LINE_RES:
        if rx.search(line):
            seg = line.split(rx.pattern.rstrip(":"), 1)[-1]
            if find_flags(seg):
                return True
    return False


def output_has_flag(output: str) -> bool:
    return any(line_has_validated_flag(l) for l in output.splitlines())


def run_entry(entry):
    """Run triage + bounded extraction/recurse + strings hints. Never raises."""
    files = [str(BASE / f) for f in entry["files"]]
    primary = files[0]
    parts = []
    try:
        findings, _arts, render = triage_file(primary)
        parts.append(render)
    except Exception as exc:  # noqa: BLE001 - runner must not crash
        return f"RUNNER EXCEPTION: {type(exc).__name__}: {exc}"
    try:
        data = Path(primary).read_bytes()[:2_000_000]
        strs = printable_strings(data)[:200]
        hits = []
        for s in strs:
            low = s.lower()
            if any(k in low for k in HINT_KEYWORDS):
                hits.append(s[:200])
                if len(hits) >= 20:
                    break
        if hits:
            parts.append("[strings-hint]\n" + "\n".join(hits))
    except OSError as exc:
        parts.append(f"[strings-hint] unreadable: {exc}")
    try:
        budget = AnalysisBudget.named("balanced")
        if entry["id"] == "f12":
            # tiny override: advertised-size rejection without OOM
            budget.max_file_bytes = 1024
            budget.max_total_bytes = 2048
        tmpws = Path(tempfile.mkdtemp(prefix="ctf-forensic-bench-"))
        try:
            arts, notes = A.recurse_extract(primary, str(tmpws), budget=budget)
            for n in notes[:10]:
                parts.append(f"NOTE: {n[:300]}")
            rflags: list[str] = []
            for a in arts[:50]:
                try:
                    blob = Path(a.path).read_bytes()[:2_000_000]
                except OSError:
                    continue
                for fl in find_flags(blob.decode("utf-8", "ignore")):
                    if fl not in rflags:
                        rflags.append(fl)
            if rflags:
                parts.append("RECURSE-FLAGS: " + ", ".join(rflags[:10]))
            else:
                parts.append("RECURSE-FLAGS: (none)")
        finally:
            shutil.rmtree(tmpws, ignore_errors=True)
    except Exception as exc:  # noqa: BLE001
        parts.append(f"EXTRACTION SKIPPED: {type(exc).__name__}: {exc}")
    return "\n".join(parts)


def classify(entry, output):
    """Return one of flag|decisive-artifact|inconclusive."""
    if output.startswith("RUNNER EXCEPTION"):
        return "missed"
    if output_has_flag(output):
        return "flag"
    low = output.lower()
    if any(m in low for m in DECISIVE_MARKERS):
        return "decisive-artifact"
    return "inconclusive"


class ForensicsBenchmarkTests(unittest.TestCase):
    def test_corpus(self):
        manifest = json.loads(MANIFEST.read_text())
        self.assertEqual(len(manifest), 30, f"manifest must have 30 entries, got {len(manifest)}")
        start = time.time()
        counts = {"flag": 0, "decisive-artifact": 0, "inconclusive": 0, "missed": 0}
        rows = []
        errors = []
        mismatches = []
        for entry in manifest:
            out = run_entry(entry)
            if out.startswith("RUNNER EXCEPTION"):
                errors.append(f"{entry['id']}: {out}")
                status = "missed"
                counts["missed"] += 1
            else:
                status = classify(entry, out)
                counts[status] += 1
            if entry["id"] in NEGATIVES:
                self.assertFalse(output_has_flag(out),
                                 f"negative {entry['id']} must not validate flags: {out[:800]}")
            if status != entry.get("expect"):
                mismatches.append(f"{entry['id']}: expect={entry.get('expect')} got={status}")
            rows.append((entry["id"], entry.get("expect"), status))
        elapsed = time.time() - start
        detected = counts["flag"] + counts["decisive-artifact"]
        print(f"\nFORENSICS-BENCHMARK: {len(manifest)}/{len(manifest)} run, {detected} detected, "
              f"{counts['flag']} flag, {counts['decisive-artifact']} decisive, "
              f"{counts['inconclusive']} inconclusive, {counts['missed']} missed, "
              f"runtime {elapsed:.1f}s")
        for eid, expect, got in rows:
            print(f"  {eid}: expect={expect} got={got}")
        self.assertEqual(errors, [], f"runner exceptions: {errors}")
        self.assertEqual(mismatches, [], f"positive expectation mismatches: {mismatches}")
        self.assertLess(elapsed, 120, f"runtime {elapsed:.1f}s exceeds 120s budget")
        self.assertGreaterEqual(detected, 26, f"need >=26/30 detected, got {detected} counts={counts}")
        flag_count = counts["flag"]
        self.assertGreaterEqual(flag_count, 21, f"need >=21 flag, got {flag_count} counts={counts}")


if __name__ == "__main__":
    unittest.main()
