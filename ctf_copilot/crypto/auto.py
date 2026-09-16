from __future__ import annotations

from pathlib import Path
import re

from .analyzer import analyze
from .block import repeated_blocks
from .classical.affine import crack as affine_crack
from .classical.transposition import candidates as transposition_candidates
from .classical.vigenere import crack as vigenere_crack
from .formats.hashes import identify as identify_hash
from .inspect import inspect_python, inspect_text
from .normalization import load_value, parse_bytes, readable
from .rsa_engine import parse_records, render_rsa
from .scoring import has_known_flag, quality
from .xor.engine import known_plaintext, repeating, single, xor_values
from ..shared.flags import emit_flag_config_warnings_once, find_flags


def _chain(result) -> str:
    return " -> ".join(f"{step.kind}({step.parameter})" if step.parameter else step.kind for step in result.chain)


def _known_or_pattern(text: str, pattern: str | None) -> bool:
    """Shared known/configured match OR per-call --flag-pattern hit."""
    if has_known_flag(text or ""):
        return True
    if pattern:
        try:
            return bool(re.compile(pattern).search(text or ""))
        except re.error:
            return False
    return False


def analyze_target(target: str, related: list[str] | None = None, description: str = "",
                   flag_pattern: str | None = None, known_plaintexts: list[str] | None = None,
                   max_depth: int = 6) -> str:
    emit_flag_config_warnings_once()
    related = related or []
    known_plaintexts = known_plaintexts or []
    primary = load_value(target)
    values = [primary] + [load_value(item) for item in related]
    text = primary.text
    lines = ["CRYPTO ANALYSIS", "===============", f"Input: {primary.source}", f"Representation: {primary.representation}"]
    findings = 0

    if Path(target).is_file() and Path(target).suffix.lower() == ".py":
        lines += ["", inspect_python(target)]
        findings += 1
    if text:
        results = analyze(text, max_depth=max(1, min(max_depth, 8)))
        if results:
            lines += ["", "LAYERED TRANSFORM CANDIDATES"]
            for index, result in enumerate(results[:5], 1):
                lines += [f"[{index}] {_chain(result)}", f"  Evidence: {result.chain[-1].reason}", f"  Result: {result.output[:800]}"]
            findings += 1

        hashes = identify_hash(text)
        decoded_flag = any(_known_or_pattern(result.output, flag_pattern) for result in results)
        if hashes and not decoded_flag:
            lines += ["", "HASH IDENTIFICATION"]
            for name, evidence in hashes:
                lines += [f"Candidate: {name}", f"Evidence: {evidence}"]
            lines += ["Meaning: this identifies a hash family; it does not decode the digest."]
            findings += 1

    combined_sources = []
    for item in [target] + related:
        value = load_value(item)
        if value.text:
            combined_sources.append(value.text)
    rsa_context = combined_sources + ([description] if description else [])
    if parse_records(rsa_context):
        lines += ["", render_rsa(rsa_context)]
        findings += 1

    context = "\n".join(combined_sources + [description]).lower()
    xor_hint = bool(re.search(r"\b(?:xor|exclusive.or|crib|keystream)\b", context))
    if xor_hint and primary.raw:
        # Auto stays bounded small (16) for noise: full 2-40 window is
        # available via `ctf crypto xor-repeat --max-key-size 40`.
        xor_rows = single(primary.raw.hex()) + repeating(primary.raw.hex(), max_key_size=16)
        for crib in known_plaintexts:
            xor_rows.extend(known_plaintext(primary.raw.hex(), crib))
        useful = sorted(xor_rows, key=lambda row: row.score, reverse=True)
        useful = [row for row in useful if _known_or_pattern(row.plaintext, flag_pattern) or row.score >= quality(primary.text or "") + .6][:5]
        if useful:
            lines += ["", "XOR CANDIDATES"]
            for row in useful:
                lines += [f"Technique: {row.technique}", f"Evidence: {row.evidence}", f"Key: {row.key!r}", f"Result: {row.plaintext[:600]}"]
            findings += 1
    if len(values) >= 2 and xor_hint:
        combined = xor_values(values[0].raw, values[1].raw)
        text_result = readable(combined)
        lines += ["", "TWO-INPUT XOR", f"Result bytes: {combined!r}"]
        if text_result:
            lines.append(f"Result text: {text_result}")
        findings += 1

    classical_hint = context
    if text and len(re.sub(r"[^A-Za-z]", "", text)) >= 24:
        baseline = quality(text)
        if "vigen" in classical_hint:
            candidates = vigenere_crack(text)
            candidates = [row for row in candidates if row.score >= baseline + .35 or _known_or_pattern(row.plaintext, flag_pattern)]
            if candidates:
                lines += ["", "VIGENERE CANDIDATES"]
                for row in candidates[:5]:
                    lines += [f"Key: {row.key}", f"Evidence: average IC={row.key_length_score:.4f}", f"Result: {row.plaintext[:600]}"]
                findings += 1
        if "affine" in classical_hint:
            rows = [row for row in affine_crack(text) if row[0] >= baseline + .35 or _known_or_pattern(row[3], flag_pattern)]
            if rows:
                lines += ["", "AFFINE CANDIDATES"] + [f"a={a} b={b}: {plain[:600]}" for _, a, b, plain in rows[:5]]
                findings += 1
        if any(hint in classical_hint for hint in ("rail", "transposition", "column")):
            rows = [row for row in transposition_candidates(text) if row[0] >= baseline + .35 or _known_or_pattern(row[3], flag_pattern)]
            if rows:
                lines += ["", "TRANSPOSITION CANDIDATES"] + [f"{kind} {parameter}: {plain[:600]}" for _, kind, parameter, plain in rows[:5]]
                findings += 1

    raw_for_blocks = primary.raw
    if text:
        try:
            raw_for_blocks = parse_bytes(text, "auto")
        except ValueError:
            pass
    if raw_for_blocks and len(raw_for_blocks) >= 32 and len(raw_for_blocks) % 16 == 0:
        blocks, repeats = repeated_blocks(raw_for_blocks, 16, "raw")
        if repeats or re.search(r"\b(?:aes|des|3des|ecb|cbc|ctr)\b", context):
            lines += ["", "BLOCK-CIPHER INSPECTION", f"Complete 16-byte blocks: {blocks}", f"Repeated blocks: {repeats}"]
            if repeats:
                lines += ["Finding: repeated ciphertext blocks support an ECB hypothesis."]
            lines += ["Next: supply an explicit key/mode to `ctf crypto block`; unknown keys are not brute-forced automatically."]
            findings += 1

    direct_flags = []
    for value in combined_sources:
        direct_flags.extend(find_flags(value))
    if flag_pattern:
        try:
            _rx = re.compile(flag_pattern)
            for value in combined_sources:
                for m in _rx.finditer(value or ""):
                    if m.group(0) and m.group(0) not in direct_flags:
                        direct_flags.append(m.group(0))
        except re.error:
            pass
    if direct_flags:
        lines += ["", "FLAG-LIKE SOURCE VALUES (UNCONFIRMED)"] + [f"  {flag}" for flag in dict.fromkeys(direct_flags)]
        lines += ["Source literals are not marked solved until a decoding/decryption path validates them."]

    if not findings:
        lines += ["", inspect_text(description + "\n" + (text or "")), "", "No supported technique produced strong evidence.", "Next: inspect the challenge description and supplied source/files; do not assume random-looking data is an encoding."]
    return "\n".join(lines)
