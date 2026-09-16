"""Single source of truth for ALL flag detection, matching, validation and scoring.

Architecture:
    <repo-root>/config.toml
                     |
                     v
            shared/flags.py   <-- THIS FILE owns every flag regex/prefix
                     |
        +------------+----------------------------------+
        |            |                                  |
        v            v                                  v
      Crypto      Forensics                            Web
        |            |                                  |
        v            v                                  v
     Reverse        Pwn                              Network
        |            |                                  |
        v            v                                  v
      OSINT         Misc                              Flags
        +------------+------------------.--------------+
                     v
               engine/pipeline
                     |
                     v
                 ctf solve
                     |
                     v
            reports/workspaces

Rules:
- Built-in prefixes live in BUILTIN_PREFIXES below.
- Competition prefixes/patterns come from <repo-root>/config.toml
  ([flags] prefixes=[...] patterns=[...]). No Python edits needed.
- Generic ANYTHING{...} stays a lower-confidence candidate.
- Hot paths (quality()/has_known_flag() in beam search) only read the
  in-memory cache; config is parsed once and warnings are surfaced via
  get_flag_config_warnings() at command entry, never per-candidate.
"""
from __future__ import annotations

import re
import time
import warnings
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10: conditional dep `tomli>=2.0`
    import tomli as tomllib


BUILTIN_PREFIXES = ("flag", "ctf", "picoCTF", "HTB", "THM")

GENERIC_PREFIX_SRC = r"[A-Za-z0-9_-]{2,24}"
GENERIC_BODY_SRC = r"[^{}\r\n]{1,300}"

PLACEHOLDER_CONTENT = re.compile(
    r"(?i)^(?:\.{2,}|flag(?:[_ -]?(?:here|goes here))?|redacted|example|placeholder|xxx+|your[_ -]?flag)$"
)

# Backward-compatible static aliases (builtins only). New code must use the
# dynamic helpers below so configured prefixes are honored.
FLAG_PATTERNS = [
    re.compile(r"\b(?:flag|ctf|picoCTF|HTB|THM)\{[^{}\r\n]{1,300}\}", re.I),
    re.compile(r"\b[A-Za-z0-9_-]{2,24}\{[^{}\r\n]{1,300}\}"),
]
KNOWN_FLAG = re.compile(r"(?i)(?:flag|ctf|picoCTF|HTB|THM)\{")
FLAG_LIKE = re.compile(r"[A-Za-z0-9_-]{2,24}\{[^{}\r\n]{1,300}\}")

_CONFIG_FILENAME = "config.toml"
_CACHE_TTL_S = 1.0

_CACHE: dict = {
    "key": None,
    "known_prefixes": tuple(BUILTIN_PREFIXES),
    "custom_srcs": [],
    "known_re": None,
    "known_full_re": None,
    "generic_re": None,
    "custom_compiled": [],
    "warnings": [],
    "last_check": 0.0,
}
_CONFIG_OVERRIDE: str | None = None
_EMITTED_WARNINGS: set[str] = set()


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def default_config_path() -> Path:
    return _repo_root() / _CONFIG_FILENAME


def reload_flag_config(path: str | Path | None = None) -> None:
    """Point the loader at another config file (tests) and invalidate cache."""
    global _CONFIG_OVERRIDE
    _CONFIG_OVERRIDE = str(path) if path is not None else None
    _CACHE["key"] = None
    _CACHE["last_check"] = 0.0


def get_flag_config_warnings() -> list[str]:
    """Return cached config warnings (malformed TOML, bad regex). No I/O churn."""
    _ensure_loaded()
    return list(_CACHE["warnings"])


def emit_flag_config_warnings_once() -> list[str]:
    """Warn once per process per message. Entry points call this; hot paths never do."""
    msgs = get_flag_config_warnings()
    fresh = [m for m in msgs if m not in _EMITTED_WARNINGS]
    for m in fresh:
        _EMITTED_WARNINGS.add(m)
        warnings.warn(m, stacklevel=2)
    return fresh


def _resolve_path() -> Path:
    if _CONFIG_OVERRIDE is not None:
        return Path(_CONFIG_OVERRIDE)
    return default_config_path()


def _cache_key(path: Path):
    try:
        st = path.stat()
        return (str(path), st.st_mtime_ns, st.st_size)
    except OSError:
        return (str(path), None)


def _normalize_prefixes(raw, warnings_out: list[str]) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, (list, tuple)):
        warnings_out.append("flag config: [flags] prefixes must be a list of strings; ignoring.")
        return []
    seen: set[str] = set()
    out: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            warnings_out.append(f"flag config: ignoring non-string prefix {item!r}.")
            continue
        name = item.strip()
        if not name:
            continue
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(name)
    return out


def _compile_custom(srcs, warnings_out: list[str]) -> list:
    compiled = []
    seen: set[str] = set()
    for idx, src in enumerate(srcs):
        if not isinstance(src, str) or not src.strip():
            warnings_out.append(f"flag config: ignoring empty custom pattern at index {idx}.")
            continue
        if src in seen:
            continue
        seen.add(src)
        try:
            compiled.append(re.compile(src))
        except re.error as exc:
            warnings_out.append(f"flag config: invalid custom pattern at index {idx} ({src!r}): {exc}; skipping.")
    return compiled


def _read_config_file(path: Path) -> tuple[list[str], list[str], list[str]]:
    warn: list[str] = []
    try:
        raw = path.read_bytes()
    except OSError:
        return [], [], []
    if not raw.strip():
        return [], [], []
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except Exception as exc:
        return [], [], [f"flag config: malformed TOML in {path}: {exc}; using built-in defaults."]
    if not isinstance(data, dict):
        return [], [], [f"flag config: malformed TOML in {path}: top level must be a table; using built-in defaults."]
    section = data.get("flags", {})
    if section is None:
        section = {}
    if not isinstance(section, dict):
        return [], [], [f"flag config: [flags] must be a table in {path}; using built-in defaults."]
    prefixes = _normalize_prefixes(section.get("prefixes", []), warn)
    pat_raw = section.get("patterns", [])
    if pat_raw is None:
        pat_raw = []
    if not isinstance(pat_raw, (list, tuple)):
        warn.append(f"flag config: [flags] patterns must be a list of strings in {path}; ignoring.")
        pat_raw = []
    else:
        for i, p in enumerate(pat_raw):
            if not isinstance(p, str):
                warn.append(f"flag config: ignoring non-string custom pattern at index {i}.")
        pat_raw = [p for p in pat_raw if isinstance(p, str) and p.strip()]
    return prefixes, pat_raw, warn


def _build_known_re(prefixes) -> tuple:
    alts = sorted((re.escape(p) for p in prefixes), key=len, reverse=True)
    joined = "|".join(alts)
    prefix_re = re.compile(r"(?i)(?:" + joined + r")\{")
    full_re = re.compile(r"\b(?:" + joined + r")\{" + GENERIC_BODY_SRC + r"\}", re.I)
    return prefix_re, full_re


def _ensure_loaded():
    now = time.monotonic()
    if _CACHE["key"] is not None and (now - _CACHE["last_check"]) < _CACHE_TTL_S:
        return _CACHE
    path = _resolve_path()
    key = _cache_key(path)
    if key == _CACHE["key"]:
        _CACHE["last_check"] = now
        return _CACHE
    prefixes, pat_srcs, warn = _read_config_file(path)
    merged: list[str] = list(BUILTIN_PREFIXES)
    seen = {p.lower() for p in merged}
    for p in prefixes:
        if p.lower() not in seen:
            seen.add(p.lower())
            merged.append(p)
    custom_compiled = _compile_custom(pat_srcs, warn)
    known_re, known_full_re = _build_known_re(merged)
    generic_re = re.compile(r"\b" + GENERIC_PREFIX_SRC + r"\{" + GENERIC_BODY_SRC + r"\}", re.I)
    _CACHE.update(
        key=key,
        known_prefixes=tuple(merged),
        custom_srcs=list(pat_srcs),
        known_re=known_re,
        known_full_re=known_full_re,
        generic_re=generic_re,
        custom_compiled=custom_compiled,
        warnings=list(warn),
        last_check=now,
    )
    return _CACHE


def known_prefixes() -> tuple[str, ...]:
    return tuple(_ensure_loaded()["known_prefixes"])


def get_flag_patterns(extra_prefixes: list[str] | None = None) -> list:
    """All active patterns: known PREFIX{...} + custom + generic fallback."""
    st = _ensure_loaded()
    rows = [st["known_full_re"]]
    rows.extend(st["custom_compiled"])
    if extra_prefixes:
        extra = [p for p in (extra_prefixes or []) if isinstance(p, str) and p.strip()]
        if extra:
            alts = sorted((re.escape(p.strip()) for p in extra), key=len, reverse=True)
            rows.insert(0, re.compile(r"\b(?:" + "|".join(alts) + r")\{" + GENERIC_BODY_SRC + r"\}", re.I))
    rows.append(st["generic_re"])
    return rows


def is_placeholder_flag(value: str) -> bool:
    if "{" not in value or not value.endswith("}"):
        return True
    content = value[value.find("{") + 1:-1].strip()
    return not content or bool(PLACEHOLDER_CONTENT.fullmatch(content))


def _iter_matches(compiled, text: str):
    try:
        for m in compiled.finditer(text or ""):
            yield m.group(0)
    except Exception:
        return


def find_flags(text: str, extra_prefixes: list[str] | None = None) -> list[str]:
    """Find flag-like values: known/configured + custom + generic fallback."""
    st = _ensure_loaded()
    out: list[str] = []
    for compiled in get_flag_patterns(extra_prefixes):
        for match in _iter_matches(compiled, text):
            if not match or match in out:
                continue
            if "{" in match:
                if is_placeholder_flag(match):
                    continue
            out.append(match)
    return out


def _is_known_format(value: str) -> bool:
    st = _ensure_loaded()
    try:
        return bool(st["known_full_re"].fullmatch(value or ""))
    except Exception:
        return False


def _is_custom_format(value: str) -> bool:
    st = _ensure_loaded()
    for compiled in st["custom_compiled"]:
        try:
            if compiled.fullmatch(value or ""):
                return True
        except Exception:
            continue
    return False


def has_known_flag(text: str) -> bool:
    """True when a known/configured PREFIX{...} occurs (strong signal)."""
    if not text:
        return False
    st = _ensure_loaded()
    try:
        if st["known_re"].search(text):
            return True
        for compiled in st["custom_compiled"]:
            try:
                if compiled.search(text):
                    return True
            except Exception:
                continue
    except Exception:
        return False
    return False


def looks_flag_like(text: str) -> bool:
    """True for generic ANYTHING{...} (weak signal)."""
    if not text:
        return False
    try:
        return bool(_ensure_loaded()["generic_re"].search(text))
    except Exception:
        return False


def validate_flags(text: str, pattern: str | None = None, source_kind: str = "derived") -> tuple[list[str], list[str]]:
    """Return (validated, candidates), keeping source literals conservative.

    - Per-call ``pattern`` fullmatch always confirms (existing --flag-pattern).
    - Known/configured prefixes and config custom patterns confirm when the
      source is decoded/decrypted/extracted/response/direct.
    - Generic ANYTHING{...} stays a candidate unless the per-call pattern matches.
    """
    rows = find_flags(text)
    custom = None
    if pattern:
        try:
            custom = re.compile(pattern)
        except re.error:
            custom = None
        else:
            try:
                for m in custom.finditer(text or ""):
                    val = m.group(0)
                    if val and val not in rows:
                        if "{" in val and is_placeholder_flag(val):
                            continue
                        rows.append(val)
            except Exception:
                pass
    confirmed: list[str] = []
    candidates: list[str] = []
    good_source = source_kind in {"decoded", "decrypted", "extracted", "response", "direct"}
    for value in rows:
        try:
            if custom is not None and custom.fullmatch(value):
                confirmed.append(value)
            elif good_source and (_is_known_format(value) or _is_custom_format(value)):
                confirmed.append(value)
            else:
                candidates.append(value)
        except Exception:
            candidates.append(value)
    return list(dict.fromkeys(confirmed)), list(dict.fromkeys(candidates))


def find_flags_bytes(data: bytes, max_xor_bytes: int = 65_536) -> list[str]:
    """Find flags in ordinary/wide text and small single-byte-XOR blobs."""
    out = []
    for encoding in ('utf-8', 'utf-16le', 'utf-16be'):
        try:
            out.extend(find_flags(data.decode(encoding, 'ignore')))
        except UnicodeError:
            pass
    if len(data) <= max_xor_bytes:
        for key in range(256):
            text = bytes(value ^ key for value in data).decode('latin1')
            found = find_flags(text)
            if found:
                out.extend(found)
    return list(dict.fromkeys(out))
