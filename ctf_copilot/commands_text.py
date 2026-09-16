from __future__ import annotations
COMMANDS = r"""
CTF COPILOT v0.8 - QUICK COMMAND GUIDE
======================================

START HERE
  ctf solve <target>
      Use when you do not know the category. First-pass classification + useful category analysis.
  ctf tools
      Shows which external Kali helpers are installed.
  ctf tools --doctor
      Shows missing helpers and practical install/search hints.

CRYPTO - encoded/encrypted/hash-looking text
  ctf crypto analyze <text>
      Best first command for unknown encoded text. Detects likely formats, follows layers, ranks evidence.
  ctf crypto decode <text> --kind <type>
      Use when you already know the encoding/cipher and want a direct decode.
  ctf crypto xor <hex>
      Use for suspected single-byte XOR represented as hex.
  ctf crypto xor-repeat <hex>
      Use for suspected repeating-key XOR represented as hex.
  ctf crypto xor-crib <hex> --crib <text>
      Use when you know a likely plaintext fragment of an XOR ciphertext.
  ctf crypto vigenere <text>
      Use when the challenge suggests Vigenere; decrypts with a key or ranks candidates.
  ctf crypto rsa <params>
      Use for weak-RSA parameter sets (small e, shared primes, supplied factors).
  ctf crypto block <ciphertext>
      Use to inspect AES/DES blocks or decrypt with an explicitly supplied key.
  ctf crypto inspect <file-or-text>
      Use to find RSA/XOR/hash clues in text or Python source (never executed).
  ctf crypto template <source>
      Use to generate an editable solve.py scaffold from supplied crypto source.
  Specialist shortcuts (still available, see `ctf crypto --help`): caesar, jwt, hash.

FORENSICS - files/images/archives/network captures
  ctf forensics triage <file>
      Best first command for an unknown file: type, metadata, strings, embedded-data clues, flags.
  ctf forensics metadata <file>
      Use when metadata may hide author/comment/GPS/software clues.
  ctf forensics stego <image>
      Use when data may be hidden inside an image/audio file.
  ctf forensics archive <archive>
      Lists archive entries/encryption/nesting clues before extracting.
  ctf forensics recurse <archive>
      Safely inspects nested ZIPs/text for flags and encoded clues without executing files.
  ctf forensics pcap <capture.pcap>
      Summarizes protocols, DNS and HTTP from a packet capture using tshark.

REVERSE - understand a compiled program
  ctf reverse triage <binary>
      Best first command: file type, protections, interesting imports/symbols/strings.
  ctf reverse strings <binary>
      Looks for passwords, success/fail messages, keys and flags embedded in a binary.
  ctf reverse symbols <binary>
      Shows function/symbol names when available.
  ctf reverse functions <binary>
      Highlights interesting named functions such as main/check/win/flag/decrypt.
  ctf reverse imports <binary>
      Highlights imported functions such as strcmp/memcmp/gets/printf/system.
  ctf reverse disasm <binary> --function <name>
      Disassembles a selected function for closer inspection.

PWN - exploit a binary bug
  ctf pwn triage <binary>
      Explains protections + dangerous imports and suggests likely exploitation direction.
  ctf pwn checksec <binary>
      Shows NX/PIE/Canary/RELRO protections.
  ctf pwn cyclic create 200
      Generates a crash pattern for finding buffer-overflow offsets.
  ctf pwn cyclic offset 0x6161616c
      Finds where a cyclic crash value occurs in the pattern.
  ctf pwn rop <binary>
      Previews reusable ROP gadgets for advanced binary exploitation.

WEB - inspect an authorized CTF web application
  ctf web analyze <url>
      Passive first pass: forms, comments, cookies, scripts and endpoints.
  ctf web endpoints <url>
      Extracts interesting paths/API routes from HTML and JavaScript.
  ctf web js <url-or-js-url>
      Looks through JavaScript for endpoints, parameters and secret-looking strings.
  ctf web params <url>
      Lists parameter names that may be useful to test manually in Burp.
  ctf web headers <url>
      Shows headers and missing security-header hints.
  ctf web test <url> --confirm-authorized [--xss --sqli --methods]
      Controlled active indicators. Use only on CTF/owned/authorized targets.

NETWORK - discover services exposed by a CTF host
  ctf network scan <host>
      Quickly checks common TCP ports and suggests what category/tool to use next.
  ctf network services <host>
      Uses Nmap version detection to identify software behind open ports.
  ctf network dns <domain>
      Queries common DNS records.
  ctf network connect <host> <port>
      Connects to a challenge TCP service and reads its initial banner.

OSINT - passive public information
  ctf osint domain <domain>
      Passive DNS/WHOIS-style domain clues.
  ctf osint username <username>
      Generates common public profile leads for manual verification.

FLAGS / WORKSPACE / MISC
  ctf flags scan <file-or-directory>
      Recursively searches collected evidence for common flag patterns.
  ctf workspace new <name>
      Creates one flat challenge workspace folder with notes.md.
  ctf workspace note <name> <note>
      Saves a finding so you do not lose progress during competition.
  ctf misc morse <text> | base ... | timestamp ...
      Small conversions that do not need the full crypto analyzer.

Rule of thumb:
  Unknown challenge -> ctf solve <target>
  Unknown encoded text -> ctf crypto analyze <text>
  Unknown file -> ctf forensics triage <file>
  Unknown binary -> ctf reverse triage <binary> + ctf pwn triage <binary>
""".strip()
from . import __version__

def _app_version() -> str:
    return "v" + __version__

COMMAND_SECTIONS: list[tuple[str, list[tuple[str, str]]]] = [
    ("START HERE", [
        ("ctf solve <target>", "Unknown category first-pass classification + useful category analysis."),
        ("ctf tools", "Shows which external Kali helpers are installed."),
        ("ctf tools --doctor", "Shows missing helpers and practical install/search hints."),
    ]),
    ("CRYPTO - encoded/encrypted/hash-looking text", [
        ("ctf crypto analyze <text>", "Best first command for unknown encoded text."),
        ("ctf crypto xor <hex>", "Suspected single-byte XOR as hex."),
        ("ctf crypto xor-repeat <hex>", "Short repeating-key XOR candidates."),
        ("ctf crypto xor-crib <hex> --crib <text>", "Known-plaintext fragment / crib dragging."),
        ("ctf crypto vigenere <text> [--key KEY]", "Vigenere decrypt or key candidates."),
        ("ctf crypto block <ciphertext> [--key KEY]", "ECB inspection / decrypt with supplied key."),
        ("ctf crypto template <source> [--output]", "Generates editable solve.py scaffold."),
    ]),
    ("FORENSICS - files/images/archives/network captures", [
        ("ctf forensics triage <file>", "Best first command for unknown file."),
        ("ctf forensics metadata <file>", "EXIF/comment/GPS/software clues."),
        ("ctf forensics stego <image>", "Hidden data checks for image/audio."),
        ("ctf forensics archive <archive> [--password WORD] [--extract DIR]", "Lists entries, tests clue passwords, and optionally extracts."),
        ("ctf forensics recurse <archive>", "Safely inspects nested readable archive layers."),
        ("ctf forensics pcap <capture.pcap>", "Summarizes protocols/DNS/HTTP via tshark."),
    ]),
    ("REVERSE - understand a compiled program", [
        ("ctf reverse triage <binary>", "File type, protections, imports/symbols/strings."),
        ("ctf reverse strings <binary>", "Passwords, keys, flags in binary."),
        ("ctf reverse symbols <binary>", "Function/symbol names when available."),
        ("ctf reverse functions <binary>", "Interesting named functions."),
        ("ctf reverse imports <binary>", "Dangerous imports like system/strcmp."),
        ("ctf reverse disasm <binary> --function <name>", "Disassembles selected function."),
    ]),
    ("PWN - exploit a binary bug", [
        ("ctf pwn triage <binary>", "Protections + likely direction."),
        ("ctf pwn checksec <binary>", "NX/PIE/Canary/RELRO."),
        ("ctf pwn cyclic create 200", "Crash pattern for offsets."),
        ("ctf pwn cyclic offset 0x6161616c", "Finds crash value in pattern."),
        ("ctf pwn rop <binary>", "Reusable ROP gadgets preview."),
    ]),
    ("WEB - inspect an authorized CTF web application", [
        ("ctf web analyze <url>", "Passive forms/comments/cookies/scripts/endpoints."),
        ("ctf web source <path>", "Static source triage without execution."),
        ("ctf web cbc-bitflip <url> [cookie] --auto-cookie --confirm-authorized", "Authorized CBC cookie helper; can obtain a fresh auth_name cookie."),
        ("ctf web test <url> --confirm-authorized [--xss --sqli --methods]", "Controlled active indicators only on authorized targets."),
    ]),
    ("NETWORK - discover services exposed by a CTF host", [
        ("ctf network scan <host>", "Common TCP ports + next-step hints."),
        ("ctf network services <host>", "Nmap version detection."),
        ("ctf network dns <domain>", "Common DNS records."),
        ("ctf network connect <host> <port>", "Banner grab from TCP service."),
    ]),
    ("OSINT - passive public information", [
        ("ctf osint domain <domain>", "Passive DNS/WHOIS-style clues."),
        ("ctf osint username <username>", "Public profile leads for manual verification."),
    ]),
    ("FLAGS / WORKSPACE / MISC", [
        ("ctf flags scan <file-or-directory>", "Flag-pattern search in evidence."),
        ("ctf solve <target> --workspace <name>", "Save structured report."),
        ("ctf report <workspace>", "Show saved structured report."),
        ("ctf workspace new <name>", "One flat challenge workspace folder."),
        ("ctf workspace flatten <name>", "Flatten an older nested workspace."),
        ("ctf workspace note <name> <note>", "Save finding during competition."),
        ("ctf misc morse <text> | base ... | timestamp ...", "Small conversions."),
    ]),
]

SPECIALIST_SECTIONS: list[tuple[str, list[tuple[str, str]]]] = [
    ("CRYPTO specialists (hidden from --help, still work)", [
        ("ctf crypto decode <text> --kind <type>", "Direct decode when you know the type."),
        ("ctf crypto caesar <text>", "Rank Caesar letter shifts."),
        ("ctf crypto jwt <token>", "Decode JWT header/payload."),
        ("ctf crypto hash <value>", "Identify likely hash family."),
        ("ctf crypto rsa <file-or-text>", "Bounded RSA weakness analysis."),
        ("ctf crypto inspect <file-or-text>", "Finds RSA/XOR/hash clues without executing source."),
    ]),
    ("WEB specialists (hidden from --help, still work)", [
        ("ctf web endpoints <url>", "Paths/API routes from HTML/JS."),
        ("ctf web js <url-or-js-url>", "Endpoints/params/secrets in JavaScript."),
        ("ctf web params <url>", "Parameter names for manual Burp testing."),
        ("ctf web headers <url>", "Headers and missing security hints."),
        ("ctf web map <url> [--max-pages N]", "Bounded passive same-origin crawl."),
        ("ctf web jwt <token>", "Decode JWT header/payload."),
    ]),
    ("FORENSICS specialists (hidden from --help, still work)", [
        ("ctf forensics evidence <file>", "Correlates magic bytes and embedded clues."),
    ]),
]

HIDDEN_COMMANDS = tuple(cmd for _, items in SPECIALIST_SECTIONS for cmd, _ in items)


def render_commands(use_color: bool = True, show_all: bool = False) -> str:
    from .shared.style import header, section, cmd, dim
    lines = [header(f"CTF COPILOT {_app_version()} - QUICK COMMAND GUIDE", enabled=use_color), "=" * 38, ""]
    for title, items in COMMAND_SECTIONS:
        lines.append(section(title, enabled=use_color))
        for command, desc in items:
            lines.append(f"  {cmd(command, enabled=use_color)}")
            lines.append(f"      {dim(desc, enabled=use_color)}")
        lines.append("")
    if show_all:
        for title, items in SPECIALIST_SECTIONS:
            lines.append(section(title, enabled=use_color))
            for command, desc in items:
                lines.append(f"  {cmd(command, enabled=use_color)}")
                lines.append(f"      {dim(desc, enabled=use_color)}")
            lines.append("")
    else:
        lines.append(dim("Specialist commands hidden from --help still work; see `ctf commands --all`.", enabled=use_color))
        lines.append("")
    lines += [
        section("Rule of thumb:", enabled=use_color),
        "  Unknown challenge -> ctf solve <target>",
        "  Unknown encoded text -> ctf crypto analyze <text>",
        "  Unknown file -> ctf forensics triage <file>",
        "  Unknown binary -> ctf reverse triage <binary> + ctf pwn triage <binary>",
    ]
    return "\n".join(lines).strip()
