COMMANDS = r"""
==============================
CTF COPILOT v0.5 COMMANDS
==============================

START HERE
  ctf solve <target>                     Unknown file/URL/text? Start here.
  ctf tools                              Check useful Kali tools.
  ctf commands                           Show this compact reference.

WEB
  ctf web analyze <url>                  Recon: forms, scripts, cookies, endpoints.
  ctf web test <url> --confirm-authorized [--headers --methods --xss --sqli]
                                         Controlled active probes on an authorized target.
  ctf web endpoints <url>                Extract endpoint-like paths.
  ctf web headers <url>                  Show response headers.
  ctf web jwt <token>                    Decode JWT header/payload.
  ctf web compare <url1> <url2>          Compare status and response size.

CRYPTO
  ctf crypto analyze <text>              Detect/follow likely encoding layers.
  ctf crypto decode <text>               Auto-decode recursively.
  ctf crypto decode <text> --kind hex    Decode a specific format.
  ctf crypto xor <hex>                   Try single-byte XOR candidates.
  ctf crypto frequency <text>            Character-frequency analysis.

FORENSICS
  ctf forensics triage <file>            First pass: file/ExifTool/Binwalk/strings.
  ctf forensics metadata <file>          ExifTool metadata.
  ctf forensics strings <file>           Printable strings.
  ctf forensics hex <file>               Hex preview.

REVERSE
  ctf reverse triage <binary>            Binary first pass.
  ctf reverse strings <binary>           High-signal strings.
  ctf reverse disasm <binary>            objdump disassembly.

PWN
  ctf pwn triage <binary>                Binary/pwn first pass.
  ctf pwn checksec <binary>              NX/PIE/Canary/RELRO.
  ctf pwn rop <binary>                   Preview useful ROP gadgets.

NETWORK
  ctf network resolve <host>             DNS/IP resolution.
  ctf network scan <host>                Common TCP-port scan.
  ctf network services <host>            Nmap service/version detection.

OSINT
  ctf osint domain <domain>              Passive DNS + WHOIS when available.
  ctf osint username <username>          Generate common profile leads.

MISC
  ctf misc morse <text>                  Decode Morse.
  ctf misc base <value> --from-base N --to-base N
  ctf misc timestamp <unix>              Convert Unix timestamp.

Rule of thumb:
  Don't know the category? -> ctf solve
  Know the category?       -> ctf <category> <action>

Use active network/web features only on CTF targets, your own systems, or systems you are explicitly authorized to test.
""".strip()
