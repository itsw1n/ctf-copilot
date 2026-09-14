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
  ctf crypto caesar <text>
      Use when letters look shifted; ranks Caesar rotations.
  ctf crypto xor <hex>
      Use for suspected single-byte XOR represented as hex.
  ctf crypto jwt <token>
      Decodes JWT header/payload only; does NOT prove or verify the signature.
  ctf crypto hash <digest>
      Identifies likely hash families so you know which John/Hashcat mode to investigate.

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
      Creates a clean challenge workspace with files/extracted/evidence/notes folders.
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
