# CTF Copilot v0.7

A modular Kali CLI for **first-pass CTF analysis**. It does not replace specialist tools such as Wireshark, Ghidra, Burp Suite, nmap, sqlmap, or GDB; it organizes common workflows and surfaces useful leads quickly.

## Install

```bash
cd ctf-copilot
pipx install -e . --force
ctf --help
```

## Architecture

```text
ctf_copilot/
├── cli.py
├── solve.py
├── crypto/
│   ├── commands.py
│   ├── analyzer.py
│   ├── scoring.py
│   ├── models.py
│   ├── encodings/
│   ├── classical/
│   ├── xor/
│   └── formats/
├── web/
│   ├── commands.py
│   ├── analyzer.py
│   ├── client.py
│   ├── endpoints.py
│   ├── headers.py
│   ├── probes/
│   └── tools/
├── forensics/
│   ├── commands.py
│   ├── triage.py
│   ├── metadata.py
│   ├── archive.py
│   ├── pcap.py
│   └── stego.py
├── reverse/
├── pwn/
├── network/
├── osint/
├── misc/
├── workspace/
├── flags/
└── shared/
```

`commands.py` wires CLI arguments. The other files contain reusable logic. `solve.py` orchestrates categories instead of duplicating their implementations.

## Useful commands

```bash
# Unknown challenge
ctf solve challenge.zip
ctf solve mystery.png
ctf solve ./chall
ctf solve 'SGVsbG8='

# Crypto
ctf crypto analyze "b'wpjvJAM{jhlzhy_k3jy9wa3k_h47j6k69}'"
ctf crypto decode '48656c6c6f' --kind hex
ctf crypto caesar 'khoor'
ctf crypto xor '1d0c...'                 # hex input
ctf crypto jwt 'eyJ...'
ctf crypto hash '5f4dcc3b5aa765d61d8327deb882cf99'

# Forensics
ctf forensics triage mystery.png
ctf forensics metadata mystery.jpg
ctf forensics stego mystery.png
ctf forensics archive challenge.zip
ctf forensics pcap traffic.pcap
ctf forensics strings mystery.bin
ctf forensics hex mystery.bin --bytes 256

# Reverse / pwn
ctf reverse triage ./chall
ctf reverse strings ./chall
ctf reverse symbols ./chall
ctf reverse disasm ./chall --function main
ctf pwn checksec ./chall
ctf pwn rop ./chall
ctf pwn cyclic create 200
ctf pwn cyclic offset 0x61616162

# Web
ctf web analyze https://authorized-target.example
ctf web endpoints https://authorized-target.example
ctf web headers https://authorized-target.example
ctf web test 'https://authorized-target.example/search?q=test' --confirm-authorized --xss --sqli

# Network
ctf network resolve challenge.example
ctf network scan challenge.example
ctf network services challenge.example
ctf network dns challenge.example
ctf network connect challenge.example 31337

# Flags / workspace / tools
ctf flags scan ./challenge-folder
ctf flags scan . --prefix ACDCTF
ctf workspace new web-login
ctf workspace note web-login 'Possible IDOR on /api/users/:id'
ctf workspace info web-login
ctf tools
ctf tools --doctor
```

## Crypto automation

`ctf crypto analyze` ranks multiple candidates and can follow plausible layers recursively. Current automatic coverage includes Base64, Base32, Base16/hex, Base85/ASCII85, decimal ASCII, binary, URL encoding, HTML entities, Morse, Caesar/ROT13, Atbash, JWT-like values, gzip reached through supported byte decoders, and readable candidate scoring.

It intentionally does **not** claim to automatically crack arbitrary AES/RSA/Vigenere/substitution challenges. Those need keys, parameters, mathematics, statistical analysis, or challenge-specific context.

## Web safety

`ctf web analyze`, `headers`, and `endpoints` are inspection/recon helpers. `ctf web test` sends controlled active probes and requires `--confirm-authorized`. Use active testing only on CTF targets, systems you own, or systems you are explicitly authorized to test.
