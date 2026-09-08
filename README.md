# CTF Copilot v0.5

CTF Copilot is a small CLI that organizes common CTF first-pass work behind one clear command group per category. It is meant to save repetitive terminal work while still showing what was found and which specialized Kali tool is being used.

## Install on Kali

```bash
cd ~/tools/ctf-copilot
pipx install -e .
ctf --help
```

If an older editable version is already installed, source changes are picked up automatically. If the package location changed, reinstall with `pipx install -e . --force`.

## The command model

```text
ctf
├── solve        unknown challenge? start here
├── web          web exploitation
├── crypto       cryptography / encodings
├── forensics    files, images, archives, PCAP clues
├── reverse      reverse engineering
├── pwn          binary exploitation
├── network      network / recon
├── osint        passive public-information helpers
├── misc         Morse, bases, timestamps
├── workspace    challenge organization
├── flags        flag scanning
└── tools        Kali tool audit
```

There are no longer separate top-level `analyze`, `decode`, `net`, `recon`, or `file` commands. Their useful behavior now lives under the correct category.

## Fast examples

```bash
# Unknown challenge
ctf solve challenge.zip
ctf solve ./chall
ctf solve '666c61677b746573747d'

# Web
ctf web analyze 'https://authorized-target.example'
ctf web endpoints 'https://authorized-target.example'
ctf web test 'https://authorized-target.example/search?q=test' \
  --confirm-authorized --xss --sqli

# Crypto
ctf crypto analyze '666c61677b746573747d'
ctf crypto decode '666c61677b746573747d' --kind hex

# Forensics
ctf forensics triage mystery.png
ctf forensics metadata mystery.png

# Reverse / pwn
ctf reverse triage ./chall
ctf reverse disasm ./chall
ctf pwn checksec ./chall
ctf pwn rop ./chall

# Network
ctf network scan challenge.example
ctf network services challenge.example

# Help
ctf commands
ctf web --help
ctf pwn --help
```

## Web testing

`ctf web analyze` performs recon/inspection. `ctf web test` is different: it sends controlled active probes and therefore requires `--confirm-authorized`.

Current v0.5 probes cover security headers, HTTP method behavior, reflected-XSS indicators, and SQL-error/response-change indicators. They do not automatically dump databases, upload shells, brute-force passwords, or perform destructive actions.

## Tool orchestration

CTF Copilot prefers proven external tools instead of reimplementing them. Depending on the command, it can use tools such as `nmap`, `exiftool`, `binwalk`, `strings`, `readelf`, `objdump`, `checksec`, and `ROPgadget` when installed.

Run:

```bash
ctf tools
```

to see what is available on the current Kali VM.

## Safety

Use active network/web testing only on CTF targets, systems you own, or systems you are explicitly authorized to test. Unknown binaries should stay inside the CTF VM.
