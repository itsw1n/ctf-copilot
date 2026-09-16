# CTF Copilot

[![Latest release tag](https://img.shields.io/github/v/tag/itsw1n/ctf-copilot?label=release)](https://github.com/itsw1n/ctf-copilot/tags)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB?logo=python&logoColor=white)](pyproject.toml)
[![Platform Kali/Linux](https://img.shields.io/badge/platform-Kali%20%2F%20Linux-557C94?logo=linux&logoColor=white)](#safe-install-on-kalilinux)
[![License MIT](https://img.shields.io/badge/license-MIT-yellow.svg)](LICENSE)

CTF Copilot is a beginner-friendly command-line assistant for **authorized CTF challenges and practice labs**. It turns a blank starting point into evidence, practical next steps, and repeatable workflows—without pretending that every challenge has a one-command solution.

```text
classify → collect evidence → test the lowest-cost useful action → explain what to do next
```

It is aimed at common **easy and medium** challenge patterns. Hard, custom, or multi-stage challenges still need your reasoning; the tool should make that reasoning faster and more organized.

## What it helps with

| Category      | First-pass help                                                                      |
| ------------- | ------------------------------------------------------------------------------------ |
| Crypto        | Encodings, Caesar/ROT, XOR, RSA checks, supplied encryption-source inspection        |
| Forensics     | File triage, strings, metadata, archives, embedded data, stego and PCAP handoffs     |
| Web           | Passive same-origin mapping, forms, scripts, endpoints, parameters, authorized tests |
| Reverse / Pwn | Binary triage, imports, functions, protections, and next-step hints                  |
| Workflow      | Workspaces, reports, flag scans, tool doctor, and beginner-oriented command help     |

## Install

Requires Python 3.10+ (3.11 or 3.12 recommended) and `cmake` with a C compiler.

```bash
git clone git@github.com:itsw1n/ctf-copilot.git ctf-copilot && cd ctf-copilot
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
ctf --help
```

Run `source .venv/bin/activate` once in each new terminal.

Install the system tools manually from [`requirements-system.txt`](requirements-system.txt) using your package manager — check what's missing with `ctf tools --doctor`.

### Kali (alternative)

On Kali Linux you can skip the manual steps above — the installer handles everything including system packages:

```bash
cd ~/tools/ctf-copilot
./scripts/install.sh
source .venv/bin/activate
ctf --help
```

## Start in 30 seconds

```bash
# See the guided command list
ctf commands

# Start with an unknown file, URL, archive, or encoded string
ctf solve <target>

# See the evidence report again later, when using a workspace
ctf report <workspace-name>
```

## Windows

The pure-Python core can run on Windows with Python 3.10+, but the complete
forensics playbooks depend on Linux/Kali command-line tools. For the full
experience on a Windows computer, use WSL2 with Kali or Ubuntu and follow the
Linux install steps above.

## Learn the commands

```bash
ctf commands
ctf crypto --help
ctf forensics --help
ctf web --help
```

Every category/action includes a short description explaining **what it does and when to use it**.

## Main workflow

```text
ctf solve <target>       unknown challenge: start here
ctf crypto ...           encoded/cipher/hash-looking text
ctf forensics ...        images/files/archives/PCAP evidence
ctf reverse ...          understand compiled programs
ctf pwn ...              investigate binary exploitation paths
ctf web ...              authorized web CTF reconnaissance/testing
ctf network ...          discover exposed services
ctf osint ...            passive public-information leads
ctf flags ...            recursively search for flag-like strings
ctf workspace ...        organize challenge notes/evidence
ctf misc ...             small conversions
```

For most challenges, you only need one command:

```bash
ctf solve <target>
```

`<target>` may be a file, ZIP, PCAP, directory, URL, or encoded text. The
challenge description is optional, but useful when it contains a password or
important hint:

```bash
ctf solve challenge.zip --description 'password: school2026' --workspace zip-01
ctf report zip-01
```

The report explains the tool used, what it found, why it matters, and the next
suggested command.

## Focused follow-up commands

Use these only when `ctf solve` or the challenge evidence points you there:

```bash
# Web: passive same-origin crawl or supplied source code
ctf web map http://challenge.local
ctf web source extracted-web-source/

# Crypto: clues, weak RSA, repeating-key XOR, safe solve-script scaffold
ctf crypto inspect encrypt.py
ctf crypto rsa rsa-values.txt
ctf crypto xor-repeat <hex-ciphertext>
ctf crypto template encrypt.py

# Forensics: evidence correlation and encrypted ZIP clue passwords
ctf forensics evidence mystery.pdf
ctf forensics archive challenge.zip --password school2026
```

## High-value examples

### Unknown encoded text

```bash
ctf crypto analyze '4d6a41784e444d3d'
```

The analyzer uses structural evidence + beam search. It should prefer a strong chain such as:

```text
hex -> base64 -> 20143
```

over speculative Caesar guesses.

### Caesar challenge

```bash
ctf crypto analyze 'wpjvJAM{jhlzhy_k3jy9wa3k_h47j6k69}'
```

### Unknown file

```bash
ctf forensics triage mystery.png
```

### Nested ZIP challenge

```bash
ctf forensics recurse challenge.zip
```

This safe helper inspects nested ZIP/readable content as **data only** and never executes files.

### Binary

```bash
ctf reverse triage ./chall
ctf reverse imports ./chall
ctf reverse functions ./chall
ctf pwn triage ./chall
```

### Authorized web challenge

```bash
ctf web analyze http://challenge.local
ctf web endpoints http://challenge.local
ctf web params http://challenge.local
ctf web js http://challenge.local/app.js
```

Controlled active probes require explicit confirmation:

```bash
ctf web test 'http://challenge.local/search?q=test' --confirm-authorized --xss --sqli
```

## Tool audit

```bash
ctf tools
ctf tools --doctor
ctf tools --doctor --category forensics
```

CTF Copilot may orchestrate external tools such as `file`, `strings`, `exiftool`, `binwalk`, `tshark`, `checksec`, `readelf`, `objdump`, `ROPgadget`, and `nmap` when installed.

## Safety

Use active web/network testing only on CTF targets, systems you own, or systems you are explicitly authorized to test. Unknown binaries should stay inside your CTF VM.

## License

Released under the [MIT License](LICENSE).
