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

| Category | First-pass help |
| --- | --- |
| Crypto | Encodings, Caesar/ROT, XOR, RSA checks, supplied encryption-source inspection |
| Forensics | File triage, strings, metadata, archives, embedded data, stego and PCAP handoffs |
| Web | Passive same-origin mapping, forms, scripts, endpoints, parameters, authorized tests |
| Reverse / Pwn | Binary triage, imports, functions, protections, and next-step hints |
| Workflow | Workspaces, reports, flag scans, tool doctor, and beginner-oriented command help |

## Safe install on Kali/Linux

```bash
cd ~/tools/ctf-copilot
./scripts/install.sh
source .venv/bin/activate
ctf --help
```

The installer uses a project-local Python virtual environment (`.venv`) and
does not modify your system Python. It also checks every package in
`requirements-system.txt`. If all required Kali helpers already exist, it does
not use `sudo`. If any are missing, it prints the exact missing package names
and uses `sudo apt` to install only those packages from your configured Kali
repositories.

`sudo` is needed only for system package installation; the `ctf` command never
runs as root. Review the repository and the package list before running an
installer on any machine. At the end, the installer runs:

```bash
ctf tools --doctor
```

to show which command-line helpers are available.

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

## Primary commands

Six commands cover the beginner first pass; everything else is a specialist
follow-up (see `ctf commands` and `ctf <category> --help`):

```bash
ctf solve <target>            # unknown challenge: classify + safe first pass
ctf crypto analyze <text>     # unknown encoded/cipher text
ctf forensics triage <file>   # unknown file: type, metadata, strings, embedded clues
ctf web analyze <url>         # passive web first pass (add --crawl N for same-origin pages)
ctf reverse triage <binary>   # binary protections, imports, high-signal strings
ctf report <workspace>        # show the saved structured report again
```

Compat shortcuts stay available but are not in the beginner list:
`ctf crypto caesar`, `ctf crypto jwt`, `ctf crypto hash` (see `ctf crypto --help`).
Primary crypto commands (`decode`, `template`, plus xor/rsa/block/inspect/vigenere
and the other per-category actions) remain in `ctf commands`.

Useful flags:

- `ctf solve <target> --input <value-or-file>` (repeatable): related values
  for RSA/XOR correlation; prefix literal text with `text:`.
- `--budget fast|balanced|deep`: analysis budget profile (`solve`, forensics triage).
- `--workspace <name>`: save a structured report (`solve`, forensics triage).
- `ctf web analyze <url> --crawl N`: bounded same-origin GET-only crawl.
- `ctf web test <url> --confirm-authorized ...`: controlled active probes;
  only on CTF/owned/authorized targets.

## Measured corpus results

Representative offline corpora bundled under `tests/benchmarks/`
(run with `python3 -m unittest discover -s tests`):

- Crypto: supported representative corpus: 29/32 patterns detected, 27/32
  decisive (solved or decisive next step), not an estimate of arbitrary
  competition solve rate.
- Forensics: supported representative corpus: 27/30 patterns detected, 21/30
  with flag validated, not an estimate of arbitrary competition solve rate.
- Web: supported representative corpus: 25/25 correct — 21/21 applicable
  patterns plus 4/4 safety/negative cases (mocked fixtures, ~0.2s) — not an
  estimate of arbitrary competition solve rate.

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
