# CTF Copilot v0.9

CTF Copilot is a beginner-friendly CLI for **authorized CTF challenges and practice labs**. It organizes repeatable first-pass work by category while relying on proven Kali tools where appropriate.

The design goal is not “magically solve every CTF.” It is:

> classify the challenge → run useful first checks → surface evidence → recommend the next action.

It is designed to automate common **easy and medium** CTF first-pass work, not
to guarantee a solve for every custom or advanced challenge.

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

## New v0.9 follow-up commands

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
