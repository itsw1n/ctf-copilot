# Changelog

## v0.5.0

- Refactored the CLI around one clear category per command group.
- Removed confusing top-level duplicates: `analyze`, `decode`, `file`, `net`, and `recon`.
- Kept `ctf solve <target>` as the universal first-pass command.
- Moved decoding entirely under `ctf crypto`.
- Standardized network commands under `ctf network`.
- Simplified reverse engineering to `triage`, `strings`, and `disasm`.
- Simplified pwn to `triage`, `checksec`, and `rop`.
- Simplified forensics to `triage`, `metadata`, `strings`, and `hex`.
- Added a small passive `ctf osint` group for domain and username leads.
- Improved workspace creation to include `files/`, `extracted/`, `scripts/`, `output/`, and `notes.md`.
- Updated help text, README, and user agents to v0.5.

## v0.4.0

- Added `ctf solve` automatic first-pass triage.
- Added external-tool audit and orchestration helpers.
- Added controlled authorized web probes.
- Added forensics and binary triage helpers.
