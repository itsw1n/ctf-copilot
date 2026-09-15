# Changelog

## Unreleased

- Moved required runtime deps (`requests`, `pycryptodome`) into `pyproject.toml [project] dependencies`; remaining helpers stay optional extras. `requirements.txt` carries a sync header with the same set.
- Audited `requirements-system.txt`: every invoked external helper now has a command-to-Kali-package mapping comment; `ctf tools --doctor` inventory matches the actually invoked tool set.
- Limited the beginner command guide to the primary crypto commands (`analyze`, `decode`, `rsa`, `xor`, `xor-repeat`, `xor-crib`, `vigenere`, `block`, `inspect`, `template`); `caesar`/`jwt`/`hash` stay as specialist compat shortcuts.
- Documented the six primary commands, the `--input`/`--budget`/`--workspace`/`--crawl`/`--confirm-authorized` flags, and measured representative-corpus results in the README.
- Minor cleanup: removed a duplicate `import re`, fixed an expression-statement append, and made crypto detection web-only for URLs (`solve` routes URLs to the passive web analyzer).

## v1.0.1

- Made `ctf_copilot.__version__` the single source for package and command-guide versions.
- Added an MIT license and refreshed the README with release, platform, Python, and license badges.

## v1.0.0

- Added recursive forensic evidence checks, safe archive helpers, stego/metadata handoffs, and bounded flag discovery.
- Added the authorized CBC cookie bit-flip helper, including optional fresh-cookie acquisition and progress feedback.
- Simplified challenge workspaces to a flat folder layout.
- Added a required-dependency installer that checks installed Kali packages before requesting `sudo` for only missing packages.
- Updated the beginner workflow, command guide, and test coverage for the v1.0 release.

## v0.9.0

- Added structured evidence reports, challenge workspaces, and saved reports.
- Added optional challenge descriptions and custom flag-pattern support to `ctf solve`.
- Added passive web mapping and static web source triage.
- Added crypto context/source inspection, weak RSA checks, repeating-key XOR candidates, and editable solver scaffolds.
- Added forensic evidence correlation, explicit encrypted-ZIP password candidates, and TCP payload clue analysis.
- Added category-filtered tool doctor output and tests for new workflows.

## v0.8.0

- Reworked crypto analysis into evidence-driven beam search.
- Strong structural formats now outrank speculative classical-cipher guesses.
- Added depth/speculation penalties and explainable decode chains.
- Added safe recursive nested-ZIP/encoded-clue forensics helper.
- Added reverse `functions` and `imports` helpers.
- Added pwn triage explanations and next-step recommendations.
- Added web JavaScript and parameter discovery helpers.
- Added network scan next-step recommendations.
- Added beginner-friendly command descriptions throughout `--help`.
- Added `ctf commands` quick guide.
- Improved `ctf solve` orchestration and recommendations.

## v0.7.0

- Category package reorganization and initial automatic crypto analyzer.
