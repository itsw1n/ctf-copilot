# Changelog

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
