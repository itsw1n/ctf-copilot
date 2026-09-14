# Changelog

## 0.7.0
- Reorganized every major CTF category into its own package.
- Kept `cli.py` as command wiring and `solve.py` as cross-category orchestration.
- Upgraded crypto auto-analysis with ranked candidates, Caesar scoring, recursion/backtracking, Base32/Base85/HTML/Morse/JWT support, hash identification, and XOR helpers.
- Added forensic archive, PCAP, and stego triage commands.
- Added reverse symbols/function disassembly helpers.
- Added pwn cyclic pattern helpers.
- Added network DNS and TCP banner helpers.
- Added recursive flag scanning with custom prefixes.
- Added workspace info/evidence directory and tool doctor.
