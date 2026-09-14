# CTF Commands Color Design — 2026-09-14

## Purpose
Make `ctf commands` scannable in Kali terminals. Keep plain-white fallback for pipes, `NO_COLOR`, and `--no-color`. Zero new dependencies.

## Constraints
- Stdlib ANSI only (`dependencies=[]` must stay empty).
- Auto-disable colors when `--no-color` flag is set, `NO_COLOR` env exists, or `stdout` is not a TTY.
- Preserve existing `COMMANDS` plain text for backwards compatibility and tests.
- Fix hardcoded `v0.8` header to use dynamic package version.

## Architecture
One new shared module plus two edits:

1. `ctf_copilot/shared/style.py` (new, ~60 lines):
   - `supports_color(no_color_flag: bool = False) -> bool` — returns False if flag is True, `NO_COLOR` env var is set (non-empty), or `sys.stdout.isatty()` is False; never raises.
   - `c(text, *codes, enabled: bool) -> str` — wraps in ANSI only when `enabled` is True, else returns `text` unchanged. No global mutable state.
   - Helpers take explicit `enabled` flag: `header()`, `section()`, `cmd()`, `dim()`, `rule()`.
   - Palette: headers bold yellow, sections bold cyan, commands bold green, descriptions default, details dim.
2. `ctf_copilot/commands_text.py` (edit):
   - Keep `COMMANDS` as-is (plain).
   - Add `COMMAND_SECTIONS: list[tuple[str, list[tuple[str, str]]]]`.
   - Add `render_commands(use_color: bool = True) -> str` that renders from sections.
   - Plain render must contain every command currently in `COMMANDS`.
3. `ctf_copilot/cli.py` (edit):
   - Add top-level `--no-color` flag before subparsers.
   - Change `commands` handler from `print(COMMANDS)` to `print(render_commands(use_color=supports_color(args.no_color)))`.

## Data Flow
`ctf [--no-color] commands` → `argparse` → `supports_color()` → `render_commands()` → `print`.
No file I/O. No network. Failure in TTY detection defaults to plain output.

## Error Handling
- `supports_color()` never raises; any exception path returns `False` (plain).
- Unknown terminal types get plain output rather than broken escape codes.
- Tests assert plain output has no `\x1b` sequences.

## Testing
Extend `tests/test_cli.py`:
- `render_commands(use_color=False)` contains `ctf solve`, `ctf crypto analyze`, `ctf forensics triage`, rule-of-thumb block, and no `\x1b`.
- `render_commands(use_color=True)` contains `\x1b[` sequences and same commands.
- `supports_color(True) is False`; with `NO_COLOR=1`, `supports_color(False) is False`.
- Existing parser tests keep passing; add parse check for top-level `--no-color`.
- Run `python3 -m unittest discover -s tests`.

## Out of Scope
- Restyling `ctf solve`, triage, or other outputs now (helper enables it later).
- 256-color themes, config files, Rich dependency.
- Changing command names or help text semantics.

## Acceptance Criteria
- `ctf commands` shows cyan sections, green commands, dim descriptions in interactive terminal.
- `ctf --no-color commands | cat` and `NO_COLOR=1 ctf commands` show current plain layout.
- All 16+ existing tests pass plus new color tests.
