"""Argparse display helpers (no behavior change to parsing)."""
from __future__ import annotations


def hide_subcommands(subparsers_action, *names: str) -> None:
    """Hide subcommands from --help listings while keeping them runnable.

    ``help=argparse.SUPPRESS`` does not fully hide subparsers (the choice
    still appears in the usage line and as a literal ``==SUPPRESS==`` entry),
    so filter the choice actions and narrow the metavar instead. Hidden
    commands still parse, execute, and answer their own ``--help``.
    """
    hide = set(names)
    try:
        subparsers_action._choices_actions[:] = [
            a for a in subparsers_action._choices_actions
            if getattr(a, "dest", None) not in hide
        ]
    except AttributeError:
        pass
    try:
        visible = [n for n in subparsers_action._name_parser_map if n not in hide]
        subparsers_action.metavar = "{%s}" % ",".join(visible)
    except AttributeError:
        pass
