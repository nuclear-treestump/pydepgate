"""pydepgate.cli.completion

Tab-completion engine for the pydepgate CLI.

This module is the data-and-logic layer. It has no argparse
dependencies; the argparse glue lives in
pydepgate.cli.subcommands.completion. Tests can exercise the engine
in isolation by passing word lists directly to complete_words.

The completion model is the standard "delegate to the program"
pattern used by kubectl, docker, git, and most modern CLIs: the
shell calls back into pydepgate with the current command-line
state, pydepgate returns candidates one per line on stdout, and
the shell turns those into completion suggestions. Three shells
are supported (bash, zsh, fish); the per-shell glue is small
because the heavy lifting happens in Python.

Stdlib-only by design: the project's zero-runtime-dependency
constraint applies here too.
"""

from __future__ import annotations

from typing import Iterable

# ---------------------------------------------------------------------------
# Subcommand inventory
# ---------------------------------------------------------------------------
#
# The set of subcommands offered by pydepgate. Kept as a tuple so it
# is iteration-stable for completion output (alphabetical-ish, with
# the most common ones first).

SUBCOMMAND_NAMES: tuple[str, ...] = (
    "scan",
    "explain",
    "preflight",
    "exec",
    "version",
    "help",
    "completions",
)


# Subcommands that are listed in user-facing help. The hidden
# _complete subcommand is registered for shell callbacks and is
# excluded from completion output (no point in suggesting it; users
# never type it).
_HIDDEN_SUBCOMMANDS: frozenset[str] = frozenset({"_complete"})


# ---------------------------------------------------------------------------
# Global flags
# ---------------------------------------------------------------------------
#
# Flags that work either before OR after the subcommand. The
# _add_global_flags helper in cli/main.py adds these to the top-level
# parser AND to every subparser. Completion treats them uniformly:
# they're available in every flag-completion context.
#
# Two structures here:
#   _GLOBAL_BOOL_FLAGS: action='store_true' (or store_const), no arg
#   _GLOBAL_VALUE_FLAGS: dict mapping flag name to its allowed values
#                        (None means "any value", e.g. paths or ints)
#
# The peek-related flags also count as global because the existing
# add_peek_arguments call site adds them via _add_global_flags too.

_GLOBAL_BOOL_FLAGS: frozenset[str] = frozenset(
    {
        "--ci",
        "--no-color",
        "--strict-exit",
        "--no-map",
        "--peek",
        "--peek-chain",
    }
)


_GLOBAL_VALUE_FLAGS: dict[str, tuple[str, ...] | None] = {
    "--format": ("human", "json", "sarif"),
    "--color": ("auto", "always", "never"),
    "--min-severity": ("info", "low", "medium", "high", "critical"),
    "--rules-file": None,  # filesystem path; shell handles fallback
    "--peek-depth": None,  # integer; no completion
    "--peek-budget": None,  # integer; no completion
    "--peek-min-length": None,  # integer; no completion
    "--sarif-srcroot": None,  # filesystem path; shell handles fallback
}


# Top-level-only flags. --version is added at the top-level parser
# only, not on subparsers.
_TOPLEVEL_ONLY_BOOL_FLAGS: frozenset[str] = frozenset({"--version"})


# ---------------------------------------------------------------------------
# Per-subcommand flags
# ---------------------------------------------------------------------------

_SCAN_BOOL_FLAGS: frozenset[str] = frozenset({"--deep", "--no-bar"})


_SCAN_VALUE_FLAGS: dict[str, tuple[str, ...] | None] = {
    "--single": None,  # filesystem path
    "--as": (
        "setup_py",
        "init_py",
        "pth",
        "sitecustomize",
        "usercustomize",
        "library_py",
    ),
}


_EXPLAIN_BOOL_FLAGS: frozenset[str] = frozenset({"--rule", "--list"})
_EXPLAIN_VALUE_FLAGS: dict[str, tuple[str, ...] | None] = {}


_PREFLIGHT_BOOL_FLAGS: frozenset[str] = frozenset()
_PREFLIGHT_VALUE_FLAGS: dict[str, tuple[str, ...] | None] = {
    "--python": None,  # filesystem path
}


_EXEC_BOOL_FLAGS: frozenset[str] = frozenset()
_EXEC_VALUE_FLAGS: dict[str, tuple[str, ...] | None] = {}


_VERSION_BOOL_FLAGS: frozenset[str] = frozenset()
_VERSION_VALUE_FLAGS: dict[str, tuple[str, ...] | None] = {}


_HELP_BOOL_FLAGS: frozenset[str] = frozenset()
_HELP_VALUE_FLAGS: dict[str, tuple[str, ...] | None] = {}


_COMPLETIONS_BOOL_FLAGS: frozenset[str] = frozenset()
_COMPLETIONS_VALUE_FLAGS: dict[str, tuple[str, ...] | None] = {}


# Lookup table: subcommand -> (bool_flags, value_flags).
_SUBCOMMAND_FLAGS: dict[
    str,
    tuple[frozenset[str], dict[str, tuple[str, ...] | None]],
] = {
    "scan": (_SCAN_BOOL_FLAGS, _SCAN_VALUE_FLAGS),
    "explain": (_EXPLAIN_BOOL_FLAGS, _EXPLAIN_VALUE_FLAGS),
    "preflight": (_PREFLIGHT_BOOL_FLAGS, _PREFLIGHT_VALUE_FLAGS),
    "exec": (_EXEC_BOOL_FLAGS, _EXEC_VALUE_FLAGS),
    "version": (_VERSION_BOOL_FLAGS, _VERSION_VALUE_FLAGS),
    "help": (_HELP_BOOL_FLAGS, _HELP_VALUE_FLAGS),
    "completions": (_COMPLETIONS_BOOL_FLAGS, _COMPLETIONS_VALUE_FLAGS),
}


# Subcommands whose first positional is a known closed set (rather
# than a path or an arbitrary string). Maps subcommand name to the
# tuple of valid values.
_SUBCOMMAND_POSITIONAL_CHOICES: dict[str, tuple[str, ...]] = {
    "help": SUBCOMMAND_NAMES,
    "completions": ("bash", "zsh", "fish"),
}


# ---------------------------------------------------------------------------
# Public helpers used by the engine
# ---------------------------------------------------------------------------


def _detect_subcommand(words: Iterable[str]) -> str | None:
    """Return the first subcommand name in `words`, or None.

    Walks the word list left-to-right, returning the first token that
    matches a known subcommand. Skips flags and flag values.

    The "skip flag values" logic is deliberately cheap: when we see a
    token that is in _GLOBAL_VALUE_FLAGS or in any subcommand's value
    flags, we skip the next token too. This is good enough for
    completion (false negatives just mean we offer subcommand
    candidates one TAB earlier than ideal).
    """
    all_value_flags: set[str] = set(_GLOBAL_VALUE_FLAGS.keys())
    for _, value_flags in _SUBCOMMAND_FLAGS.values():
        all_value_flags.update(value_flags.keys())

    skip_next = False
    for word in words:
        if skip_next:
            skip_next = False
            continue
        if word in all_value_flags:
            # The next token is its value; don't treat it as a subcommand.
            skip_next = True
            continue
        if word.startswith("-"):
            continue
        if word in SUBCOMMAND_NAMES:
            return word
        # First non-flag, non-subcommand positional means the subcommand
        # field is empty (e.g., `pydepgate target.whl` has no subcommand).
        return None
    return None


def _flag_names_for_context(subcommand: str | None) -> list[str]:
    """Return the flag names valid in the given subcommand context.

    None means we haven't seen a subcommand yet, so we offer global
    flags plus the top-level-only flags.
    """
    flags: set[str] = set()
    flags.update(_GLOBAL_BOOL_FLAGS)
    flags.update(_GLOBAL_VALUE_FLAGS.keys())

    if subcommand is None:
        flags.update(_TOPLEVEL_ONLY_BOOL_FLAGS)
    elif subcommand in _SUBCOMMAND_FLAGS:
        sub_bool, sub_value = _SUBCOMMAND_FLAGS[subcommand]
        flags.update(sub_bool)
        flags.update(sub_value.keys())

    return sorted(flags)


def _values_for_flag(flag: str) -> tuple[str, ...] | None:
    """Return the choices for a flag-with-arg, or None for free-form.

    Returns:
        A tuple of static choices when the flag has them.
        None when the flag's value is free-form (path, integer, etc.).
        An empty tuple when `flag` isn't a known value flag.

    Callers distinguish "no completion offered" (None) from "unknown
    flag" (empty tuple) by checking the type, not the truthiness. The
    None return tells the shell glue to fall back to filesystem
    completion; the empty-tuple return is a hint that completion has
    no opinion at all.
    """
    if flag in _GLOBAL_VALUE_FLAGS:
        return _GLOBAL_VALUE_FLAGS[flag]
    for _, sub_value in _SUBCOMMAND_FLAGS.values():
        if flag in sub_value:
            return sub_value[flag]
    return ()


def _explain_topic_candidates() -> list[str]:
    """Return all signal IDs and rule IDs as completion candidates.

    Loads user rules so user-defined rule_ids are completable too.
    Failures during user-rule loading are non-fatal: completion
    falls back to defaults-only without surfacing the error. We do
    not want a malformed .gate file to break tab completion.
    """
    # Imports are local because this function is only called for
    # `explain` topic completion. Top-level imports would pay the
    # cost on every shell callback regardless of context.
    try:
        from pydepgate.rules.explanations import (
            list_all_rule_ids,
            list_all_signal_ids,
        )
    except Exception:
        return []

    candidates: list[str] = []
    try:
        candidates.extend(list_all_signal_ids())
    except Exception:
        # If built-in signal discovery fails, continue with whatever
        # other candidates we can still compute.
        pass

    user_rules: list = []
    try:
        from pydepgate.rules.loader import load_user_rules

        loaded = load_user_rules()
        user_rules = list(loaded.rules)
    except Exception:
        # Malformed .gate file or any other discovery error: defaults
        # only. Tab completion continues to work.
        pass

    try:
        candidates.extend(list_all_rule_ids(user_rules))
    except Exception:
        # If rule ID enumeration fails for any reason, keep any
        # previously collected candidates so shell completion still works.
        pass

    # De-dup while preserving sort order; signal IDs and rule IDs
    # share no naming convention so collisions are unlikely, but
    # cheap to defend against.
    seen: set[str] = set()
    out: list[str] = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return sorted(out)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def complete_words(cur: str, prev: str, words: list[str]) -> list[str]:
    """Compute completion candidates for the current shell state.

    Args:
        cur: The partial token being completed (may be empty).
        prev: The token immediately before `cur` on the command line.
        words: The full word list AFTER the program name. So
               `pydepgate scan --form` parses to:
                   cur="--form", prev="scan", words=["scan", "--form"]

    Returns:
        A list of candidate strings, alphabetized. May be empty.
        An empty list signals to the shell glue that no Python-side
        candidates are available; the shell may fall back to its
        native completion (filesystem paths, etc.).
    """
    # Step 1: previous-word-is-a-flag-with-value override. This wins
    # over every other rule because the shell is asking specifically
    # "what value goes after this flag?"
    if prev in _GLOBAL_VALUE_FLAGS or any(
        prev in sub_value for _, sub_value in _SUBCOMMAND_FLAGS.values()
    ):
        values = _values_for_flag(prev)
        if values is None:
            # Free-form value (path, integer). Shell falls back to
            # filesystem completion via empty return.
            return []
        return [v for v in values if v.startswith(cur)]

    # Step 2: user is typing a flag (current token starts with -).
    subcommand = _detect_subcommand(words)
    if cur.startswith("-"):
        return [f for f in _flag_names_for_context(subcommand) if f.startswith(cur)]

    # Step 3: no subcommand yet, offer the subcommand list.
    if subcommand is None:
        candidates = sorted(
            sc
            for sc in SUBCOMMAND_NAMES
            if sc not in _HIDDEN_SUBCOMMANDS and sc.startswith(cur)
        )
        return candidates

    # Step 4: subcommand-specific positional completion.
    if subcommand in _SUBCOMMAND_POSITIONAL_CHOICES:
        choices = _SUBCOMMAND_POSITIONAL_CHOICES[subcommand]
        return [c for c in choices if c.startswith(cur)]

    if subcommand == "explain":
        return [t for t in _explain_topic_candidates() if t.startswith(cur)]

    # Step 5: scan, exec, preflight have free-form positionals
    # (paths, package names, scripts). Return empty so the shell
    # falls through to filesystem completion.
    return []


# ---------------------------------------------------------------------------
# Per-shell script generation
# ---------------------------------------------------------------------------
#
# These produce the shell-side glue that delegates back to
# `pydepgate _complete` for actual candidate computation. Each
# shell's syntax is different but the contract is identical:
# capture the current word, the previous word, and the full word
# list; pass them to pydepgate; turn the output into completions.
#
# All three scripts handle the empty-output fallback the same way:
# if pydepgate returns no candidates, fall back to filesystem
# completion. This is what makes `--single <TAB>` complete file
# paths even though the engine returns [] for that case.

_BASH_TEMPLATE = """\
# pydepgate bash completion
# Source this file from your ~/.bashrc, or run:
#   eval "$(pydepgate completions bash)"
# Generated by `pydepgate completions bash`.

_pydepgate_complete() {
    local cur prev candidates
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # Delegate to pydepgate. The `=` syntax on --cur and --prev is
    # mandatory because the value of $prev may start with `--` (e.g.
    # the user just typed `--format`); argparse handles --flag=value
    # correctly in that case but not --flag value. The `--` after
    # the named args ends option parsing so that --format / --peek /
    # etc. in the user's word list are passed through as REMAINDER
    # data, not interpreted as flags.
    candidates=$(pydepgate _complete \\
        --cur="$cur" \\
        --prev="$prev" \\
        -- "${COMP_WORDS[@]:1}" 2>/dev/null)

    if [ -z "$candidates" ]; then
        # No Python-side candidates; fall back to filename completion.
        COMPREPLY=( $(compgen -f -- "$cur") )
    else
        COMPREPLY=( $(compgen -W "$candidates" -- "$cur") )
    fi
}

complete -F _pydepgate_complete pydepgate
"""


_ZSH_TEMPLATE = """\
# pydepgate zsh completion
# Source this file from your ~/.zshrc, or run:
#   eval "$(pydepgate completions zsh)"
# Generated by `pydepgate completions zsh`.
#
# This uses bashcompinit to bridge bash-style completion into zsh.
# A native zsh _arguments-based completion would be more idiomatic
# but is significantly more code; the bashcompinit bridge works
# well for the dynamic-callback pattern pydepgate uses.

autoload -U +X bashcompinit && bashcompinit
autoload -U +X compinit && compinit

_pydepgate_complete() {
    local cur prev candidates
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # See bash template note: --flag=value is mandatory because $prev
    # may begin with `--`, which argparse otherwise treats as a flag.
    candidates=$(pydepgate _complete \\
        --cur="$cur" \\
        --prev="$prev" \\
        -- "${COMP_WORDS[@]:1}" 2>/dev/null)

    if [ -z "$candidates" ]; then
        COMPREPLY=( $(compgen -f -- "$cur") )
    else
        COMPREPLY=( $(compgen -W "$candidates" -- "$cur") )
    fi
}

complete -F _pydepgate_complete pydepgate
"""


_FISH_TEMPLATE = """\
# pydepgate fish completion
# Save this to ~/.config/fish/completions/pydepgate.fish, or run:
#   pydepgate completions fish | source
# Generated by `pydepgate completions fish`.

function __pydepgate_complete
    set -l cur (commandline -ct)
    set -l tokens (commandline -opc)
    set -l prev ""
    if test (count $tokens) -gt 0
        set prev $tokens[-1]
    end
    # tokens[1] is "pydepgate"; pass tokens[2..-1] as the word list.
    set -l rest
    if test (count $tokens) -gt 1
        set rest $tokens[2..-1]
    end
    # See bash template note: --flag=value syntax is mandatory because
    # $prev may begin with `--`, which argparse otherwise interprets
    # as a separate flag rather than a value.
    pydepgate _complete --cur="$cur" --prev="$prev" -- $rest 2>/dev/null
end

# -f disables file completion as the default; we add it back as a
# fallback below. -a delegates candidate generation to our function.
complete -c pydepgate -f -a '(__pydepgate_complete)'

# When the dynamic source returns no candidates, fall through to
# normal file completion. This makes `pydepgate scan <TAB>` and
# `pydepgate scan --single <TAB>` complete paths.
complete -c pydepgate -F
"""


def bash_completion_script() -> str:
    """Return the bash completion script as a string.

    The script is self-contained; it can be written to disk and
    sourced, or eval'd directly via `eval "$(pydepgate completions bash)"`.
    """
    return _BASH_TEMPLATE


def zsh_completion_script() -> str:
    """Return the zsh completion script as a string.

    Uses zsh's bashcompinit to bridge the bash-style completion
    function into zsh's completion system. A native _arguments
    implementation would be more idiomatic but considerably more
    code; the bridge works well for dynamic callback completions.
    """
    return _ZSH_TEMPLATE


def fish_completion_script() -> str:
    """Return the fish completion script as a string.

    Fish has the cleanest completion syntax of the three shells;
    the script is concise and uses fish's native `complete -c`
    declarations.
    """
    return _FISH_TEMPLATE


def script_for_shell(shell: str) -> str:
    """Dispatch to the per-shell script generator.

    Args:
        shell: One of "bash", "zsh", "fish".

    Raises:
        ValueError: when `shell` is not recognized.
    """
    if shell == "bash":
        return bash_completion_script()
    if shell == "zsh":
        return zsh_completion_script()
    if shell == "fish":
        return fish_completion_script()
    raise ValueError(f"unknown shell {shell!r}; expected one of: bash, zsh, fish")


SUPPORTED_SHELLS: tuple[str, ...] = ("bash", "zsh", "fish")
