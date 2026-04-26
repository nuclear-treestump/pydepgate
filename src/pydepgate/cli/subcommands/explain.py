"""The 'explain' subcommand: show signal/rule descriptions."""

from __future__ import annotations

import argparse
import sys

from pydepgate.cli import exit_codes
from pydepgate.rules.defaults import DEFAULT_RULES
from pydepgate.rules.explanations import (
    explain_rule,
    explain_signal,
    list_all_rule_ids,
    list_all_signal_ids,
)
from pydepgate.rules.loader import load_user_rules


def register(subparsers) -> None:
    parser = subparsers.add_parser(
        "explain",
        help="Show explanation for a signal ID or rule ID",
        description=(
            "Show pydepgate's description and rationale for a signal "
            "or rule. Without arguments, lists all known signals and "
            "rules."
        ),
    )
    parser.add_argument(
        "topic",
        nargs="?",
        help="Signal ID or rule ID to explain",
    )
    parser.add_argument(
        "--rule",
        action="store_true",
        help="Treat topic as a rule ID (default: try signal first)",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all known signal IDs and rule IDs",
    )
    parser.set_defaults(func=run)


def run(args: argparse.Namespace) -> int:
    # Load user rules to surface user-defined rule explanations too.
    try:
        loaded = load_user_rules()
    except Exception as exc:
        sys.stderr.write(f"warning: could not load user rules: {exc}\n")
        loaded = None

    user_rules = loaded.rules if loaded else []

    if args.list:
        return _do_list(user_rules)

    if not args.topic:
        sys.stderr.write(
            "explain: missing topic. Try 'pydepgate explain --list' "
            "for available IDs.\n"
        )
        return exit_codes.TOOL_ERROR

    topic = args.topic

    # Try signal first unless --rule was specified.
    if not args.rule:
        sig_explanation = explain_signal(topic)
        if sig_explanation is not None:
            _print_signal(topic, sig_explanation, user_rules)
            return 0

    rule_explanation = explain_rule(topic, user_rules)
    if rule_explanation is not None:
        _print_rule(topic, rule_explanation)
        return 0

    sys.stderr.write(
        f"unknown signal or rule: {topic!r}\n"
        f"Try 'pydepgate explain --list' for available IDs.\n"
    )
    return exit_codes.TOOL_ERROR


def _do_list(user_rules: list) -> int:
    sys.stdout.write("Signal IDs:\n")
    for sig_id in list_all_signal_ids():
        sig = explain_signal(sig_id)
        desc = sig["description"] if sig else "(no description)"
        sys.stdout.write(f"  {sig_id:<20} {desc[:60]}\n")
    sys.stdout.write("\nRule IDs:\n")
    all_rules = list(DEFAULT_RULES) + list(user_rules)
    for rule_id in list_all_rule_ids(user_rules):
        # Find the rule by ID to determine its source.
        for rule in all_rules:
            if rule.rule_id == rule_id:
                tag = f"[{rule.source.value}]"
                sys.stdout.write(f"  {tag:<10} {rule_id}\n")
                break
        else:
            sys.stdout.write(f"  [unknown]  {rule_id}\n")
    return 0


def _print_signal(signal_id: str, explanation: dict, user_rules: list) -> None:
    """Print the explanation for a signal, including applicable rules."""
    sys.stdout.write(f"\nSignal: {signal_id}\n")
    sys.stdout.write("=" * 60 + "\n")
    sys.stdout.write(f"\n{explanation['description']}\n\n")
    sys.stdout.write("Why it matters:\n")
    sys.stdout.write(f"  {explanation['why_it_matters']}\n\n")

    if "common_evasions" in explanation:
        sys.stdout.write("Common evasions:\n")
        for evasion in explanation["common_evasions"]:
            sys.stdout.write(f"  - {evasion}\n")
        sys.stdout.write("\n")

    # Find applicable default rules.
    applicable_defaults = [
        r for r in DEFAULT_RULES
        if r.match.signal_id == signal_id or r.match.signal_id is None
    ]
    if applicable_defaults:
        sys.stdout.write("Default rules that may apply:\n")
        for rule in applicable_defaults:
            sys.stdout.write(f"  {rule.rule_id}\n")
        sys.stdout.write("\n")

    # Find applicable user rules.
    applicable_user = [
        r for r in user_rules
        if r.match.signal_id == signal_id or r.match.signal_id is None
    ]
    if applicable_user:
        sys.stdout.write("User rules that may apply:\n")
        for rule in applicable_user:
            sys.stdout.write(f"  {rule.rule_id}\n")
        sys.stdout.write("\n")


def _print_rule(rule_id: str, explanation: dict) -> None:
    """Print the explanation for a rule."""
    sys.stdout.write(f"\nRule: {rule_id}\n")
    sys.stdout.write("=" * 60 + "\n")
    sys.stdout.write(f"\n{explanation['description']}\n\n")
    sys.stdout.write("Why it matters:\n")
    sys.stdout.write(f"  {explanation['why_it_matters']}\n\n")
    if "applies_to" in explanation:
        sys.stdout.write(f"Applies to: {explanation['applies_to']}\n")
    if "effect" in explanation:
        sys.stdout.write(f"Effect:     {explanation['effect']}\n")
    sys.stdout.write("\n")