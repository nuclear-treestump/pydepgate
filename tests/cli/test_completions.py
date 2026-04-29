"""
Tests for the tab-completion engine in pydepgate.cli.completion.

These tests exercise the engine directly; the argparse glue in
pydepgate.cli.subcommands.completion is a thin shell around
complete_words and is covered indirectly by integration tests
elsewhere.

The tests are organized by completion phase:
    1. Subcommand-level completion (no subcommand seen yet)
    2. Flag-name completion (current word starts with -)
    3. Flag-value completion (previous word is a flag-with-arg)
    4. Subcommand-positional completion (help, completions, explain)
    5. Free-form positional fallback (scan, exec, preflight)

Plus a small batch of tests for the per-shell script generators.
"""

from __future__ import annotations

import unittest

from pydepgate.cli.completion import (
    SUBCOMMAND_NAMES,
    SUPPORTED_SHELLS,
    bash_completion_script,
    complete_words,
    fish_completion_script,
    script_for_shell,
    zsh_completion_script,
)


class SubcommandCompletionTests(unittest.TestCase):
    """No subcommand typed yet: offer the subcommand list."""

    def test_empty_offers_visible_subcommands(self):
        candidates = complete_words(cur="", prev="pydepgate", words=[])
        # All visible subcommands present.
        for sc in ("scan", "explain", "version", "help", "completions"):
            self.assertIn(sc, candidates)

    def test_hidden_complete_subcommand_not_offered(self):
        candidates = complete_words(cur="", prev="pydepgate", words=[])
        self.assertNotIn("_complete", candidates)

    def test_partial_match_filters(self):
        candidates = complete_words(cur="sc", prev="pydepgate", words=["sc"])
        self.assertEqual(candidates, ["scan"])

    def test_no_partial_match_returns_empty(self):
        candidates = complete_words(
            cur="zzz", prev="pydepgate", words=["zzz"],
        )
        self.assertEqual(candidates, [])

    def test_subcommand_after_global_flag_still_completes(self):
        # `pydepgate --format json sc<TAB>` should still complete to scan.
        candidates = complete_words(
            cur="sc", prev="json", words=["--format", "json", "sc"],
        )
        self.assertIn("scan", candidates)


class FlagNameCompletionTests(unittest.TestCase):
    """Current word starts with -: complete flag names."""

    def test_global_flags_at_top_level(self):
        candidates = complete_words(cur="--", prev="pydepgate", words=["--"])
        # Top-level offers --version PLUS all globals.
        self.assertIn("--version", candidates)
        self.assertIn("--format", candidates)
        self.assertIn("--color", candidates)
        self.assertIn("--peek", candidates)

    def test_global_flags_after_subcommand(self):
        candidates = complete_words(
            cur="--", prev="scan", words=["scan", "--"],
        )
        # Globals available after subcommand too (because main.py applies
        # _add_global_flags to every subparser).
        self.assertIn("--format", candidates)
        self.assertIn("--color", candidates)
        self.assertIn("--peek", candidates)
        # Subcommand-specific flags also appear.
        self.assertIn("--deep", candidates)
        self.assertIn("--single", candidates)

    def test_scan_specific_flags_only_in_scan_context(self):
        scan_candidates = complete_words(
            cur="--", prev="scan", words=["scan", "--"],
        )
        explain_candidates = complete_words(
            cur="--", prev="explain", words=["explain", "--"],
        )
        self.assertIn("--deep", scan_candidates)
        self.assertNotIn("--deep", explain_candidates)
        self.assertIn("--rule", explain_candidates)
        self.assertNotIn("--rule", scan_candidates)

    def test_partial_flag_match(self):
        candidates = complete_words(
            cur="--peek-", prev="scan", words=["scan", "--peek-"],
        )
        # Should include all peek-prefixed flags.
        self.assertIn("--peek-depth", candidates)
        self.assertIn("--peek-budget", candidates)
        self.assertIn("--peek-min-length", candidates)
        self.assertIn("--peek-chain", candidates)
        # Should NOT include --peek (the bare flag, doesn't have the dash suffix).
        self.assertNotIn("--peek", candidates)

    def test_top_level_only_flag_not_offered_inside_subcommand(self):
        candidates = complete_words(
            cur="--ver", prev="scan", words=["scan", "--ver"],
        )
        # --version is registered only on the top-level parser; argparse
        # would error if a user typed `pydepgate scan --version`. Don't
        # offer it.
        self.assertNotIn("--version", candidates)


class FlagValueCompletionTests(unittest.TestCase):
    """Previous word is a flag-with-arg: complete its values."""

    def test_format_values(self):
        candidates = complete_words(
            cur="", prev="--format", words=["scan", "--format"],
        )
        self.assertEqual(candidates, ["human", "json", "sarif"])

    def test_color_values(self):
        candidates = complete_words(
            cur="", prev="--color", words=["scan", "--color"],
        )
        self.assertEqual(candidates, ["auto", "always", "never"])

    def test_min_severity_values(self):
        candidates = complete_words(
            cur="", prev="--min-severity",
            words=["scan", "--min-severity"],
        )
        self.assertEqual(
            candidates,
            ["info", "low", "medium", "high", "critical"],
        )

    def test_as_kind_values(self):
        candidates = complete_words(
            cur="", prev="--as",
            words=["scan", "--single", "/tmp/x", "--as"],
        )
        self.assertIn("setup_py", candidates)
        self.assertIn("library_py", candidates)
        self.assertIn("pth", candidates)

    def test_format_value_partial_match(self):
        candidates = complete_words(
            cur="js", prev="--format", words=["scan", "--format", "js"],
        )
        self.assertEqual(candidates, ["json"])

    def test_free_form_value_returns_empty(self):
        # --rules-file takes a path; the engine returns [] so the shell
        # falls back to filesystem completion.
        candidates = complete_words(
            cur="", prev="--rules-file",
            words=["scan", "--rules-file"],
        )
        self.assertEqual(candidates, [])

    def test_integer_value_returns_empty(self):
        # --peek-depth takes an int; same fallback.
        candidates = complete_words(
            cur="", prev="--peek-depth",
            words=["scan", "--peek-depth"],
        )
        self.assertEqual(candidates, [])


class PositionalCompletionTests(unittest.TestCase):
    """Subcommand-specific positional argument completion."""

    def test_help_topic_offers_subcommand_names(self):
        candidates = complete_words(
            cur="", prev="help", words=["help"],
        )
        for sc in SUBCOMMAND_NAMES:
            if sc != "_complete":
                self.assertIn(sc, candidates)

    def test_help_topic_partial_match(self):
        candidates = complete_words(
            cur="ex", prev="help", words=["help", "ex"],
        )
        # Both 'exec' and 'explain' start with 'ex'.
        self.assertIn("exec", candidates)
        self.assertIn("explain", candidates)
        self.assertNotIn("scan", candidates)

    def test_completions_offers_supported_shells(self):
        candidates = complete_words(
            cur="", prev="completions", words=["completions"],
        )
        self.assertEqual(sorted(candidates), sorted(list(SUPPORTED_SHELLS)))

    def test_completions_partial_match(self):
        candidates = complete_words(
            cur="b", prev="completions", words=["completions", "b"],
        )
        self.assertEqual(candidates, ["bash"])


class FreeFormPositionalTests(unittest.TestCase):
    """Subcommands whose positionals are paths/names: return empty."""

    def test_scan_target_returns_empty(self):
        # `pydepgate scan <TAB>` -> filesystem fallback.
        candidates = complete_words(
            cur="", prev="scan", words=["scan"],
        )
        self.assertEqual(candidates, [])

    def test_exec_script_returns_empty(self):
        candidates = complete_words(
            cur="", prev="exec", words=["exec"],
        )
        self.assertEqual(candidates, [])


class FlagValueOverridesEverythingElseTests(unittest.TestCase):
    """The previous-flag-is-a-value-flag rule is highest precedence."""

    def test_flag_value_completion_wins_over_subcommand_logic(self):
        # `pydepgate scan --format <TAB>` should suggest format values,
        # not file paths or scan-related candidates.
        candidates = complete_words(
            cur="", prev="--format", words=["scan", "--format"],
        )
        self.assertEqual(candidates, ["human", "json", "sarif"])

    def test_flag_value_completion_works_at_top_level_too(self):
        # `pydepgate --format <TAB>` (before subcommand).
        candidates = complete_words(
            cur="", prev="--format", words=["--format"],
        )
        self.assertEqual(candidates, ["human", "json", "sarif"])


class SubcommandDetectionTests(unittest.TestCase):
    """Edge cases in detecting which subcommand we're inside."""

    def test_subcommand_skipped_after_path_value_flag(self):
        # `pydepgate scan --rules-file foo.gate <TAB>` is still in scan
        # context. The engine must skip the value of --rules-file when
        # walking the words list.
        candidates = complete_words(
            cur="--",
            prev="foo.gate",
            words=["scan", "--rules-file", "foo.gate", "--"],
        )
        self.assertIn("--deep", candidates)  # scan-specific

    def test_subcommand_skipped_after_choice_value_flag(self):
        candidates = complete_words(
            cur="--",
            prev="json",
            words=["scan", "--format", "json", "--"],
        )
        self.assertIn("--deep", candidates)


class ScriptGenerationTests(unittest.TestCase):
    """The per-shell script generators produce non-empty, plausible output."""

    def test_bash_script_contains_expected_pieces(self):
        script = bash_completion_script()
        self.assertIn("_pydepgate_complete", script)
        self.assertIn("complete -F", script)
        self.assertIn("pydepgate _complete", script)
        self.assertIn("COMPREPLY", script)

    def test_zsh_script_contains_expected_pieces(self):
        script = zsh_completion_script()
        self.assertIn("bashcompinit", script)
        self.assertIn("_pydepgate_complete", script)
        self.assertIn("pydepgate _complete", script)

    def test_fish_script_contains_expected_pieces(self):
        script = fish_completion_script()
        self.assertIn("__pydepgate_complete", script)
        self.assertIn("complete -c pydepgate", script)
        self.assertIn("pydepgate _complete", script)

    def test_script_for_shell_dispatches_correctly(self):
        self.assertEqual(
            script_for_shell("bash"), bash_completion_script(),
        )
        self.assertEqual(
            script_for_shell("zsh"), zsh_completion_script(),
        )
        self.assertEqual(
            script_for_shell("fish"), fish_completion_script(),
        )

    def test_script_for_shell_unknown_raises(self):
        with self.assertRaises(ValueError):
            script_for_shell("powershell")

    def test_supported_shells_matches_dispatcher(self):
        # Every shell in SUPPORTED_SHELLS must dispatch successfully.
        for shell in SUPPORTED_SHELLS:
            try:
                script_for_shell(shell)
            except Exception as exc:
                self.fail(
                    f"script_for_shell({shell!r}) raised: {exc!r}"
                )


if __name__ == "__main__":
    unittest.main()