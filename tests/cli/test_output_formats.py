"""Tests for output format rendering."""

import json
import os
import re
import subprocess
import sys
import unittest


# ANSI escape sequence pattern. Used to assert the presence or
# absence of color codes in CLI output. Matches the standard
# CSI-style escape codes pydepgate emits (e.g. "\033[1m", "\033[0m",
# "\033[31;1m"), and stays loose enough not to depend on the exact
# color choices.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _run_cli(args, env=None):
    base_env = os.environ.copy()
    for k in list(base_env.keys()):
        if k.startswith("PYDEPGATE_") or k == "NO_COLOR":
            del base_env[k]
    if env:
        base_env.update(env)
    result = subprocess.run(
        [sys.executable, "-m", "pydepgate"] + list(args),
        capture_output=True,
        text=True,
        env=base_env,
        timeout=10,
    )
    return result.returncode, result.stdout, result.stderr


class JsonFormatTests(unittest.TestCase):

    def test_scan_pip_json_output_is_valid_json(self):
        rc, out, err = _run_cli(["scan", "pip", "--format", "json"])
        # Output must parse as JSON.
        payload = json.loads(out)
        self.assertIn("schema_version", payload)
        self.assertIn("findings", payload)
        self.assertIn("statistics", payload)

    def test_json_schema_has_expected_top_level_keys(self):
        rc, out, err = _run_cli(["scan", "pip", "--format", "json"])
        payload = json.loads(out)
        for key in ("schema_version", "artifact", "findings",
                    "skipped", "statistics", "diagnostics"):
            self.assertIn(key, payload)


class HumanFormatTests(unittest.TestCase):

    def test_human_format_clean_scan(self):
        rc, out, err = _run_cli([
            "scan", "pip", "--format", "human", "--no-color",
        ])
        self.assertEqual(rc, 0)
        self.assertIn("No findings", out)


class SarifStubTests(unittest.TestCase):

    def test_sarif_format_emits_stub_message(self):
        rc, out, err = _run_cli(["scan", "pip", "--format", "sarif"])
        # SARIF stub returns TOOL_ERROR.
        self.assertEqual(rc, 3)
        self.assertIn("under development", out)


# ===========================================================================
# Color flag tests
#
# `--color={auto,always,never}` is the canonical color control. The
# legacy `--no-color` flag is preserved as an alias for `--color=never`.
# Tests confirm:
#   - Each choice value is accepted.
#   - --no-color still works (no regressions for users with that flag
#     in their CI configs).
#   - --color=always produces ANSI escape codes even when stdout is
#     redirected (the whole point of "always").
#   - --color=never never produces ANSI escape codes.
#   - PYDEPGATE_COLOR env var is respected.
#   - NO_COLOR env var still implies color disabled under default
#     auto mode.
#   - --color=always overrides NO_COLOR (explicit user intent wins
#     per the no-color.org spec).
#   - Invalid --color values are rejected by argparse (exit 2).
# ===========================================================================

class ColorFlagTests(unittest.TestCase):

    # --- choice acceptance -------------------------------------------------

    def test_color_auto_accepted(self):
        rc, out, err = _run_cli([
            "scan", "pip", "--format", "human", "--color", "auto",
        ])
        self.assertEqual(rc, 0)
        self.assertIn("No findings", out)

    def test_color_always_accepted(self):
        rc, out, err = _run_cli([
            "scan", "pip", "--format", "human", "--color", "always",
        ])
        self.assertEqual(rc, 0)
        self.assertIn("No findings", out)

    def test_color_never_accepted(self):
        rc, out, err = _run_cli([
            "scan", "pip", "--format", "human", "--color", "never",
        ])
        self.assertEqual(rc, 0)
        self.assertIn("No findings", out)

    def test_invalid_color_value_rejected(self):
        # Argparse should reject anything outside the choices set.
        rc, out, err = _run_cli([
            "scan", "pip", "--format", "human", "--color", "rainbow",
        ])
        self.assertEqual(rc, 2)
        self.assertIn("invalid choice", err)

    # --- --no-color alias --------------------------------------------------

    def test_no_color_alias_still_works(self):
        # Backwards compatibility: existing CI configs and shell
        # aliases that pass --no-color must continue to function.
        rc, out, err = _run_cli([
            "scan", "pip", "--format", "human", "--no-color",
        ])
        self.assertEqual(rc, 0)
        self.assertNotRegex(out, _ANSI_RE)

    def test_no_color_produces_same_output_as_color_never(self):
        rc1, out1, _ = _run_cli([
            "scan", "pip", "--format", "human", "--no-color",
        ])
        rc2, out2, _ = _run_cli([
            "scan", "pip", "--format", "human", "--color", "never",
        ])
        self.assertEqual(rc1, rc2)
        # The statistics line includes a duration that varies between
        # runs. Strip it before comparing.
        def _strip_duration(text):
            return re.sub(r"\d+ms", "Nms", text)
        self.assertEqual(_strip_duration(out1), _strip_duration(out2))
    # --- always overrides redirection --------------------------------------

    def test_color_always_emits_ansi_under_redirection(self):
        # subprocess.run captures stdout into a pipe, which means
        # sys.stdout.isatty() returns False inside the child. Under
        # auto mode that suppresses color; under "always" it must
        # not. This is the headline test for --color=always.
        rc, out, err = _run_cli([
            "scan", "pip", "--format", "human", "--color", "always",
        ])
        self.assertEqual(rc, 0)
        self.assertRegex(out, _ANSI_RE)

    def test_color_never_suppresses_ansi(self):
        rc, out, err = _run_cli([
            "scan", "pip", "--format", "human", "--color", "never",
        ])
        self.assertEqual(rc, 0)
        self.assertNotRegex(out, _ANSI_RE)

    def test_color_auto_suppresses_ansi_under_redirection(self):
        # The historical default behavior: piping/redirecting stdout
        # disables color. We're capturing into a pipe via subprocess
        # so this exercises the not-a-TTY code path.
        rc, out, err = _run_cli([
            "scan", "pip", "--format", "human", "--color", "auto",
        ])
        self.assertEqual(rc, 0)
        self.assertNotRegex(out, _ANSI_RE)

    # --- env var precedence ------------------------------------------------

    def test_pydepgate_color_env_var_used_as_default(self):
        # Without an explicit --color flag, the PYDEPGATE_COLOR env
        # var should set the default. "always" forces color even
        # under stdout-pipe.
        rc, out, err = _run_cli(
            ["scan", "pip", "--format", "human"],
            env={"PYDEPGATE_COLOR": "always"},
        )
        self.assertEqual(rc, 0)
        self.assertRegex(out, _ANSI_RE)

    def test_explicit_cli_color_overrides_env(self):
        # CLI flag must win over env var. Env says always, CLI says
        # never -> output must be plain.
        rc, out, err = _run_cli(
            ["scan", "pip", "--format", "human", "--color", "never"],
            env={"PYDEPGATE_COLOR": "always"},
        )
        self.assertEqual(rc, 0)
        self.assertNotRegex(out, _ANSI_RE)

    def test_no_color_env_implies_never(self):
        # NO_COLOR per the no-color.org spec: any value (including
        # empty? per the spec, presence alone) means "no color." Our
        # implementation treats "any non-empty value" as the trigger,
        # which is the practical reading.
        rc, out, err = _run_cli(
            ["scan", "pip", "--format", "human"],
            env={"NO_COLOR": "1"},
        )
        self.assertEqual(rc, 0)
        self.assertNotRegex(out, _ANSI_RE)

    def test_color_always_overrides_no_color_env(self):
        # The user explicitly opted back in via --color=always. That
        # must win over a system-wide NO_COLOR=1, per the no-color
        # spec's stipulation that explicit flags beat env vars.
        rc, out, err = _run_cli(
            ["scan", "pip", "--format", "human", "--color", "always"],
            env={"NO_COLOR": "1"},
        )
        self.assertEqual(rc, 0)
        self.assertRegex(out, _ANSI_RE)

    def test_pydepgate_no_color_env_implies_never(self):
        # Same behavior as NO_COLOR but via the pydepgate-specific
        # env var. Useful when a user wants to disable color for
        # pydepgate without affecting other tools that read NO_COLOR.
        rc, out, err = _run_cli(
            ["scan", "pip", "--format", "human"],
            env={"PYDEPGATE_NO_COLOR": "1"},
        )
        self.assertEqual(rc, 0)
        self.assertNotRegex(out, _ANSI_RE)

    # --- ci-mode interaction -----------------------------------------------

    def test_ci_mode_disables_color_by_default(self):
        # --ci historically forces color off. The new auto-flip in
        # _apply_ci_defaults preserves that for the common case.
        rc, out, err = _run_cli([
            "--ci", "scan", "pip", "--format", "human",
        ])
        self.assertEqual(rc, 0)
        self.assertNotRegex(out, _ANSI_RE)

if __name__ == "__main__":
    unittest.main()