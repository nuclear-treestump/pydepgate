"""
Loader for pydepgate rule files (.gate format).

Auto-detects JSON vs TOML format. Validates schema with accumulated
errors and Levenshtein-based 'did you mean' suggestions for typos.
Auto-numbers user-supplied rules with USER### or USER_<id> prefixes.

File format: TOML or JSON.

The loader is strict: any validation error rejects the entire file.
This prevents partial rule sets from silently changing behavior.
"""

from __future__ import annotations

import difflib
import json
import os
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

from pydepgate.analyzers.base import Scope
from pydepgate.engines.base import Severity
from pydepgate.rules.base import (
    Rule,
    RuleAction,
    RuleEffect,
    RuleMatch,
    RuleSource,
)
from pydepgate.traffic_control.triage import FileKind


GATE_FILENAME = "pydepgate.gate"
ENV_RULES_FILE = "PYDEPGATE_RULES_FILE"

# Valid field names for a rule. Used by the typo-suggestion logic.
_VALID_RULE_FIELDS = frozenset({
    "id", "signal_id", "analyzer", "file_kind", "scope",
    "path_glob", "context_contains",
    "action", "severity", "description", "explain",
})

_VALID_ACTIONS = {a.value for a in RuleAction}
_VALID_SEVERITIES = {s.value for s in Severity}
_VALID_FILE_KINDS = {fk.value for fk in FileKind}
_VALID_SCOPES = {s.name.lower() for s in Scope}


class GateFileError(Exception):
    """Error loading or validating a .gate file."""
    pass


@dataclass
class LoadedRules:
    """Result of loading rules from a file.

    Attributes:
        rules: Successfully loaded rules.
        warnings: Non-fatal messages (e.g. missing format declaration).
        source_path: Path the rules were loaded from, or None.
        also_found: Other .gate files found during discovery that were
            not loaded (for visibility per discovery semantics).
    """
    rules: list[Rule]
    warnings: list[str]
    source_path: Path | None
    also_found: list[Path]


# ---- Discovery ----


def discover_rules_files(
    explicit_path: str | None = None,
    cwd: Path | None = None,
) -> tuple[Path | None, list[Path]]:
    """Find rules files in the standard discovery locations.

    Returns (chosen_path, other_paths_found). If no file found,
    returns (None, []).

    Discovery order (first match wins):
      1. explicit_path argument (if not None)
      2. PYDEPGATE_RULES_FILE environment variable
      3. ./pydepgate.gate (cwd or specified)
      4. <venv>/pydepgate.gate (sys.prefix if in a venv)
    """
    cwd = cwd or Path.cwd()
    candidates: list[Path] = []

    # 1. Explicit path
    if explicit_path:
        path = Path(explicit_path)
        if not path.suffix == ".gate":
            raise GateFileError(
                f"rules file must end in .gate: {path}"
            )
        if not path.is_file():
            raise GateFileError(f"rules file not found: {path}")
        return (path, [])

    # 2. Env var
    env_path = os.environ.get(ENV_RULES_FILE)
    if env_path:
        path = Path(env_path)
        if not path.suffix == ".gate":
            raise GateFileError(
                f"PYDEPGATE_RULES_FILE must point to a .gate file: {path}"
            )
        if not path.is_file():
            raise GateFileError(
                f"PYDEPGATE_RULES_FILE points to nonexistent file: {path}"
            )
        return (path, [])

    # 3. cwd
    cwd_file = cwd / GATE_FILENAME
    if cwd_file.is_file():
        candidates.append(cwd_file)

    # 4. venv (only if running in a venv)
    if hasattr(sys, "real_prefix") or sys.base_prefix != sys.prefix:
        venv_file = Path(sys.prefix) / GATE_FILENAME
        if venv_file.is_file() and venv_file != cwd_file:
            candidates.append(venv_file)

    if not candidates:
        return (None, [])

    chosen = candidates[0]
    others = candidates[1:]
    return (chosen, others)


# ---- Format detection and parsing ----


def _detect_format_and_parse(content: bytes) -> tuple[str, dict, list[str]]:
    """Try to parse content as JSON first, then TOML.

    Returns (format_name, parsed_data, warnings).
    Raises GateFileError on parse failure for both formats.
    """
    warnings: list[str] = []

    # Try JSON first.
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GateFileError(f"file is not valid UTF-8: {exc}")

    try:
        data = json.loads(text)
        # Check for format declaration.
        declared_format = data.get("_pydepgate_format")
        declared_version = data.get("_pydepgate_version")
        if declared_format is None:
            warnings.append(
                "JSON file lacks '_pydepgate_format' key; assuming JSON v1"
            )
        elif declared_format != "json":
            raise GateFileError(
                f"file declares format '{declared_format}' but content is JSON"
            )
        if declared_version is None:
            warnings.append(
                "JSON file lacks '_pydepgate_version' key; assuming v1"
            )
        elif declared_version != 1:
            raise GateFileError(
                f"unsupported _pydepgate_version: {declared_version}"
            )
        return ("json", data, warnings)
    except json.JSONDecodeError:
        pass

    # Try TOML.
    try:
        data = tomllib.loads(text)
        # TOML doesn't support top-level _pydepgate_format because of
        # comment limitations. We accept any TOML file as v1 for now.
        return ("toml", data, warnings)
    except tomllib.TOMLDecodeError as exc:
        raise GateFileError(
            f"file is neither valid JSON nor valid TOML.\n"
            f"TOML parse error: {exc}"
        ) from None


# ---- Schema validation ----


def _suggest_field(unknown: str, valid: set[str]) -> str | None:
    """Return a typo correction suggestion if one looks plausible."""
    matches = difflib.get_close_matches(unknown, valid, n=1, cutoff=0.6)
    return matches[0] if matches else None


def _validate_rule_dict(
    rule_dict: dict,
    rule_index: int,
    errors: list[str],
) -> None:
    """Validate a single rule dict, accumulating errors.

    Does not raise; appends to errors list. Caller decides whether
    to continue or abort based on accumulated errors.
    """
    if not isinstance(rule_dict, dict):
        errors.append(f"Rule {rule_index}: not a dict, got {type(rule_dict).__name__}")
        return

    rule_id = rule_dict.get("id", f"rule {rule_index}")

    # Check for unknown fields with typo suggestions.
    for field in rule_dict.keys():
        if field not in _VALID_RULE_FIELDS:
            suggestion = _suggest_field(field, _VALID_RULE_FIELDS)
            if suggestion:
                errors.append(
                    f"Rule {rule_id}: unknown field '{field}'. "
                    f"Did you mean '{suggestion}'?"
                )
            else:
                errors.append(
                    f"Rule {rule_id}: unknown field '{field}'. "
                    f"Valid fields: {', '.join(sorted(_VALID_RULE_FIELDS))}."
                )

    # Validate action.
    action = rule_dict.get("action")
    if action is None:
        errors.append(f"Rule {rule_id}: 'action' is required")
    elif action not in _VALID_ACTIONS:
        suggestion = _suggest_field(action, _VALID_ACTIONS)
        if suggestion:
            errors.append(
                f"Rule {rule_id}: unknown action '{action}'. "
                f"Did you mean '{suggestion}'?"
            )
        else:
            errors.append(
                f"Rule {rule_id}: unknown action '{action}'. "
                f"Valid actions: {', '.join(sorted(_VALID_ACTIONS))}."
            )

    # Validate severity if action requires it.
    severity = rule_dict.get("severity")
    if action == "set_severity":
        if severity is None:
            errors.append(
                f"Rule {rule_id}: action 'set_severity' requires "
                f"a 'severity' field"
            )
        elif severity not in _VALID_SEVERITIES:
            suggestion = _suggest_field(severity, _VALID_SEVERITIES)
            hint = f" Did you mean '{suggestion}'?" if suggestion else ""
            errors.append(
                f"Rule {rule_id}: invalid severity '{severity}'.{hint} "
                f"Valid: {', '.join(sorted(_VALID_SEVERITIES))}."
            )

    # Validate description if action requires it.
    if action == "set_description":
        if rule_dict.get("description") is None:
            errors.append(
                f"Rule {rule_id}: action 'set_description' requires "
                f"a 'description' field"
            )

    # Validate file_kind if present.
    file_kind = rule_dict.get("file_kind")
    if file_kind is not None and file_kind not in _VALID_FILE_KINDS:
        suggestion = _suggest_field(file_kind, _VALID_FILE_KINDS)
        hint = f" Did you mean '{suggestion}'?" if suggestion else ""
        errors.append(
            f"Rule {rule_id}: invalid file_kind '{file_kind}'.{hint} "
            f"Valid: {', '.join(sorted(_VALID_FILE_KINDS))}."
        )

    # Validate scope if present.
    scope = rule_dict.get("scope")
    if scope is not None and scope not in _VALID_SCOPES:
        suggestion = _suggest_field(scope, _VALID_SCOPES)
        hint = f" Did you mean '{suggestion}'?" if suggestion else ""
        errors.append(
            f"Rule {rule_id}: invalid scope '{scope}'.{hint} "
            f"Valid: {', '.join(sorted(_VALID_SCOPES))}."
        )

    # context_contains must be a dict if present.
    cc = rule_dict.get("context_contains")
    if cc is not None and not isinstance(cc, dict):
        errors.append(
            f"Rule {rule_id}: context_contains must be a dict/object, "
            f"got {type(cc).__name__}"
        )


def _build_rule(
    rule_dict: dict,
    auto_id: str,
    source: RuleSource,
) -> Rule:
    """Construct a Rule from a validated dict.

    Caller must have validated the dict via _validate_rule_dict first.
    """
    # Determine the actual rule_id with source prefix.
    explicit_id = rule_dict.get("id")
    if explicit_id:
        prefix = source.value.upper()
        rule_id = f"{prefix}_{explicit_id}"
    else:
        rule_id = auto_id

    # Build the match.
    file_kind = None
    if rule_dict.get("file_kind"):
        file_kind = FileKind(rule_dict["file_kind"])

    scope = None
    if rule_dict.get("scope"):
        scope = Scope[rule_dict["scope"].upper()]

    match = RuleMatch(
        signal_id=rule_dict.get("signal_id"),
        analyzer=rule_dict.get("analyzer"),
        file_kind=file_kind,
        scope=scope,
        path_glob=rule_dict.get("path_glob"),
        context_contains=rule_dict.get("context_contains"),
    )

    # Build the effect.
    action = RuleAction(rule_dict["action"])
    severity = None
    if rule_dict.get("severity"):
        severity = Severity(rule_dict["severity"])

    effect = RuleEffect(
        action=action,
        severity=severity,
        description=rule_dict.get("description"),
    )

    return Rule(
        rule_id=rule_id,
        source=source,
        match=match,
        effect=effect,
        explain=rule_dict.get("explain", ""),
    )


def _extract_rule_list(data: dict, fmt: str) -> list:
    """Extract the list of rules from parsed data.

    JSON: looks for 'rules' key.
    TOML: uses [[rule]] tables, which appear as data['rule'].
    """
    if fmt == "json":
        rules = data.get("rules", [])
        if not isinstance(rules, list):
            raise GateFileError("'rules' must be a list/array")
        return rules
    elif fmt == "toml":
        rules = data.get("rule", [])
        if not isinstance(rules, list):
            raise GateFileError("'[[rule]]' tables must form an array")
        return rules
    else:
        raise GateFileError(f"unknown format: {fmt}")


# ---- Top-level loading ----


def load_rules_file(
    path: Path,
    source: RuleSource = RuleSource.USER,
) -> LoadedRules:
    """Load rules from a single .gate file.

    Args:
        path: Path to a .gate file.
        source: Source category (USER or SYSTEM).

    Returns:
        LoadedRules with the parsed rules and any warnings.

    Raises:
        GateFileError: if the file cannot be parsed or fails validation.
    """
    if not path.suffix == ".gate":
        raise GateFileError(
            f"rules file must end in .gate: {path}"
        )

    try:
        content = path.read_bytes()
    except OSError as exc:
        raise GateFileError(f"cannot read {path}: {exc}") from None

    fmt, data, warnings = _detect_format_and_parse(content)

    rule_dicts = _extract_rule_list(data, fmt)

    # Validate all rules, accumulating errors.
    errors: list[str] = []
    for idx, rule_dict in enumerate(rule_dicts, start=1):
        _validate_rule_dict(rule_dict, idx, errors)

    if errors:
        msg = f"Failed to load {path}:\n\n"
        for err in errors:
            msg += f"  {err}\n"
        msg += f"\n{len(errors)} validation error"
        msg += "s" if len(errors) != 1 else ""
        msg += " in {len(rule_dicts)} rules. No rules were loaded."
        raise GateFileError(msg)

    # Build Rule objects with auto-numbered IDs.
    prefix = source.value.upper()
    rules: list[Rule] = []
    for idx, rule_dict in enumerate(rule_dicts, start=1):
        auto_id = f"{prefix}{idx:03d}"
        rules.append(_build_rule(rule_dict, auto_id, source))

    return LoadedRules(
        rules=rules,
        warnings=warnings,
        source_path=path,
        also_found=[],
    )


def load_user_rules(
    explicit_path: str | None = None,
    cwd: Path | None = None,
) -> LoadedRules:
    """Discover and load user rules.

    Returns LoadedRules. If no rules file found, returns empty rules
    with no warnings.
    """
    chosen, others = discover_rules_files(explicit_path, cwd)

    if chosen is None:
        return LoadedRules(
            rules=[],
            warnings=[],
            source_path=None,
            also_found=[],
        )

    loaded = load_rules_file(chosen, source=RuleSource.USER)
    loaded = LoadedRules(
        rules=loaded.rules,
        warnings=loaded.warnings,
        source_path=loaded.source_path,
        also_found=others,
    )

    return loaded


def load_system_rules() -> LoadedRules:
    """Stub for system rules. Returns empty rules.

    System config support is wired but not active in v0.1. When
    implemented, this function will look for /etc/pydepgate/pydepgate.gate
    and similar paths.
    """
    return LoadedRules(
        rules=[],
        warnings=[],
        source_path=None,
        also_found=[],
    )