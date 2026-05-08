"""pydepgate.reporters.sarif.rules

Generates the SARIF tool.driver.rules array from
pydepgate's existing signal explanation data.

Each pydepgate signal_id (DENS010, DYN002, STDLIB001, and
the others) becomes one entry in the rules array. The
reportingDescriptor for each signal is constructed from
three sources of project-internal data:

  1. SIGNAL_EXPLANATIONS for the description, why-it-matters
     text, and (when present) common evasions list. This
     data already exists for the 'pydepgate explain'
     command, so the SARIF catalog stays current without
     a separate maintenance step.

  2. RULES (the default rule set) for the
     defaultConfiguration.level, computed as the highest
     SARIF level set by any DEFAULT-source SET_SEVERITY
     rule targeting that signal_id. For signals with no
     default rule, a fallback severity is used.

  3. A prefix-to-analyzer mapping for the analyzer/* tag
     and the rule name. This is the one piece of pydepgate-
     internal data that the SARIF reporter has to maintain
     itself; when a new analyzer is introduced with a new
     signal_id prefix, ANALYZER_BY_PREFIX needs one new
     entry. The test suite includes a defensive
     check that every signal in SIGNAL_EXPLANATIONS resolves
     to a known analyzer, so missing mappings fail loudly.

"""

from __future__ import annotations

import re
from typing import Iterable

from pydepgate.engines.base import Severity
from pydepgate.rules.base import RuleAction, RuleSource
from pydepgate.rules.explanations import SIGNAL_EXPLANATIONS
from pydepgate.rules.groups import DEFAULT_RULES as RULES

from pydepgate.reporters.sarif.severity import (
    to_sarif_level,
    to_security_severity,
    severity_rank,
)

# Maps signal_id alphabetic prefix to the analyzer name. The
# values produce both the analyzer/* tag on each rule and
# the analyzer portion of the rule name. When a new analyzer
# is introduced, add one entry here. Naming convention is
# kebab-case to keep SARIF rule names readable.
ANALYZER_BY_PREFIX: dict[str, str] = {
    "DENS": "density",
    "DYN": "dynamic-execution",
    "ENC": "encoding-abuse",
    "STR": "string-ops",
    "STDLIB": "suspicious-stdlib",
}

# Tags applied to every rule. Identifies pydepgate output
# uniformly so consumers can filter on these in GitHub's UI.
# 'security' is the GitHub convention for security-relevant
# findings; 'supply-chain' and 'python' are pydepgate-specific
# discriminators useful for organizations running multiple
# scanners.
BASE_TAGS: tuple[str, ...] = ("security", "supply-chain", "python")

# Initial precision applied to every rule. SARIF precision
# is one of: very-high, high, medium, low. Future
# refinements can differentiate per-rule based on real-world
# false-positive rates from production GitHub alerts; that
# refinement is a follow-up and we have
# data on which signals are noisier than others.
INITIAL_PRECISION: str = "high"

# Fallback severity for rules that have no default-rule
# severity setting. Severity.MEDIUM maps to SARIF 'warning'
# level and a 5.0 security-severity numeric, the middle of
# the band where neither alarming nor dismissive feels
# correct. Signals known to lack a default rule include
# DYN001, DYN003, and DYN004 (per the docstring in
# pydepgate.rules.groups.dynamic).
DEFAULT_SEVERITY_FALLBACK: Severity = Severity.MEDIUM


# Regex extracting the alphabetic prefix from a signal_id.
# Stops at the first non-uppercase-letter character. For
# 'DENS010' it yields 'DENS'; for 'DYN006_PRECURSOR' it
# yields 'DYN'.
_PREFIX_PATTERN = re.compile(r"^([A-Z]+)")

# Regex finding the first sentence-ending period. A sentence
# ends at a period followed by whitespace or end-of-string;
# this avoids matching periods inside abbreviations or
# decimal numbers that lack a trailing space.
_SENTENCE_END_PATTERN = re.compile(r"\.(\s|$)")


def make_rules_array() -> tuple[list[dict], dict[str, int]]:
    """Produce the SARIF tool.driver.rules array.

    Walks SIGNAL_EXPLANATIONS to enumerate every known
    signal_id, builds a reportingDescriptor for each, and
    returns the array sorted by signal_id along with an
    index map for downstream phases that need to set
    result.ruleIndex.

    Returns:
        A two-tuple of (rules, indices):

          rules: a list of reportingDescriptor dicts,
            sorted by signal_id. One entry per signal in
            SIGNAL_EXPLANATIONS. Every dict in the list is
            JSON-serializable.

          indices: a dict mapping signal_id (str) to its
            zero-based position in the rules list.

    The output is deterministic across calls against the
    same project state. Sorting by signal_id keeps SARIF
    document diffs minimal across runs that find the same
    signals.
    """
    default_severities = _compute_default_severities()
    sorted_signal_ids = sorted(SIGNAL_EXPLANATIONS.keys())

    rules: list[dict] = []
    indices: dict[str, int] = {}
    for index, signal_id in enumerate(sorted_signal_ids):
        explanation = SIGNAL_EXPLANATIONS[signal_id]
        default_severity = default_severities.get(signal_id, DEFAULT_SEVERITY_FALLBACK)
        rules.append(make_rule_descriptor(signal_id, explanation, default_severity))
        indices[signal_id] = index
    return rules, indices


def make_rule_descriptor(
    signal_id: str,
    explanation: dict,
    default_severity: Severity,
) -> dict:
    """Build a single SARIF reportingDescriptor.

    Args:
        signal_id: the pydepgate signal_id (e.g., 'DENS010').
        explanation: the SIGNAL_EXPLANATIONS entry for this
            signal, with at minimum 'description' and
            'why_it_matters' keys, plus optionally a
            'common_evasions' list of strings.
        default_severity: the Severity to encode as the
            rule's defaultConfiguration.level. Callers
            compute this by walking the default rule set;
            see _compute_default_severities.

    Returns:
        A reportingDescriptor dict suitable for embedding in
        tool.driver.rules. All values are JSON-serializable.

    The descriptor includes:
      id: the signal_id verbatim.
      name: '{analyzer}/{signal_id_lower}', following
        GitHub's 'language/rule-slug' convention.
      shortDescription.text: first sentence of description.
      fullDescription.text: complete description.
      help.text: plain-text help with description, why it
        matters, and (when present) common evasions.
      help.markdown: same content with markdown formatting.
      defaultConfiguration.level: SARIF level mapped from
        default_severity.
      properties.tags: BASE_TAGS plus an analyzer tag.
      properties.precision: INITIAL_PRECISION.
      properties.security-severity: numeric mapped from
        default_severity.
    """
    description = explanation["description"]
    why_it_matters = explanation["why_it_matters"]
    common_evasions = explanation.get("common_evasions")

    analyzer = analyzer_for_signal(signal_id)

    return {
        "id": signal_id,
        "name": _rule_name(signal_id, analyzer),
        "shortDescription": {"text": _first_sentence(description)},
        "fullDescription": {"text": description},
        "help": {
            "text": _build_help_text(description, why_it_matters, common_evasions),
            "markdown": _build_help_markdown(
                description, why_it_matters, common_evasions
            ),
        },
        "defaultConfiguration": {
            "level": to_sarif_level(default_severity),
        },
        "properties": {
            "tags": list(BASE_TAGS) + [f"analyzer/{analyzer}"],
            "precision": INITIAL_PRECISION,
            "security-severity": to_security_severity(default_severity),
        },
    }


def analyzer_for_signal(signal_id: str) -> str:
    """Return the analyzer name for a signal_id.

    Looks up by the alphabetic prefix of the signal_id.
    Returns 'unknown' if no mapping exists.

    The 'unknown' return value is a defensive default rather
    than a raised exception so that adding a new analyzer
    does not crash SARIF emission before ANALYZER_BY_PREFIX
    is updated. The test suite checks every signal
    in SIGNAL_EXPLANATIONS resolves to a non-'unknown'
    analyzer; that test fails when ANALYZER_BY_PREFIX is out
    of date.

    Args:
        signal_id: a pydepgate signal_id string. Expected to
            start with an uppercase alphabetic prefix.

    Returns:
        The analyzer name, or 'unknown' for unmapped or
        malformed signal_ids.
    """
    match = _PREFIX_PATTERN.match(signal_id)
    if match is None:
        return "unknown"
    prefix = match.group(1)
    return ANALYZER_BY_PREFIX.get(prefix, "unknown")


def _compute_default_severities() -> dict[str, Severity]:
    """Compute each signal's highest default-rule severity.

    Iterates RULES, filters to RuleSource.DEFAULT entries
    with RuleAction.SET_SEVERITY, groups by signal_id, and
    takes the maximum severity per signal. Severity ordering
    is provided by the rank table in severity.py because the
    Severity enum itself does not support direct comparison
    operators.

    Catch-all rules (signal_id is None) are skipped because
    they target every signal indiscriminately and are not
    informative for the per-signal default catalog.

    Returns:
        A dict mapping signal_id to the highest Severity
        any default rule promotes for that signal. Signals
        without any default rule are absent from the result.
    """
    by_signal: dict[str, Severity] = {}
    for rule in RULES:
        if rule.source is not RuleSource.DEFAULT:
            continue
        if rule.effect.action is not RuleAction.SET_SEVERITY:
            continue
        signal_id = rule.match.signal_id
        if signal_id is None:
            continue
        promoted_severity = rule.effect.severity
        if promoted_severity is None:
            continue
        existing = by_signal.get(signal_id)
        if existing is None or severity_rank(promoted_severity) > severity_rank(
            existing
        ):
            by_signal[signal_id] = promoted_severity
    return by_signal


def _rule_name(signal_id: str, analyzer: str) -> str:
    """Build the SARIF rule name from signal_id and analyzer.

    Format: '{analyzer}/{signal_id_lower}'. Mirrors GitHub's
    'language/rule-slug' convention used by CodeQL queries.

    Examples:
      ('DENS010', 'density') becomes 'density/dens010'
      ('DYN006_PRECURSOR', 'dynamic-execution') becomes
        'dynamic-execution/dyn006_precursor'
      ('STDLIB001', 'suspicious-stdlib') becomes
        'suspicious-stdlib/stdlib001'

    The signal_id is lowercased rather than dash-cased so
    that DYN006_PRECURSOR keeps its underscore and remains
    visually distinct from DYN006.
    """
    return f"{analyzer}/{signal_id.lower()}"


def _first_sentence(text: str) -> str:
    """Extract the first sentence of a string.

    A sentence ends at a period followed by whitespace or
    end-of-string. Matches abbreviations and decimal numbers
    correctly because those have no trailing whitespace
    after the period within the same token.

    Args:
        text: any string.

    Returns:
        Everything up to and including the first
        sentence-ending period, or the full text if no
        sentence ending is found.
    """
    match = _SENTENCE_END_PATTERN.search(text)
    if match is None:
        return text
    return text[: match.start() + 1]


def _build_help_text(
    description: str,
    why_it_matters: str,
    common_evasions: Iterable[str] | None,
) -> str:
    """Build the help.text for a rule descriptor.

    Plain-text format suitable for terminals or consumers
    that don't render markdown. Format:

        {description}

        Why it matters:
        {why_it_matters}

        Common evasions:
          - {evasion 1}
          - {evasion 2}
    """
    parts = [description, "", "Why it matters:", why_it_matters]
    if common_evasions:
        parts.extend(["", "Common evasions:"])
        for evasion in common_evasions:
            parts.append(f"  - {evasion}")
    return "\n".join(parts)


def _build_help_markdown(
    description: str,
    why_it_matters: str,
    common_evasions: Iterable[str] | None,
) -> str:
    """Build the help.markdown for a rule descriptor.

    Markdown format. GitHub's alert UI renders help.markdown
    in preference to help.text when both are present. Format:

        {description}

        **Why it matters:**

        {why_it_matters}

        **Common evasions:**

        - `{evasion 1}`
        - `{evasion 2}`

    The bold lead-ins separate sections; the code-fenced
    evasions render as inline code in GitHub's UI, which is
    appropriate because evasions are typically code snippets.
    """
    parts = [description, "", "**Why it matters:**", "", why_it_matters]
    if common_evasions:
        parts.extend(["", "**Common evasions:**", ""])
        for evasion in common_evasions:
            parts.append(f"- `{evasion}`")
    return "\n".join(parts)
