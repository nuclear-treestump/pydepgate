"""pydepgate.reporters.sarif.severity

Maps pydepgate's severity scale to SARIF's level enum and to
GitHub's security-severity numeric.

Pydepgate has five severities: INFO, LOW, MEDIUM, HIGH,
CRITICAL. SARIF's result.level field accepts only three
useful values for code scanning: note, warning, error
(plus 'none' which suppresses the result from the alert
list). GitHub additionally uses a security-severity numeric
in the 0.0 to 10.0 range to drive its critical / high /
medium / low display badges.

The mapping is calibrated so that:

  CRITICAL -> 'error'   level, security-severity 9.5  (display: critical)
  HIGH     -> 'error'   level, security-severity 8.0  (display: high)
  MEDIUM   -> 'warning' level, security-severity 5.0  (display: medium)
  LOW      -> 'note'    level, security-severity 2.0  (display: low)
  INFO     -> 'note'    level, security-severity 0.5  (display: low)

INFO and LOW share the SARIF level 'note' because SARIF has
only three useful levels. The distinction between INFO and
LOW is preserved in the security-severity numeric: INFO
(0.5) is below LOW (2.0), so consumers that consult
security-severity get the full ordering.

The numeric values are anchored inside GitHub's display
bands (>=9.0 critical, 7.0-8.9 high, 4.0-6.9 medium,
0.1-3.9 low) at positions that leave room for future
fine-grained calibration without crossing band boundaries.
"""

from __future__ import annotations

from pydepgate.engines.base import Severity

# Module-level mapping tables. Defined as constants so callers
# (tests, documentation generators) can introspect them
# directly. Updates must touch both tables together.

SARIF_LEVEL_BY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

SECURITY_SEVERITY_BY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.0",
    Severity.INFO: "0.5",
}


def to_sarif_level(severity: Severity) -> str:
    """Return the SARIF level string for a pydepgate severity.

    The return values are exactly those accepted by GitHub
    code scanning: 'note', 'warning', or 'error'.

    Args:
        severity: a Severity enum member.

    Returns:
        The corresponding SARIF level as a lowercase string.

    Raises:
        KeyError: if severity is not a known Severity member.
            This is intentional: an unmapped severity is a
            programming bug that should fail loudly rather
            than silently default to a value that misleads
            consumers.
    """
    return SARIF_LEVEL_BY_SEVERITY[severity]


def to_security_severity(severity: Severity) -> str:
    """Return GitHub's security-severity numeric as a string.

    SARIF's security-severity property is a string per the
    GitHub specification. The string parses as a float;
    GitHub's display logic uses the numeric value to choose
    critical / high / medium / low badges per the bands:

        >= 9.0       critical
        7.0 to 8.9   high
        4.0 to 6.9   medium
        0.1 to 3.9   low
        0.0 or out of range:  no security severity

    Args:
        severity: a Severity enum member.

    Returns:
        The numeric severity as a string suitable for direct
        embedding in SARIF's properties.security-severity
        field.

    Raises:
        KeyError: if severity is not a known Severity member.
    """
    return SECURITY_SEVERITY_BY_SEVERITY[severity]
