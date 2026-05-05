"""pydepgate.cli.exit_codes

Exit codes for the pydepgate CLI.

These codes are part of pydepgate's public interface: CI systems and
shell scripts depend on them to make decisions about whether a scan
"passed". Changing them is a breaking change.

  0  CLEAN: no findings produced
  1  FINDINGS_BELOW_BLOCKING: findings produced, none HIGH or CRITICAL
  2  FINDINGS_BLOCKING: at least one HIGH or CRITICAL finding
  3  TOOL_ERROR: pydepgate could not complete the scan (artifact
     unreadable, package not installed, malformed wheel, etc.)
"""

CLEAN = 0
FINDINGS_BELOW_BLOCKING = 1
FINDINGS_BLOCKING = 2
TOOL_ERROR = 3