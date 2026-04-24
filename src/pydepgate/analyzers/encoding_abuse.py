"""
Detects patterns where encoded content is decoded and executed.

The canonical attack pattern this catches:

    exec(base64.b64decode('...'))

and its many variants:

    eval(codecs.decode(b'...', 'base64'))
    exec(bytes.fromhex('...'))
    exec(zlib.decompress(base64.b64decode('...')))
    exec(binascii.unhexlify('...'))

These are how the vast majority of unsophisticated Python malware hides
its payload. An analyzer that catches 90% of this is catching 90% of
the real attack population.

Confidence calibration:
  - DEFINITE: decode-then-exec chain with obvious encoded-looking string literal
  - HIGH:     decode-then-exec chain without literal (the encoded content is
              loaded from elsewhere, which is still malicious but slightly
              harder to be sure about)
  - MEDIUM:   decode call followed eventually by exec in the same scope
              (loose coupling, more potential for false positives)
"""

from __future__ import annotations

import ast
from typing import Iterable

from pydepgate.analyzers.base import (
    Analyzer, Confidence, Scope, Signal,
)
from pydepgate.analyzers._visitor import _ScopeTracker, get_qualified_name
from pydepgate.parsers.pysource import ParsedPySource, SourceLocation


# Functions that decode encoded content. The tuple format is
# (module, attr) where module can be a dotted path.
_DECODE_FUNCTIONS = {
    ("base64", "b64decode"),
    ("base64", "b32decode"),
    ("base64", "b16decode"),
    ("base64", "a85decode"),
    ("base64", "decodebytes"),
    ("base64", "urlsafe_b64decode"),
    ("codecs", "decode"),
    ("binascii", "unhexlify"),
    ("binascii", "a2b_base64"),
    ("binascii", "a2b_hex"),
    ("zlib", "decompress"),
    ("bz2", "decompress"),
    ("lzma", "decompress"),
    ("gzip", "decompress"),
    ("bytes", "fromhex"),  # bytes.fromhex(...)
}

# Functions that execute code.
_EXEC_FUNCTIONS = {
    "exec", "eval", "compile",
    "__import__",  # Dynamic import, slightly different but similar threat.
}


def _is_decode_call(node: ast.AST) -> tuple[str, str] | None:
    """If node is a call to a known decode function, return (module, attr).

    Returns None otherwise.
    """
    if not isinstance(node, ast.Call):
        return None
    name = get_qualified_name(node.func)
    if name is None:
        return None
    # Match exact module.attr pairs.
    for module, attr in _DECODE_FUNCTIONS:
        if name == f"{module}.{attr}" or (module == "bytes" and name.endswith(".fromhex")):
            return (module, attr)
    # Also check bare names if they might be imported-from.
    # e.g., `from base64 import b64decode; b64decode(...)` would show
    # as just 'b64decode'. We'll catch these in a follow-up pass; for
    # v0.1, we require the module.attr form.
    return None


def _is_exec_call(node: ast.AST) -> str | None:
    """If node is a call to exec/eval/compile/__import__, return the name."""
    if not isinstance(node, ast.Call):
        return None
    name = get_qualified_name(node.func)
    if name in _EXEC_FUNCTIONS:
        return name
    return None


def _string_looks_like_payload(node: ast.AST) -> bool:
    """Heuristic: does this string literal look like an encoded payload?

    True if:
      - It's a str or bytes constant
      - Over 40 characters long
      - Contains only characters from the base64 alphabet (or a tight
        superset like base64url)
    """
    if not isinstance(node, ast.Constant):
        return False
    value = node.value
    if isinstance(value, bytes):
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError:
            return False
    if not isinstance(value, str):
        return False
    if len(value) < 40:
        return False
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_")
    return all(c in allowed for c in value)


class EncodingAbuseAnalyzer(Analyzer):
    """Detects decode-then-exec patterns."""

    @property
    def name(self) -> str:
        return "encoding_abuse"

    def analyze_python(self, parsed: ParsedPySource) -> Iterable[Signal]:
        if not parsed.is_parseable:
            return
        visitor = _Visitor()
        visitor.visit(parsed.ast_tree)
        yield from visitor.signals


class _Visitor(_ScopeTracker):
    """AST visitor implementing the actual detection logic."""

    def __init__(self):
        super().__init__()
        self.signals: list[Signal] = []

    def visit_Call(self, node: ast.Call):
        # Pattern 1: exec(decode(...))
        exec_name = _is_exec_call(node)
        if exec_name and node.args:
            first_arg = node.args[0]
            decode_match = _is_decode_call(first_arg)
            if decode_match is not None:
                module, attr = decode_match
                # Check if the decoded thing looks like a payload literal.
                has_payload_literal = (
                    isinstance(first_arg, ast.Call)
                    and first_arg.args
                    and _string_looks_like_payload(first_arg.args[0])
                )
                confidence = Confidence.DEFINITE if has_payload_literal else Confidence.HIGH
                self.signals.append(Signal(
                    analyzer="encoding_abuse",
                    signal_id="ENC001",
                    confidence=confidence,
                    scope=self.current_scope,
                    location=SourceLocation(
                        line=node.lineno,
                        column=node.col_offset,
                    ),
                    description=(
                        f"{exec_name}() called with result of {module}.{attr}() - "
                        f"classic decode-then-execute pattern"
                    ),
                    context={
                        "exec_function": exec_name,
                        "decode_module": module,
                        "decode_function": attr,
                        "has_payload_literal": has_payload_literal,
                    },
                ))

        self.generic_visit(node)