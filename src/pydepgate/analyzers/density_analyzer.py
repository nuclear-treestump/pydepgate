"""pydepgate.analyzers.density_analyzer

Detects structural obfuscation patterns in Python source files.

This analyzer operates at a different layer than the other pydepgate
analyzers. Where encoding_abuse, dynamic_execution, and string_ops look
for specific *behavioral* patterns (this code will exec something hidden),
code_density looks for *statistical and structural* fingerprints of
intentionally obfuscated code: things that are true of minified,
generated, or deliberately mangled files regardless of what the code
actually does.

None of these signals are individually conclusive. A UUID is high-entropy.
A code-golf solution has very short identifiers. A Cython-generated file
has a deep AST. The rules engine is where context makes these signals
meaningful: a high-entropy string literal in a .pth file is very different
from one in a test fixture.

Signal inventory
----------------
  DENS001  Single-line compression: a physical line with anomalously many
           tokens, indicating minification or deliberate packing.

  DENS002  Semicolon statement chaining: multiple statements joined by
           semicolons on one physical line.

  DENS010  High-entropy string literal: a string constant whose Shannon
           entropy and length together suggest encoded content.

  DENS011  Base64-alphabet string constant: a long string whose character
           set is restricted to the base64 alphabet, indicating a payload
           even without an accompanying exec call.

  DENS020  Low-vowel-ratio identifier: an identifier whose consonant-heavy
           composition suggests random or machine-generated naming.

  DENS021  Confusable single-character identifier: use of 'l', 'O', or 'I'
           as a variable name (PEP 8 explicitly prohibits these because
           they are visually indistinguishable from 0, 0, and 1).

  DENS030  Invisible Unicode character: zero-width spaces, joiners, or the
           byte-order mark found anywhere in the source.

  DENS031  Unicode homoglyph in identifier: a non-ASCII character that is
           visually identical to an ASCII letter used in an identifier,
           enabling steganographic evasion of string-match scanners.

  DENS040  Disproportionate AST depth: the AST is unusually deep relative
           to the file's line count, indicating expression compression.

  DENS041  Deep lambda or comprehension nesting: lambdas or comprehensions
           nested beyond a configurable depth, a common functional-style
           obfuscation technique.

  DENS042  Large integer literal array: a list or tuple whose elements are
           predominantly byte-range integers (0-255), suggesting shellcode
           or payload staging.

  DENS050  High-entropy docstring: a docstring-position string with entropy
           and length suggesting a payload disguised as documentation.

  DENS051  Dynamic __doc__ reference: __doc__ read and passed to a
           callable, suggesting a payload hidden in docstring text.

Thresholds
----------
All numeric thresholds are module-level constants, named _THRESHOLD_* or
_MIN_*. They are chosen conservatively to minimize false positives on
legitimate code, at the cost of missing some obfuscated code. Users who
want more aggressive detection can add rules that lower the effective
threshold by promoting AMBIGUOUS signals to higher severities.
"""

from __future__ import annotations

import ast
import io
import math
import tokenize
import unicodedata
from collections import Counter
from typing import Iterable

from pydepgate.analyzers.base import (
    Analyzer,
    Confidence,
    Scope,
    Signal,
)
from pydepgate.analyzers._visitor import _ScopeTracker
from pydepgate.parsers.pysource import ParsedPySource, SourceLocation
from pydepgate.enrichers._magic import detect_format
from pydepgate.analyzers._enrichment import stash_value

# ---------------------------------------------------------------------------
# DENS001 thresholds: single-line token compression
# ---------------------------------------------------------------------------
# Number of non-whitespace, non-newline tokens on one physical line
# before the signal fires. 50 is a conservative choice: even dense
# legitimate Python (long function signatures, chained calls) rarely
# exceeds 30-35 tokens on one line. 80+ is almost certainly generated.
_THRESHOLD_TOKENS_PER_LINE_MEDIUM = 50
_THRESHOLD_TOKENS_PER_LINE_HIGH = 100

# ---------------------------------------------------------------------------
# DENS002 thresholds: semicolon chaining
# ---------------------------------------------------------------------------
# Number of semicolons on one physical line before the signal fires.
# One semicolon is unusual but not unheard of in legitimate code.
# Two or more on the same line is virtually always obfuscation.
_THRESHOLD_SEMICOLONS_MEDIUM = 1
_THRESHOLD_SEMICOLONS_HIGH = 3

# ---------------------------------------------------------------------------
# DENS010 thresholds: high-entropy string literals
# ---------------------------------------------------------------------------
# Shannon entropy (bits per character) thresholds. Calibrated against real
# attack payloads:
#
#   Base64(random bytes, 200b) ~5.8     -> HIGH if long enough
#   Base64(Python source)      ~5.2-5.4 -> AMBIGUOUS/MEDIUM
#   Normal Python strings      ~3.5-5.0 -> no signal
#
# The AMBIGUOUS tier exists specifically because b64-encoded Python source
# (the LiteLLM 1.82.8 attack pattern) lands at ~5.2-5.4, below what a
# naive "only flag truly random-looking strings" threshold would catch.
# The rules engine promotes AMBIGUOUS to MEDIUM or higher for .pth files
# and setup.py, where there is no legitimate reason for encoded content.
_THRESHOLD_ENTROPY_AMBIGUOUS = 5.2
_THRESHOLD_ENTROPY_MEDIUM = 5.5
_THRESHOLD_ENTROPY_HIGH = 5.8
# Minimum string length before entropy is computed. Short strings have
# noisily high entropy by chance (e.g. "q4" has entropy 1.0).
_MIN_LEN_FOR_ENTROPY = 80

# ---------------------------------------------------------------------------
# DENS011 thresholds: base64-alphabet strings
# ---------------------------------------------------------------------------
# Minimum length of a b64-alphabet string to flag. The encoding_abuse
# analyzer already catches strings used directly with b64decode(). This
# signal fires on strings that just *sit there* looking like payloads.
# 80 chars is chosen so that a typical b64-encoded attack payload (~88 bytes
# of source becoming ~120 chars b64, but sometimes shorter) is reliably
# caught.
_MIN_LEN_B64_ALPHABET = 80
_B64_ALPHABET = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=-_"
)

# ---------------------------------------------------------------------------
# DENS020 thresholds: identifier vowel ratio
# ---------------------------------------------------------------------------
# Vowel ratio = vowels / len(identifier). English words average ~0.38.
# Names with no vowels at all (ratio 0.0) are suspicious when long enough.
_VOWELS = frozenset("aeiouAEIOU")
_THRESHOLD_VOWEL_RATIO = 0.10  # below this is suspicious
_MIN_LEN_FOR_VOWEL_CHECK = 8  # don't flag short abbreviations

# Identifiers to skip entirely: builtins, dunders, common abbreviations
# that legitimately have no vowels.
_SKIP_IDENTIFIERS = frozenset(
    {
        # Python builtins
        "print",
        "len",
        "str",
        "int",
        "float",
        "bool",
        "list",
        "dict",
        "set",
        "tuple",
        "type",
        "None",
        "True",
        "False",
        # Common single-word abbreviations that are vowel-free
        "cls",
        "ctx",
        "fmt",
        "fn",
        "fs",
        "idx",
        "msg",
        "num",
        "ptr",
        "rc",
        "ret",
        "tmp",
        "typ",
        "val",
    }
)

# ---------------------------------------------------------------------------
# DENS021: confusable single-character identifiers
# ---------------------------------------------------------------------------
_CONFUSABLE_SINGLE_CHARS = frozenset("lOI")

# ---------------------------------------------------------------------------
# DENS030: invisible Unicode characters
# ---------------------------------------------------------------------------
_INVISIBLE_CODEPOINTS: dict[str, str] = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\ufeff": "BYTE ORDER MARK / ZERO WIDTH NO-BREAK SPACE",
    "\u00ad": "SOFT HYPHEN",
    "\u034f": "COMBINING GRAPHEME JOINER",
    "\u17b4": "KHMER VOWEL INHERENT AQ",
    "\u17b5": "KHMER VOWEL INHERENT AA",
    "\u2028": "LINE SEPARATOR",
    "\u2029": "PARAGRAPH SEPARATOR",
    "\u202a": "LEFT-TO-RIGHT EMBEDDING",
    "\u202b": "RIGHT-TO-LEFT EMBEDDING",
    "\u202c": "POP DIRECTIONAL FORMATTING",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE",  # highest risk: changes visual order
    "\u2066": "LEFT-TO-RIGHT ISOLATE",
    "\u2067": "RIGHT-TO-LEFT ISOLATE",
    "\u2068": "FIRST STRONG ISOLATE",
    "\u2069": "POP DIRECTIONAL ISOLATE",
}

# ---------------------------------------------------------------------------
# DENS031: Unicode homoglyphs
# ---------------------------------------------------------------------------
# Characters from other scripts that are visually indistinguishable from
# the ASCII letters shown in the values. This list covers the most common
# ones used in real attacks; it is not exhaustive.
_HOMOGLYPHS: dict[str, str] = {
    # Cyrillic
    "\u0430": "a",  # cyrillic small a -> ascii a
    "\u0435": "e",  # cyrillic small ie -> ascii e
    "\u043e": "o",  # cyrillic small o -> ascii o
    "\u0440": "p",  # cyrillic small er -> ascii p
    "\u0441": "c",  # cyrillic small es -> ascii c
    "\u0445": "x",  # cyrillic small ha -> ascii x
    "\u0410": "A",  # cyrillic capital A
    "\u0412": "B",  # cyrillic capital Ve
    "\u0415": "E",  # cyrillic capital Ie
    "\u041a": "K",  # cyrillic capital Ka
    "\u041c": "M",  # cyrillic capital Em
    "\u041d": "H",  # cyrillic capital En
    "\u041e": "O",  # cyrillic capital O
    "\u0420": "P",  # cyrillic capital Er
    "\u0421": "C",  # cyrillic capital Es
    "\u0422": "T",  # cyrillic capital Te
    "\u0425": "X",  # cyrillic capital Ha
    "\u0443": "y",  # cyrillic small u -> ascii y
    # Greek
    "\u03bf": "o",  # greek small omicron -> ascii o
    "\u03c1": "p",  # greek small rho -> ascii p
    "\u03c5": "u",  # greek small upsilon -> ascii u
    "\u0391": "A",  # greek capital Alpha
    "\u0392": "B",  # greek capital Beta
    "\u0395": "E",  # greek capital Epsilon
    "\u0396": "Z",  # greek capital Zeta
    "\u0397": "H",  # greek capital Eta
    "\u0399": "I",  # greek capital Iota
    "\u039a": "K",  # greek capital Kappa
    "\u039c": "M",  # greek capital Mu
    "\u039d": "N",  # greek capital Nu
    "\u039f": "O",  # greek capital Omicron
    "\u03a1": "P",  # greek capital Rho
    "\u03a4": "T",  # greek capital Tau
    "\u03a5": "Y",  # greek capital Upsilon
    "\u03a7": "X",  # greek capital Chi
}

# ---------------------------------------------------------------------------
# DENS040 thresholds: AST depth
# ---------------------------------------------------------------------------
# Ratio of max AST depth to file line count above which the signal fires.
# A 100-line file with AST depth 500 is almost certainly generated or
# obfuscated.
_THRESHOLD_DEPTH_RATIO_MEDIUM = 4.0
_THRESHOLD_DEPTH_RATIO_HIGH = 8.0
_MIN_LINE_COUNT_FOR_DEPTH = 5  # don't flag tiny files

# ---------------------------------------------------------------------------
# DENS041 thresholds: lambda/comprehension nesting
# ---------------------------------------------------------------------------
_THRESHOLD_NEST_DEPTH = 3  # lambdas or comprehensions nested beyond this

# ---------------------------------------------------------------------------
# DENS042 thresholds: integer literal arrays
# ---------------------------------------------------------------------------
_THRESHOLD_INT_ARRAY_LEN = 24  # minimum element count to flag
_THRESHOLD_INT_ARRAY_RATIO = 0.80  # proportion that must be 0-255 ints

# ---------------------------------------------------------------------------
# DENS050 thresholds: high-entropy docstrings
# ---------------------------------------------------------------------------
# Same as DENS010 but applied only to docstring-position constants.
# We use a slightly lower length threshold because docstrings that are
# encoded payloads tend to be shorter than standalone payload variables.
_MIN_LEN_FOR_DOCSTRING_ENTROPY = 60
_THRESHOLD_DOCSTRING_ENTROPY = 5.6  # slightly more sensitive than DENS010


# ===========================================================================
# Shared utility functions
# ===========================================================================


def _shannon_entropy(text: str) -> float:
    """Compute the Shannon entropy of a string in bits per character.

    Returns 0.0 for empty strings.
    """
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _vowel_ratio(name: str) -> float:
    """Fraction of characters in name that are vowels."""
    if not name:
        return 0.0
    return sum(1 for ch in name if ch in _VOWELS) / len(name)


def _max_ast_depth(tree: ast.AST) -> int:
    """Return the maximum depth of the AST, measured in node levels."""
    max_depth = 0
    stack: list[tuple[ast.AST, int]] = [(tree, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > max_depth:
            max_depth = depth
        for child in ast.iter_child_nodes(node):
            stack.append((child, depth + 1))
    return max_depth


def _value_preview(value: str | bytes, max_len: int = 40) -> str:
    """A truncated, safe string representation for signal context."""
    if isinstance(value, bytes):
        try:
            s = value.decode("ascii")
        except UnicodeDecodeError:
            s = repr(value)
    else:
        s = value
    if len(s) > max_len:
        return s[:max_len] + "..."
    return s


def _is_docstring_position(node: ast.Expr, parent: ast.AST) -> bool:
    """True if node is in docstring position (first stmt of a body)."""
    if not isinstance(node.value, ast.Constant):
        return False
    if not isinstance(node.value.value, str):
        return False
    body: list[ast.stmt] | None = None
    if isinstance(
        parent, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    ):
        body = parent.body  # type: ignore[assignment]
    if body and body[0] is node:
        return True
    return False


def _docstring_looks_like_prose(content: str) -> bool:
    """True if content classifies as plain ASCII prose.

    Uses _magic.detect_format to identify content shape. Returns True
    only when the result is a terminal `ascii_text` classification,
    which is the single shape that means "ordinary text, not encoded,
    not Python source, not binary." Every other classification (any
    encoding shape, Python source, pickle, binary executable, image,
    archive, unknown binary, etc.) returns False because those are
    all signals worth flagging in a docstring context.

    Empty content returns False conservatively. An empty docstring
    is unusual enough that we'd rather keep the DENS051 finding than
    suppress on it.
    """
    if not content:
        return False
    result = detect_format(content)
    return result.is_terminal and result.kind == "ascii_text"


# ===========================================================================
# Token-level analysis (operates on raw source text)
# ===========================================================================


def _analyze_token_density(
    source_text: str,
    analyzer_name: str,
    file_scope: Scope,
) -> list[Signal]:
    """
    Tokenize source_text and emit signals for:
      DENS001: lines with anomalously high token counts
      DENS002: lines with multiple semicolons

    Returns a (possibly empty) list of Signals.
    """
    signals: list[Signal] = []

    # Map physical line number to list of token types seen on that line.
    # We use token.start[0] (1-based) as the line key.
    tokens_by_line: dict[int, list[int]] = {}
    semis_by_line: dict[int, int] = {}

    buf = io.BytesIO(source_text.encode("utf-8", errors="replace"))
    try:
        for tok in tokenize.tokenize(buf.readline):
            if tok.type in (
                tokenize.NEWLINE,
                tokenize.NL,
                tokenize.INDENT,
                tokenize.DEDENT,
                tokenize.COMMENT,
                tokenize.ENCODING,
                tokenize.ENDMARKER,
            ):
                continue
            line_no = tok.start[0]
            tokens_by_line.setdefault(line_no, []).append(tok.type)
            if tok.type == tokenize.OP and tok.string == ";":
                semis_by_line[line_no] = semis_by_line.get(line_no, 0) + 1
    except (tokenize.TokenError, IndentationError, UnicodeDecodeError):
        # Tokenization failure is not our job to flag; parsers handle it.
        pass

    # DENS001: token density per line
    for line_no, toks in tokens_by_line.items():
        count = len(toks)
        if count >= _THRESHOLD_TOKENS_PER_LINE_HIGH:
            confidence = Confidence.HIGH
        elif count >= _THRESHOLD_TOKENS_PER_LINE_MEDIUM:
            confidence = Confidence.MEDIUM
        else:
            continue
        signals.append(
            Signal(
                analyzer=analyzer_name,
                signal_id="DENS001",
                confidence=confidence,
                scope=file_scope,
                location=SourceLocation(line=line_no, column=0),
                description=(
                    f"line {line_no} contains {count} tokens, "
                    f"consistent with minification or deliberate compression"
                ),
                context={
                    "line": line_no,
                    "token_count": count,
                    "threshold": (
                        _THRESHOLD_TOKENS_PER_LINE_HIGH
                        if confidence == Confidence.HIGH
                        else _THRESHOLD_TOKENS_PER_LINE_MEDIUM
                    ),
                },
            )
        )

    # DENS002: semicolon chaining
    for line_no, count in semis_by_line.items():
        if count >= _THRESHOLD_SEMICOLONS_HIGH:
            confidence = Confidence.HIGH
        elif count >= _THRESHOLD_SEMICOLONS_MEDIUM:
            confidence = Confidence.MEDIUM
        else:
            continue
        # Approximate statement count as semicolons + 1
        stmt_count = count + 1
        signals.append(
            Signal(
                analyzer=analyzer_name,
                signal_id="DENS002",
                confidence=confidence,
                scope=file_scope,
                location=SourceLocation(line=line_no, column=0),
                description=(
                    f"line {line_no} chains {stmt_count} statements "
                    f"via {count} semicolon{'s' if count != 1 else ''}"
                ),
                context={
                    "line": line_no,
                    "semicolon_count": count,
                    "statement_count": stmt_count,
                },
            )
        )

    return signals


# ===========================================================================
# Raw-text Unicode analysis (operates on source_text directly)
# ===========================================================================


def _analyze_unicode_anomalies(
    source_text: str,
    analyzer_name: str,
) -> list[Signal]:
    """
    Scan source_text for invisible characters (DENS030) and homoglyph
    characters in identifier-likely positions (DENS031).

    Line numbers are computed by scanning for newlines before each
    match position.
    """
    signals: list[Signal] = []

    # Pre-compute line starts so we can map char offset to line number.
    line_starts = [0]
    for i, ch in enumerate(source_text):
        if ch == "\n":
            line_starts.append(i + 1)

    def _offset_to_line(offset: int) -> int:
        # Binary search in line_starts for the line containing offset.
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1  # 1-indexed

    # Track which lines we've already emitted each signal for, to avoid
    # flooding with one signal per character occurrence on the same line.
    dens030_lines: set[int] = set()
    dens031_lines: set[tuple[int, str]] = set()

    for offset, ch in enumerate(source_text):
        # DENS030: invisible Unicode
        if ch in _INVISIBLE_CODEPOINTS:
            line_no = _offset_to_line(offset)
            if line_no not in dens030_lines:
                dens030_lines.add(line_no)
                name = _INVISIBLE_CODEPOINTS[ch]
                codepoint = f"U+{ord(ch):04X}"
                # RTL override is DEFINITE; everything else is HIGH.
                confidence = (
                    Confidence.DEFINITE
                    if ch in ("\u202e", "\u202d")
                    else Confidence.HIGH
                )
                signals.append(
                    Signal(
                        analyzer=analyzer_name,
                        signal_id="DENS030",
                        confidence=confidence,
                        scope=Scope.MODULE,
                        location=SourceLocation(line=line_no, column=0),
                        description=(
                            f"{name} ({codepoint}) found at line {line_no}; "
                            f"invisible characters in source can hide content "
                            f"from human readers and naive string-match scanners"
                        ),
                        context={
                            "codepoint": codepoint,
                            "unicode_name": name,
                            "line": line_no,
                        },
                    )
                )

        # DENS031: homoglyph characters
        if ch in _HOMOGLYPHS:
            line_no = _offset_to_line(offset)
            ascii_lookalike = _HOMOGLYPHS[ch]
            key = (line_no, ch)
            if key not in dens031_lines:
                dens031_lines.add(key)
                codepoint = f"U+{ord(ch):04X}"
                try:
                    unicode_name = unicodedata.name(ch, "UNKNOWN")
                except ValueError:
                    unicode_name = "UNKNOWN"
                signals.append(
                    Signal(
                        analyzer=analyzer_name,
                        signal_id="DENS031",
                        confidence=Confidence.DEFINITE,
                        scope=Scope.MODULE,
                        location=SourceLocation(line=line_no, column=0),
                        description=(
                            f"{unicode_name} ({codepoint}) at line {line_no} "
                            f"is visually identical to ASCII '{ascii_lookalike}' "
                            f"but is a distinct character; enables evasion of "
                            f"string-match scanners (e.g. cyrillic-mixed "
                            f"identifiers can evade an 'exec' string match)"
                        ),
                        context={
                            "codepoint": codepoint,
                            "unicode_name": unicode_name,
                            "ascii_lookalike": ascii_lookalike,
                            "line": line_no,
                        },
                    )
                )

    return signals


# ===========================================================================
# AST visitor
# ===========================================================================


class _Visitor(_ScopeTracker):
    """
    AST visitor for code_density detection.

    Walks the tree collecting signals for string entropy (DENS010/050),
    base64-alphabet strings (DENS011), identifier anomalies (DENS020/021),
    structural depth (DENS041), integer arrays (DENS042), and
    dynamic __doc__ references (DENS051).

    DENS040 (whole-file AST depth) is computed outside the visitor by
    the analyzer's analyze_python method, since it is a single
    file-level metric rather than a per-node observation.

    Emits signals into self.signals as it walks. No finalize() pass is
    needed: all checks are local to the nodes where they fire.
    """

    def __init__(self, analyzer_name: str) -> None:
        super().__init__()
        self.signals: list[Signal] = []
        self._analyzer_name = analyzer_name

        # For DENS041: track nesting depth of lambda/comprehension nodes.
        self._nest_depth: int = 0

        # Parent tracking for DENS050 (docstring detection).
        # We use a simple parent stack rather than ast.get_parent_map
        # to avoid building the whole map upfront.
        self._parent_stack: list[ast.AST] = []

        # For DENS051 resolution: index of top-level definitions by
        # name. Populated when entering the module. Used to resolve
        # `.__doc__` references where obj is a name defined at
        # module top level. Nested definitions are not indexed for
        # simplicity; references that can't be resolved fall through
        # to conservative emit-anyway behavior.
        self._top_level_defs: dict[str, ast.AST] = {}

    # ------------------------------------------------------------------
    # Parent tracking helpers
    # ------------------------------------------------------------------

    def _push_parent(self, node: ast.AST) -> None:
        self._parent_stack.append(node)

    def _pop_parent(self) -> None:
        if self._parent_stack:
            self._parent_stack.pop()

    @property
    def _current_parent(self) -> ast.AST | None:
        return self._parent_stack[-1] if self._parent_stack else None

    # ------------------------------------------------------------------
    # Scope-bearing node visitors (push/pop parent AND scope)
    # ------------------------------------------------------------------

    def visit_Module(self, node: ast.Module) -> None:
        self._push_parent(node)
        # Build top-level definitions index for DENS051 resolution.
        # We only index top-level names; nested definitions are
        # resolved conservatively (emit the finding rather than
        # try harder).
        for stmt in node.body:
            if isinstance(
                stmt,
                (
                    ast.FunctionDef,
                    ast.AsyncFunctionDef,
                    ast.ClassDef,
                ),
            ):
                self._top_level_defs[stmt.name] = stmt
        self.generic_visit(node)
        self._pop_parent()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._push_parent(node)
        super().visit_FunctionDef(node)  # handles scope stack + generic_visit
        self._pop_parent()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._push_parent(node)
        super().visit_AsyncFunctionDef(node)
        self._pop_parent()

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._push_parent(node)
        super().visit_ClassDef(node)
        self._pop_parent()

    # ------------------------------------------------------------------
    # DENS010 + DENS011 + DENS050: string literal analysis
    # ------------------------------------------------------------------

    def visit_Expr(self, node: ast.Expr) -> None:
        """Handle bare expression statements, catching docstrings."""
        parent = self._current_parent
        if (
            parent is not None
            and _is_docstring_position(node, parent)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            self._check_docstring_entropy(node.value)
            # Do NOT generic_visit here: the inner Constant would
            # otherwise be re-visited by visit_Constant and produce a
            # duplicate DENS010/DENS011 signal for the same string.
            # Docstrings are reported as DENS050 only.
            return
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        value = node.value
        if isinstance(value, (str, bytes)):
            self._check_string_entropy(node, value)
            self._check_b64_alphabet(node, value)
        self.generic_visit(node)

    def _check_string_entropy(
        self,
        node: ast.Constant,
        value: str | bytes,
    ) -> None:
        """DENS010: high-entropy string literal."""
        if isinstance(value, bytes):
            try:
                s = value.decode("ascii")
            except UnicodeDecodeError:
                # Non-ASCII bytes: compute entropy on the byte values as chars
                s = "".join(chr(b) for b in value)
        else:
            s = value

        if len(s) < _MIN_LEN_FOR_ENTROPY:
            return

        entropy = _shannon_entropy(s)

        if entropy >= _THRESHOLD_ENTROPY_HIGH and len(s) >= 200:
            confidence = Confidence.HIGH
        elif entropy >= _THRESHOLD_ENTROPY_MEDIUM:
            confidence = Confidence.MEDIUM
        elif entropy >= _THRESHOLD_ENTROPY_AMBIGUOUS:
            # AMBIGUOUS catches b64(Python source) ~5.2-5.4.
            # Rules promote this to MEDIUM/HIGH for .pth and setup.py.
            confidence = Confidence.AMBIGUOUS
        else:
            return

        stashed, truncated = stash_value(value)
        dens010_context: dict = {
            "entropy": round(entropy, 4),
            "length": len(s),
            "value_preview": _value_preview(value),
            "scope_name": self.current_scope.name.lower(),
            "_full_value": stashed,
        }
        if truncated:
            dens010_context["_full_value_truncated"] = True
        self.signals.append(
            Signal(
                analyzer=self._analyzer_name,
                signal_id="DENS010",
                confidence=confidence,
                scope=self.current_scope,
                location=SourceLocation(line=node.lineno, column=node.col_offset),
                description=(
                    f"string literal at line {node.lineno} has Shannon entropy "
                    f"{entropy:.2f} bits/char (length {len(s)}), "
                    f"consistent with base64, compressed, or encrypted content"
                ),
                context=dens010_context,
                enrichment_hints=frozenset({"payload_peek"}),
            )
        )

    def _check_b64_alphabet(
        self,
        node: ast.Constant,
        value: str | bytes,
    ) -> None:
        """DENS011: string whose character set is confined to the base64 alphabet."""
        if isinstance(value, bytes):
            try:
                s = value.decode("ascii")
            except UnicodeDecodeError:
                return
        else:
            s = value

        if len(s) < _MIN_LEN_B64_ALPHABET:
            return

        # Must be *entirely* within the b64 alphabet and include at least
        # some uppercase, lowercase, and digits (to avoid flagging long
        # slugs or hex strings).
        if not all(ch in _B64_ALPHABET for ch in s):
            return

        has_upper = any(ch.isupper() for ch in s)
        has_lower = any(ch.islower() for ch in s)
        has_digits = any(ch.isdigit() for ch in s)
        if not (has_upper and has_lower and has_digits):
            return

        # Note: DENS010 may also fire on the same string if entropy is
        # high enough. The two signals are intentionally distinct
        # perspectives (entropy vs alphabet) and rules can suppress one
        # if the duplication is unwanted.
        stashed, truncated = stash_value(value)
        dens011_context: dict = {
            "length": len(s),
            "value_preview": _value_preview(s),
            "scope_name": self.current_scope.name.lower(),
            "_full_value": stashed,
        }
        if truncated:
            dens011_context["_full_value_truncated"] = True
        self.signals.append(
            Signal(
                analyzer=self._analyzer_name,
                signal_id="DENS011",
                confidence=Confidence.MEDIUM,
                scope=self.current_scope,
                location=SourceLocation(line=node.lineno, column=node.col_offset),
                description=(
                    f"string literal at line {node.lineno} (length {len(s)}) "
                    f"uses only base64-alphabet characters, may be an encoded "
                    f"payload even without an accompanying decode/exec call"
                ),
                context=dens011_context,
                enrichment_hints=frozenset({"payload_peek"}),
            )
        )

    def _check_docstring_entropy(self, node: ast.Constant) -> None:
        """DENS050: high-entropy string in docstring position."""
        s = node.value
        if not isinstance(s, str):
            return
        if len(s) < _MIN_LEN_FOR_DOCSTRING_ENTROPY:
            return

        entropy = _shannon_entropy(s)
        if entropy < _THRESHOLD_DOCSTRING_ENTROPY:
            return

        self.signals.append(
            Signal(
                analyzer=self._analyzer_name,
                signal_id="DENS050",
                confidence=Confidence.HIGH,
                scope=self.current_scope,
                location=SourceLocation(line=node.lineno, column=node.col_offset),
                description=(
                    f"string in docstring position at line {node.lineno} has "
                    f"Shannon entropy {entropy:.2f} bits/char (length {len(s)}), "
                    f"may be a payload disguised as documentation"
                ),
                context={
                    "entropy": round(entropy, 4),
                    "length": len(s),
                    "value_preview": _value_preview(s),
                    "scope_name": self.current_scope.name.lower(),
                },
            )
        )

    # ------------------------------------------------------------------
    # DENS020 + DENS021: identifier analysis
    # ------------------------------------------------------------------

    def visit_Name(self, node: ast.Name) -> None:
        self._check_identifier(node.id, node.lineno, node.col_offset)
        self.generic_visit(node)

    def visit_arg(self, node: ast.arg) -> None:
        """Function argument names."""
        self._check_identifier(node.arg, node.lineno, node.col_offset)
        self.generic_visit(node)

    def _check_identifier(
        self,
        name: str,
        line: int,
        col: int,
    ) -> None:
        """Check a single identifier for DENS020 and DENS021."""
        # Skip dunders, short single-char names (handled by DENS021
        # separately), and names in the skip list.
        if name.startswith("__") and name.endswith("__"):
            return
        if name in _SKIP_IDENTIFIERS:
            return

        # DENS021: confusable single characters
        if len(name) == 1 and name in _CONFUSABLE_SINGLE_CHARS:
            self.signals.append(
                Signal(
                    analyzer=self._analyzer_name,
                    signal_id="DENS021",
                    confidence=Confidence.LOW,
                    scope=self.current_scope,
                    location=SourceLocation(line=line, column=col),
                    description=(
                        f"single-character identifier {name!r} at line {line} "
                        f"is visually confusable with a digit (PEP 8 "
                        f"'Names to avoid')"
                    ),
                    context={
                        "identifier": name,
                        "confusable_with": (
                            "1" if name == "l" else "0" if name == "O" else "1"  # I
                        ),
                    },
                )
            )
            return

        # DENS020: low vowel ratio
        if len(name) < _MIN_LEN_FOR_VOWEL_CHECK:
            return

        ratio = _vowel_ratio(name)
        if ratio <= _THRESHOLD_VOWEL_RATIO:
            # Slightly higher confidence for longer names (harder to
            # accidentally have no vowels in a 10-char English word).
            confidence = Confidence.MEDIUM if len(name) >= 10 else Confidence.LOW
            self.signals.append(
                Signal(
                    analyzer=self._analyzer_name,
                    signal_id="DENS020",
                    confidence=confidence,
                    scope=self.current_scope,
                    location=SourceLocation(line=line, column=col),
                    description=(
                        f"identifier {name!r} at line {line} has a vowel ratio "
                        f"of {ratio:.2f}, consistent with randomly generated "
                        f"or machine-produced names"
                    ),
                    context={
                        "identifier": name,
                        "vowel_ratio": round(ratio, 4),
                        "length": len(name),
                    },
                )
            )

    # ------------------------------------------------------------------
    # DENS040: disproportionate AST depth (handled post-walk in analyzer)
    # DENS041: deep lambda/comprehension nesting
    # ------------------------------------------------------------------

    def _enter_nest(self) -> None:
        self._nest_depth += 1

    def _exit_nest(self) -> None:
        self._nest_depth -= 1

    def _check_nest_depth(
        self,
        node: ast.AST,
        node_label: str,
    ) -> None:
        if self._nest_depth > _THRESHOLD_NEST_DEPTH:
            self.signals.append(
                Signal(
                    analyzer=self._analyzer_name,
                    signal_id="DENS041",
                    confidence=Confidence.MEDIUM,
                    scope=self.current_scope,
                    location=SourceLocation(
                        line=node.lineno,  # type: ignore[attr-defined]
                        column=node.col_offset,  # type: ignore[attr-defined]
                    ),
                    description=(
                        f"{node_label} at line {node.lineno} is nested "  # type: ignore[attr-defined]
                        f"{self._nest_depth} levels deep inside other "
                        f"lambdas or comprehensions; deep nesting is a "
                        f"common functional-style obfuscation technique"
                    ),
                    context={
                        "nesting_depth": self._nest_depth,
                        "node_type": node_label,
                    },
                )
            )

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self._enter_nest()
        self._check_nest_depth(node, "lambda")
        self.generic_visit(node)
        self._exit_nest()

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._enter_nest()
        self._check_nest_depth(node, "list comprehension")
        self.generic_visit(node)
        self._exit_nest()

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self._enter_nest()
        self._check_nest_depth(node, "set comprehension")
        self.generic_visit(node)
        self._exit_nest()

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._enter_nest()
        self._check_nest_depth(node, "dict comprehension")
        self.generic_visit(node)
        self._exit_nest()

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self._enter_nest()
        self._check_nest_depth(node, "generator expression")
        self.generic_visit(node)
        self._exit_nest()

    # ------------------------------------------------------------------
    # DENS042: large integer literal array
    # ------------------------------------------------------------------

    def _check_int_array(
        self,
        node: ast.List | ast.Tuple,
        label: str,
    ) -> None:
        elts = node.elts
        if len(elts) < _THRESHOLD_INT_ARRAY_LEN:
            return

        # Count how many elements are integer constants in 0-255.
        byte_range_count = sum(
            1
            for e in elts
            if (
                isinstance(e, ast.Constant)
                and isinstance(e.value, int)
                and 0 <= e.value <= 255
            )
        )
        ratio = byte_range_count / len(elts)
        if ratio < _THRESHOLD_INT_ARRAY_RATIO:
            return

        # Collect a short preview of the values.
        preview: list[int] = []
        for e in elts[:8]:
            if isinstance(e, ast.Constant) and isinstance(e.value, int):
                preview.append(e.value)

        self.signals.append(
            Signal(
                analyzer=self._analyzer_name,
                signal_id="DENS042",
                confidence=Confidence.MEDIUM,
                scope=self.current_scope,
                location=SourceLocation(
                    line=node.lineno,
                    column=node.col_offset,
                ),
                description=(
                    f"{label} at line {node.lineno} contains {len(elts)} "
                    f"elements, {byte_range_count} of which are byte-range "
                    f"integers (0-255), a pattern consistent with shellcode "
                    f"or payload byte array staging"
                ),
                context={
                    "element_count": len(elts),
                    "byte_range_count": byte_range_count,
                    "byte_range_ratio": round(ratio, 4),
                    "value_preview": preview,
                },
            )
        )

    def visit_List(self, node: ast.List) -> None:
        self._check_int_array(node, "list literal")
        self.generic_visit(node)

    def visit_Tuple(self, node: ast.Tuple) -> None:
        self._check_int_array(node, "tuple literal")
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # DENS051: dynamic __doc__ reference
    # ------------------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        """Check if any argument to a call is a __doc__ reference.

        Before emitting DENS051, attempt to resolve the actual
        docstring content. If the content classifies as plain
        ASCII prose via _magic.detect_format, suppress the finding
        (this is documentation tooling, not payload hiding). If
        the content classifies as anything else, or cannot be
        resolved, emit DENS051 as before.
        """
        all_args = list(node.args) + [kw.value for kw in node.keywords]
        for arg in all_args:
            doc_ref = self._get_doc_ref(arg)
            if doc_ref is None:
                continue

            # Attempt resolution + prose check. If the docstring
            # resolves and looks like prose, suppress.
            content = self._resolve_docstring_content(arg)
            if content is not None and _docstring_looks_like_prose(content):
                continue

            # Otherwise emit. Conservative on unresolvable references:
            # we'd rather over-flag than miss an attack.
            callee = self._callee_name(node.func)
            self.signals.append(
                Signal(
                    analyzer=self._analyzer_name,
                    signal_id="DENS051",
                    confidence=Confidence.HIGH,
                    scope=self.current_scope,
                    location=SourceLocation(
                        line=node.lineno,
                        column=node.col_offset,
                    ),
                    description=(
                        f"__doc__ passed to {callee}() at line "
                        f"{node.lineno}; payloads are sometimes hidden "
                        f"in docstring text and executed via this pattern"
                    ),
                    context={
                        "reference": doc_ref,
                        "callee": callee,
                    },
                )
            )
        self.generic_visit(node)

    @staticmethod
    def _get_doc_ref(node: ast.expr) -> str | None:
        """If node is a __doc__ reference, return its textual form."""
        if isinstance(node, ast.Name) and node.id == "__doc__":
            return "__doc__"
        if isinstance(node, ast.Attribute) and node.attr == "__doc__":
            return "<obj>.__doc__"
        return None

    @staticmethod
    def _callee_name(func: ast.expr) -> str:
        """Best-effort name of the function being called."""
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return ""

    def _resolve_docstring_content(
        self,
        arg_node: ast.expr,
    ) -> str | None:
        """Resolve the actual docstring text for a __doc__ reference.

        Two cases:

          Bare `__doc__`: look up the scope whose docstring this
          reference resolves to at runtime, per Python's name
          resolution rules. See _find_docstring_scope_for_bare_doc
          for the rules.

          `.__doc__` where obj is a Name: look up obj in the
          top-level definitions index. If obj is a FunctionDef,
          AsyncFunctionDef, or ClassDef defined at module top level,
          return its docstring.

        Returns the docstring string on success, None when the
        reference cannot be resolved statically. None causes the
        caller to fall through to conservative emit.
        """
        if isinstance(arg_node, ast.Name) and arg_node.id == "__doc__":
            scope = self._find_docstring_scope_for_bare_doc()
            if scope is None:
                return None
            return ast.get_docstring(scope, clean=False)

        if (
            isinstance(arg_node, ast.Attribute)
            and arg_node.attr == "__doc__"
            and isinstance(arg_node.value, ast.Name)
        ):
            target = self._top_level_defs.get(arg_node.value.id)
            if target is None:
                return None
            return ast.get_docstring(target, clean=False)

        return None

    def _find_docstring_scope_for_bare_doc(self) -> ast.AST | None:
        """Find the scope a bare __doc__ reference resolves to.

        Python's runtime semantics for `__doc__` as a bare name:

          - At module top level: the module's __doc__ attribute.
          - Inside a class body (but not in a nested function): the
            class's __doc__ attribute.
          - Inside a function body (regardless of class containment):
            falls through to module's __doc__ via name resolution.

        Walks the parent stack from innermost outward. If a Function
        or AsyncFunction is encountered before any ClassDef, the
        reference is module-scoped. If a ClassDef is encountered
        first, the reference is class-scoped. Otherwise (no enclosing
        scope), we're at module level.
        """
        for parent in reversed(self._parent_stack):
            if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Inside a function; bare __doc__ resolves to module.
                break
            if isinstance(parent, ast.ClassDef):
                # In class body, not in a nested function: class doc.
                return parent
        # Fall through to module scope.
        for parent in self._parent_stack:
            if isinstance(parent, ast.Module):
                return parent
        return None


# ===========================================================================
# The analyzer
# ===========================================================================


class CodeDensityAnalyzer(Analyzer):
    """
    Detects structural and statistical obfuscation patterns.

    Operates on both Python source files (via analyze_python) and .pth
    exec lines (via analyze_pth_exec_line). The .pth path applies a
    subset of checks (token density, semicolons, entropy, base64
    alphabet, and Unicode anomalies) since .pth exec lines are single
    statements and AST-depth or docstring checks are not meaningful.
    """

    safe_for_library_scan = True

    @property
    def name(self) -> str:
        return "code_density"

    def analyze_python(self, parsed: ParsedPySource) -> Iterable[Signal]:
        """
        Full analysis pass on a parsed Python source file.

        Runs three independent analysis layers:
          1. Token-level (DENS001, DENS002): tokenizes source_text
          2. Unicode / raw-text (DENS030, DENS031): scans source_text
          3. AST walk (DENS010, DENS011, DENS020, DENS021, DENS040,
                       DENS041, DENS042, DENS050, DENS051)
        """
        signals: list[Signal] = []

        # Layer 1: token-level analysis. Runs even on files that failed
        # to parse as valid Python; their source_text is still available.
        if parsed.source_text:
            signals.extend(
                _analyze_token_density(
                    parsed.source_text,
                    self.name,
                    Scope.MODULE,
                )
            )
            # Layer 2: Unicode / raw-text
            signals.extend(
                _analyze_unicode_anomalies(
                    parsed.source_text,
                    self.name,
                )
            )

        if not parsed.is_parseable:
            return signals

        # Layer 3: AST walk
        visitor = _Visitor(self.name)
        visitor.visit(parsed.ast_tree)
        signals.extend(visitor.signals)

        # DENS040: AST depth (computed post-walk from the tree directly)
        if parsed.line_count >= _MIN_LINE_COUNT_FOR_DEPTH:
            depth = _max_ast_depth(parsed.ast_tree)
            ratio = depth / parsed.line_count
            confidence: Confidence | None
            if ratio >= _THRESHOLD_DEPTH_RATIO_HIGH:
                confidence = Confidence.HIGH
            elif ratio >= _THRESHOLD_DEPTH_RATIO_MEDIUM:
                confidence = Confidence.MEDIUM
            else:
                confidence = None
            if confidence is not None:
                signals.append(
                    Signal(
                        analyzer=self.name,
                        signal_id="DENS040",
                        confidence=confidence,
                        scope=Scope.MODULE,
                        location=SourceLocation(line=1, column=0),
                        description=(
                            f"AST depth {depth} is {ratio:.1f}x the line count "
                            f"({parsed.line_count}), disproportionate nesting "
                            f"consistent with expression compression or "
                            f"generated code"
                        ),
                        context={
                            "ast_depth": depth,
                            "line_count": parsed.line_count,
                            "ratio": round(ratio, 4),
                        },
                    )
                )

        return signals

    def analyze_pth_exec_line(
        self,
        line_text: str,
        location: SourceLocation,
    ) -> Iterable[Signal]:
        """
        Analyze a single executable line from a .pth file.

        Applies the token-density, Unicode, entropy, and base64-alphabet
        checks. AST-depth, docstring, and identifier checks are not
        meaningful on a single-line statement and are skipped.
        """
        signals: list[Signal] = []

        # Token density and semicolons (DENS001, DENS002).
        signals.extend(_analyze_token_density(line_text, self.name, Scope.MODULE))

        # Unicode anomalies (DENS030, DENS031).
        signals.extend(_analyze_unicode_anomalies(line_text, self.name))

        # String entropy and base64 alphabet (DENS010, DENS011).
        # Parse the line as a mini module to get an AST.
        try:
            tree = ast.parse(line_text, mode="exec")
        except SyntaxError:
            return signals

        visitor = _Visitor(self.name)
        # Only run the string-literal checks; skip identifier and structural
        # checks that require a full module context.
        visitor.visit(tree)
        # Filter to only DENS010 and DENS011 signals from the visitor.
        for sig in visitor.signals:
            if sig.signal_id in ("DENS010", "DENS011"):
                # Re-stamp the location to use the .pth file's actual line.
                signals.append(
                    Signal(
                        analyzer=sig.analyzer,
                        signal_id=sig.signal_id,
                        confidence=sig.confidence,
                        scope=sig.scope,
                        location=location,
                        description=sig.description,
                        context=sig.context,
                    )
                )

        return signals
