"""
.pth file parser for pydepgate.

Parses Python path-configuration (.pth) files as specified by
CPython's site.addpackage() behavior in Lib/site.py. This parser
is intentionally *non-executing*: it classifies lines but never
compiles, evaluates, or imports their contents.

The .pth format:
  - One entry per line.
  - Blank lines are ignored.
  - Lines starting with '#' are comments and ignored.
  - Lines starting with 'import ' or 'import\\t' are passed to exec()
    by site.addpackage() at interpreter startup. These are the
    security-relevant lines.
  - All other non-blank, non-comment lines are treated as paths
    and appended to sys.path.

Reference: https://docs.python.org/3/library/site.html
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class LineKind(Enum):
    BLANK = "blank"
    COMMENT = "comment"
    PATH = "path"
    EXEC = "exec"


@dataclass(frozen=True)
class PthLine:
    """A single parsed line from a .pth file.

    Attributes:
        kind: How site.py would interpret this line.
        raw: The decoded line text, exactly as it appeared in the file
            (minus the line terminator). Leading/trailing whitespace
            is preserved because site.py preserves it.
        line_number: 1-indexed line number, matching how Python
            reports positions in tracebacks.
        content: For PATH lines, the path itself (same as raw).
            For EXEC lines, the statement to be executed (same as raw).
            For BLANK/COMMENT lines, an empty string.
    """
    kind: LineKind
    raw: str
    line_number: int
    content: str


@dataclass(frozen=True)
class ParsedPth:
    """Full parse result for a .pth file.

    Attributes:
        source_path: Filesystem path or identifier the content came from.
        size_bytes: Original byte length, before decoding. Useful for
            size-based heuristics (real .pth files are almost always
            under a few hundred bytes; the LiteLLM malware was 34KB).
        lines: All parsed lines, in order.
        encoding_used: "utf-8" on success, "latin-1 (fallback)" if
            UTF-8 decoding failed.
        decode_notes: Diagnostic strings about encoding issues.
    """
    source_path: str
    size_bytes: int
    lines: tuple[PthLine, ...]
    encoding_used: str
    decode_notes: tuple[str, ...]

    @property
    def exec_lines(self) -> tuple[PthLine, ...]:
        """All lines site.py would pass to exec()."""
        return tuple(l for l in self.lines if l.kind is LineKind.EXEC)

    @property
    def path_lines(self) -> tuple[PthLine, ...]:
        """All lines site.py would append to sys.path."""
        return tuple(l for l in self.lines if l.kind is LineKind.PATH)


# These prefixes exactly match the check in CPython's site.addpackage().
# Do not "improve" this to handle 'import\t\t' or leading whitespace
# site.py doesn't, so neither should we. Diverging here means either
# flagging things Python won't execute, or missing things it will.
_EXEC_PREFIXES = ("import ", "import\t")


def _classify_line(text: str) -> LineKind:
    """Classify a single line using the same rules as site.addpackage()."""
    if not text:
        return LineKind.BLANK
    # site.py uses .strip() when checking for blank/comment lines specifically.
    # It does NOT strip before the 'import ' prefix check.
    stripped = text.strip()
    if not stripped:
        return LineKind.BLANK
    if stripped.startswith("#"):
        return LineKind.COMMENT
    if text.startswith(_EXEC_PREFIXES):
        return LineKind.EXEC
    return LineKind.PATH


def _decode(content: bytes) -> tuple[str, str, tuple[str, ...]]:
    """Decode file bytes to str with a deterministic fallback.

    Returns (text, encoding_used, decode_notes).

    We try UTF-8 first because it's by far the most common encoding
    for .pth files in modern Python installs. On failure, we fall
    back to latin-1, which never errors (every byte is a valid
    latin-1 codepoint). This matches the behavior of "be liberal
    in what you accept" we'd rather parse a weirdly-encoded file
    and let rules flag suspicious content than refuse to parse it
    at all and let the attack go unexamined.
    """
    try:
        return content.decode("utf-8"), "utf-8", ()
    except UnicodeDecodeError as exc:
        text = content.decode("latin-1")
        note = (
            f"utf-8 decode failed at byte {exc.start}: {exc.reason}; "
            f"fell back to latin-1"
        )
        return text, "latin-1 (fallback)", (note,)


def parse_pth(content: bytes, source_path: str = "<bytes>") -> ParsedPth:
    """Parse .pth file bytes into a structured representation.

    This function never executes, compiles, or imports any content
    from the input. It is safe to call on completely untrusted bytes.

    Args:
        content: Raw file bytes.
        source_path: Human-readable identifier for the source, used
            in the returned ParsedPth. Does not need to exist on disk.

    Returns:
        A ParsedPth with classified lines and metadata.
    """
    text, encoding, notes = _decode(content)

    # splitlines() handles \n, \r\n, and bare \r, and does not include
    # the line terminators in the output. It also handles some exotic
    # line separators (U+2028, U+2029) that keepends=True would preserve.
    # For .pth parsing, we want to match what Python's file iteration
    # would produce when site.py reads the file, which is universal
    # newline handling.
    raw_lines = text.splitlines()

    parsed: list[PthLine] = []
    for idx, raw in enumerate(raw_lines, start=1):
        kind = _classify_line(raw)
        if kind in (LineKind.BLANK, LineKind.COMMENT):
            line_content = ""
        else:
            # For PATH and EXEC, preserve the raw text as content.
            # Rules will decide whether and how to strip/normalize.
            line_content = raw
        parsed.append(PthLine(
            kind=kind,
            raw=raw,
            line_number=idx,
            content=line_content,
        ))

    return ParsedPth(
        source_path=source_path,
        size_bytes=len(content),
        lines=tuple(parsed),
        encoding_used=encoding,
        decode_notes=notes,
    )