"""
Safe parser for arbitrary Python source code.

Produces a structured representation (AST + comments + tokens + metadata)
suitable for downstream analysis. This parser never executes, compiles,
or imports any content from the input. it only parses the source into
inert data structures.

Used by pydepgate's setup.py parser, __init__.py analyzer, and anywhere
else Python source needs to be inspected without running it.
"""

from __future__ import annotations

import ast
import io
import tokenize
from dataclasses import dataclass
from enum import Enum


class ParseStatus(Enum):
    """Outcome of attempting to parse Python source."""
    OK = "ok"
    SYNTAX_ERROR = "syntax_error"
    TOKENIZE_ERROR = "tokenize_error"
    RECURSION_ERROR = "recursion_error"
    DECODE_ERROR = "decode_error"


@dataclass(frozen=True)
class SourceLocation:
    """A position within a source file.

    Line numbers are 1-indexed to match Python's tracebacks.
    Column numbers are 0-indexed to match the ast module's convention.
    """
    line: int
    column: int


@dataclass(frozen=True)
class Comment:
    """A single comment token extracted from the source.

    Attributes:
        text: The comment text including the leading '#'.
        location: Position of the '#' character.
        is_shebang: True if this is the first-line shebang (#!...).
        is_encoding_declaration: True if this is a PEP 263 encoding
            declaration in the first two lines.
        encoding_name: If is_encoding_declaration, the declared encoding
            (e.g. "utf-8"). None otherwise.
    """
    text: str
    location: SourceLocation
    is_shebang: bool
    is_encoding_declaration: bool
    encoding_name: str | None


@dataclass(frozen=True)
class ParsedPySource:
    """Parse result for Python source code.

    When status is OK, ast_tree and comments are populated. Otherwise
    they may be empty. check status before relying on them.

    Attributes:
        source_path: Path or identifier the source came from.
        size_bytes: Original byte length.
        status: Parse outcome.
        diagnostic: Human-readable description of any parse failure.
        ast_tree: The parsed AST, or None on failure.
        comments: All comment tokens found.
        source_text: The decoded source text.
        encoding_used: Encoding used to decode source_text.
        line_count: Number of lines in the source.
    """
    source_path: str
    size_bytes: int
    status: ParseStatus
    diagnostic: str
    ast_tree: ast.Module | None
    comments: tuple[Comment, ...]
    source_text: str
    encoding_used: str
    line_count: int

    @property
    def is_parseable(self) -> bool:
        """True if the source parsed successfully into an AST."""
        return self.status is ParseStatus.OK

    @property
    def shebang(self) -> Comment | None:
        """The shebang comment if present, None otherwise."""
        for c in self.comments:
            if c.is_shebang:
                return c
        return None

    @property
    def encoding_declaration(self) -> Comment | None:
        """The PEP 263 encoding declaration if present, None otherwise."""
        for c in self.comments:
            if c.is_encoding_declaration:
                return c
        return None


# Encoding declarations are matched by tokenize.detect_encoding, but we
# also want to flag the comment itself. PEP 263 specifies the pattern
# loosely as "coding[:=]\s*([-\w.]+)" anywhere in the first two lines.
# We use a simple substring check plus a more careful extraction.
_ENCODING_MARKERS = ("coding:", "coding=")

# Encodings we consider mundane. Anything else in an encoding declaration
# is worth surfacing to analyzers.
_COMMON_ENCODINGS = frozenset({
    "utf-8", "utf8",
    "ascii", "us-ascii",
    "latin-1", "latin1", "iso-8859-1",
    "cp1252", "windows-1252",
})


def _extract_encoding_name(comment_text: str) -> str | None:
    """Extract the declared encoding from a PEP 263 encoding declaration.

    Returns None if the text doesn't look like an encoding declaration.
    Matches the pattern used by CPython's tokenize.detect_encoding:
    the substring 'coding' followed by ':' or '=', then the encoding name.
    """
    for marker in _ENCODING_MARKERS:
        idx = comment_text.find(marker)
        if idx < 0:
            continue
        rest = comment_text[idx + len(marker):].lstrip()
        # Encoding name is alphanumerics, hyphens, underscores, dots.
        name = []
        for ch in rest:
            if ch.isalnum() or ch in "-_.":
                name.append(ch)
            else:
                break
        if name:
            return "".join(name).lower()
    return None


def _classify_comment(
    text: str,
    location: SourceLocation,
) -> Comment:
    """Classify a single comment and extract any special metadata."""
    is_shebang = location.line == 1 and text.startswith("#!")
    encoding_name = None
    is_encoding_declaration = False
    if location.line <= 2:
        # Only the first two lines can contain encoding declarations per PEP 263.
        encoding_name = _extract_encoding_name(text)
        is_encoding_declaration = encoding_name is not None
    return Comment(
        text=text,
        location=location,
        is_shebang=is_shebang,
        is_encoding_declaration=is_encoding_declaration,
        encoding_name=encoding_name,
    )


def _fallback_comment_scan(source_bytes: bytes) -> tuple[Comment, ...]:
    """Extract comments from the first two lines without using tokenize.

    Used when tokenize fails (typically due to an invalid or non-text
    encoding declaration). This is lossy. we only get the first two
    lines, which is exactly where shebangs and encoding declarations
    live, so it's the right tradeoff for the failure case.
    """
    # Decode as latin-1 so any byte sequence becomes a string without error.
    text = source_bytes.decode("latin-1")
    comments: list[Comment] = []
    for line_num, line in enumerate(text.splitlines()[:2], start=1):
        hash_idx = line.find("#")
        if hash_idx < 0:
            continue
        # Find the actual comment (not a # inside a string literal).
        # Since we're in the first two lines and can't parse, we accept
        # any # as a comment marker. False positives here are acceptable.
        comment_text = line[hash_idx:]
        location = SourceLocation(line=line_num, column=hash_idx)
        comments.append(_classify_comment(comment_text, location))
    return tuple(comments)


def _extract_comments(source_bytes: bytes) -> tuple[tuple[Comment, ...], str]:
    """Tokenize source and extract all comment tokens.

    Returns (comments, encoding_used). The encoding is reported by
    tokenize.detect_encoding based on BOM, PEP 263 declaration, or default.

    On tokenization failure, returns whatever comments were successfully
    extracted before the failure, and the encoding if it was detected.
    """
    # tokenize.tokenize wants a callable returning bytes (the readline
    # interface). We wrap our bytes in a BytesIO.
    buf = io.BytesIO(source_bytes)

    # Detect encoding first. this also consumes the BOM if present.
    # We need to rewind and re-tokenize because detect_encoding's position
    # is not at a clean start for tokenize().
    try:
        encoding, _ = tokenize.detect_encoding(buf.readline)
    except (SyntaxError, UnicodeDecodeError):
        encoding = "utf-8"
    buf.seek(0)

    comments: list[Comment] = []
    try:
        for tok in tokenize.tokenize(buf.readline):
            if tok.type == tokenize.COMMENT:
                start_line, start_col = tok.start
                location = SourceLocation(line=start_line, column=start_col)
                comments.append(_classify_comment(tok.string, location))
    except tokenize.TokenError:
        pass
    except (SyntaxError, IndentationError):
        pass
    except LookupError:
        comments = list(_fallback_comment_scan(source_bytes))

    return tuple(comments), encoding


def parse_python_source(
    source_bytes: bytes,
    source_path: str = "<bytes>",
) -> ParsedPySource:
    """Parse Python source bytes into a structured representation.

    This function never executes, compiles, imports, or otherwise runs
    content from the input bytes. It is safe to call on arbitrary,
    potentially malicious input.

    Args:
        source_bytes: The raw file bytes to parse.
        source_path: Human-readable identifier for diagnostics. Does not
            need to exist on disk; defaults to "<bytes>".

    Returns:
        A ParsedPySource describing what was found. Check the status
        field before using ast_tree or comments. a failed parse may
        have empty or partial data.
    """
    size_bytes = len(source_bytes)

    # Extract comments via tokenize. This also gives us the encoding.
    comments, encoding_used = _extract_comments(source_bytes)

    # Decode source for downstream analyzers that want the text.
    try:
        source_text = source_bytes.decode(encoding_used)
    except (UnicodeDecodeError, LookupError) as exc:
        # If the declared encoding is bogus or the bytes don't match it,
        # fall back to latin-1 (which always succeeds) and record the issue.
        source_text = source_bytes.decode("latin-1")
        return ParsedPySource(
            source_path=source_path,
            size_bytes=size_bytes,
            status=ParseStatus.DECODE_ERROR,
            diagnostic=f"failed to decode as {encoding_used}: {exc}; fell back to latin-1",
            ast_tree=None,
            comments=comments,
            source_text=source_text,
            encoding_used="latin-1 (fallback)",
            line_count=source_text.count("\n") + (0 if source_text.endswith("\n") else 1 if source_text else 0),
        )

    line_count = source_text.count("\n") + (0 if source_text.endswith("\n") else 1 if source_text else 0)

    # Attempt to parse the AST.
    try:
        tree = ast.parse(source_bytes, filename=source_path)
    except SyntaxError as exc:
        return ParsedPySource(
            source_path=source_path,
            size_bytes=size_bytes,
            status=ParseStatus.SYNTAX_ERROR,
            diagnostic=f"line {exc.lineno}: {exc.msg}",
            ast_tree=None,
            comments=comments,
            source_text=source_text,
            encoding_used=encoding_used,
            line_count=line_count,
        )
    except ValueError as exc:
        # ast.parse raises ValueError on source containing null bytes.
        return ParsedPySource(
            source_path=source_path,
            size_bytes=size_bytes,
            status=ParseStatus.SYNTAX_ERROR,
            diagnostic=f"malformed source: {exc}",
            ast_tree=None,
            comments=comments,
            source_text=source_text,
            encoding_used=encoding_used,
            line_count=line_count,
        )
    except RecursionError:
        return ParsedPySource(
            source_path=source_path,
            size_bytes=size_bytes,
            status=ParseStatus.RECURSION_ERROR,
            diagnostic="source exceeds recursion limit during parsing",
            ast_tree=None,
            comments=comments,
            source_text=source_text,
            encoding_used=encoding_used,
            line_count=line_count,
        )

    return ParsedPySource(
        source_path=source_path,
        size_bytes=size_bytes,
        status=ParseStatus.OK,
        diagnostic="",
        ast_tree=tree,
        comments=comments,
        source_text=source_text,
        encoding_used=encoding_used,
        line_count=line_count,
    )