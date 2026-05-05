"""pydepgate.analyzers.dynamic_execution

Detects dynamic code execution patterns.

The dynamic_execution analyzer flags uses of Python's runtime code
execution primitives: exec, eval, compile, __import__, and
importlib.import_module. It also catches common evasion patterns
where these primitives are accessed indirectly through builtins,
globals, locals, or vars.

The analyzer operates on three layers:

  1. Direct calls to known exec primitives (DYN001-003).
  2. Dynamic import patterns (DYN004).
  3. Indirect access patterns that reach exec primitives by string
     lookup, regardless of what name the result gets assigned to
     (DYN005).

A separate two-pass detection (DYN006) finds compile-then-exec
constructs by tracking compile() results across the file.

A shape-based pass (DYN007) flags Call(Call(decode...)) patterns
where the outer call could be an aliased exec primitive, catching
evasions like `e = exec; e(base64.b64decode(...))`.

The analyzer does NOT do text-based fallback in v0.1. If a file
fails to parse as Python, no signals are emitted. This is Option A
from the design discussion. Future versions may add text-fallback
signals with a distinct source marker.
"""

from __future__ import annotations

import ast
from typing import Iterable

from pydepgate.analyzers.base import (
    Analyzer, Confidence, Scope, Signal,
)
from pydepgate.analyzers._visitor import _ScopeTracker, get_qualified_name
from pydepgate.parsers.pysource import ParsedPySource, SourceLocation


# Names that execute arbitrary code. The exec_primitive() helper
# matches these against fully-qualified names too (e.g. 'builtins.eval').
_EXEC_NAMES = frozenset({
    "exec", "eval", "compile",
    "builtins.exec", "builtins.eval", "builtins.compile",
})

# Names that perform dynamic imports.
_DYNAMIC_IMPORT_NAMES = frozenset({
    "__import__",
    "builtins.__import__",
    "importlib.import_module",
    "importlib.__import__",
})

# Names whose return value contains exec primitives. When we see
# subscript access into one of these (e.g. globals()['eval']), that
# is a dynamic-execution evasion pattern.
_NAMESPACE_FUNCTIONS = frozenset({
    "globals", "locals", "vars",
    "builtins.globals", "builtins.locals", "builtins.vars",
})

# Names that, when passed to getattr, indicate reaching into builtins.
_BUILTINS_NAMES = frozenset({
    "__builtins__", "builtins",
})

# Names of decode functions, copied from encoding_abuse for the
# DYN007 shape detection. We match on the call shape, not the
# specific decoder. This list is intentionally a superset of what
# encoding_abuse uses because we are looking for any "decoded
# something" pattern feeding into an exec-shaped call.
_DECODE_NAMES = frozenset({
    "base64.b64decode", "base64.b32decode", "base64.b16decode",
    "base64.a85decode", "base64.decodebytes", "base64.urlsafe_b64decode",
    "codecs.decode",
    "binascii.unhexlify", "binascii.a2b_base64", "binascii.a2b_hex",
    "zlib.decompress", "bz2.decompress", "lzma.decompress",
    "gzip.decompress",
    "bytes.fromhex",
})


def _is_literal(node: ast.AST) -> bool:
    """True if a node is a constant value an attacker cannot influence.

    A literal is an ast.Constant whose value is a primitive type
    (str, bytes, int, float, bool, None). Everything else, including
    f-strings, name references, calls, and binary operations, is
    treated as dynamic.
    """
    if not isinstance(node, ast.Constant):
        return False
    return isinstance(node.value, (str, bytes, int, float, bool, type(None)))


def _is_exec_primitive(node: ast.AST) -> str | None:
    """If node is a reference to an exec primitive, return the name.

    Matches both bare names (eval) and qualified names (builtins.eval).
    Returns the qualified name on match, None otherwise.
    """
    name = get_qualified_name(node)
    if name in _EXEC_NAMES:
        return name
    return None


def _is_dynamic_import(node: ast.AST) -> str | None:
    """If node is a reference to a dynamic-import function, return name."""
    name = get_qualified_name(node)
    if name in _DYNAMIC_IMPORT_NAMES:
        return name
    return None


def _is_namespace_function_call(node: ast.AST) -> str | None:
    """If node is a call to globals(), locals(), or vars(), return name."""
    if not isinstance(node, ast.Call):
        return None
    name = get_qualified_name(node.func)
    if name in _NAMESPACE_FUNCTIONS:
        return name
    return None


def _is_decode_call(node: ast.AST) -> str | None:
    """If node is a call to a decode function, return its qualified name."""
    if not isinstance(node, ast.Call):
        return None
    name = get_qualified_name(node.func)
    if name in _DECODE_NAMES:
        return name
    # bytes.fromhex on a literal: bytes.fromhex(...) where the LHS
    # of the attribute is the bytes type itself, not an instance.
    if name and name.endswith(".fromhex"):
        return name
    return None


def _get_compile_mode(call: ast.Call) -> str | None:
    """Extract the mode string from a compile() call.

    compile(source, filename, mode) is the standard signature. Mode
    may be passed positionally or as a keyword. Returns the mode
    string if it is a literal, None if it cannot be determined.
    """
    if not isinstance(call, ast.Call):
        return None
    # Positional: third argument.
    if len(call.args) >= 3 and _is_literal(call.args[2]):
        value = call.args[2].value  # type: ignore[attr-defined]
        if isinstance(value, str):
            return value
    # Keyword: mode=...
    for kw in call.keywords:
        if kw.arg == "mode" and _is_literal(kw.value):
            value = kw.value.value  # type: ignore[attr-defined]
            if isinstance(value, str):
                return value
    return None


class DynamicExecutionAnalyzer(Analyzer):
    """Detects dynamic code execution patterns."""

    @property
    def name(self) -> str:
        return "dynamic_execution"

    def analyze_python(self, parsed: ParsedPySource) -> Iterable[Signal]:
        if not parsed.is_parseable:
            return ()
        visitor = _Visitor()
        visitor.visit(parsed.ast_tree)
        # After the AST walk, run the cross-reference pass for compile-then-exec.
        visitor.finalize()
        return visitor.signals


class _Visitor(_ScopeTracker):
    """AST visitor for dynamic_execution detection.

    Walks the tree and emits signals for direct exec/eval/compile
    calls, dynamic imports, and indirect-access patterns. Tracks
    compile() results in a side table so finalize() can detect
    compile-then-exec constructs.
    """

    def __init__(self) -> None:
        super().__init__()
        self.signals: list[Signal] = []
        # Maps variable name -> SourceLocation of the compile() that
        # produced it. Used by the compile-then-exec detection.
        self._compile_results: dict[str, SourceLocation] = {}
        # Tracks exec/eval calls keyed by the name of their argument.
        # Used together with _compile_results to find DYN006 patterns.
        self._exec_calls_by_arg: list[tuple[str, SourceLocation]] = []

    # ---- Direct-call detection ----

    def visit_Call(self, node: ast.Call) -> None:
        self._check_exec_primitive(node)
        self._check_dynamic_import(node)
        self._check_getattr_into_builtins(node)
        self._check_aliased_exec_shape(node)
        self._track_compile_result(node)
        self._track_exec_with_named_arg(node)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        self._check_namespace_subscript(node)
        self.generic_visit(node)

    # ---- Detection methods ----

    def _check_exec_primitive(self, node: ast.Call) -> None:
        """DYN001/DYN002/DYN003: direct call to exec, eval, or compile."""
        name = _is_exec_primitive(node.func)
        if name is None:
            return
        if not node.args:
            return
        first_arg = node.args[0]
        is_literal = _is_literal(first_arg)
        location = SourceLocation(line=node.lineno, column=node.col_offset)

        # Special case for compile: even a literal-source compile() with
        # mode='exec' is a precursor to dynamic execution. Flag separately.
        if name.endswith("compile"):
            mode = _get_compile_mode(node)
            if mode == "exec":
                self.signals.append(self._make_signal(
                    signal_id="DYN006_PRECURSOR",
                    confidence=Confidence.MEDIUM,
                    location=location,
                    description=(
                        f"compile() with mode='exec' creates a code object "
                        f"that can be executed dynamically"
                    ),
                    context={"primitive": name, "mode": mode},
                ))
                # Fall through; we still want DYN001/002/003 if applicable.

        if self.current_scope is Scope.MODULE:
            if is_literal:
                self.signals.append(self._make_signal(
                    signal_id="DYN001",
                    confidence=Confidence.MEDIUM,
                    location=location,
                    description=(
                        f"{name}() at module scope with literal argument; "
                        f"unusual pattern, often vestigial debugging or test code"
                    ),
                    context={"primitive": name, "argument_kind": "literal"},
                ))
            else:
                self.signals.append(self._make_signal(
                    signal_id="DYN002",
                    confidence=Confidence.HIGH,
                    location=location,
                    description=(
                        f"{name}() at module scope with non-literal argument; "
                        f"executes code computed at runtime"
                    ),
                    context={"primitive": name, "argument_kind": "dynamic"},
                ))
        elif self.current_scope in (Scope.FUNCTION, Scope.NESTED_FUNCTION, Scope.CLASS_BODY):
            if not is_literal:
                self.signals.append(self._make_signal(
                    signal_id="DYN003",
                    confidence=Confidence.MEDIUM,
                    location=location,
                    description=(
                        f"{name}() inside function or class body with "
                        f"non-literal argument"
                    ),
                    context={"primitive": name, "argument_kind": "dynamic"},
                ))

    def _check_dynamic_import(self, node: ast.Call) -> None:
        """DYN004: __import__ or importlib.import_module with non-literal name."""
        name = _is_dynamic_import(node.func)
        if name is None:
            return
        if not node.args:
            return
        first_arg = node.args[0]
        if _is_literal(first_arg):
            return
        self.signals.append(self._make_signal(
            signal_id="DYN004",
            confidence=Confidence.HIGH,
            location=SourceLocation(line=node.lineno, column=node.col_offset),
            description=(
                f"{name}() with non-literal argument; module name "
                f"computed at runtime"
            ),
            context={"primitive": name},
        ))

    def _check_getattr_into_builtins(self, node: ast.Call) -> None:
        """DYN005 (getattr form): getattr(__builtins__, 'eval') and friends.

        Matches Call(func=Name('getattr'), args=[<builtins>, <constant>])
        where <constant> is the string name of an exec primitive.
        """
        func_name = get_qualified_name(node.func)
        if func_name != "getattr":
            return
        if len(node.args) < 2:
            return
        target = node.args[0]
        attr = node.args[1]
        target_name = get_qualified_name(target)
        if target_name not in _BUILTINS_NAMES:
            return
        if not _is_literal(attr):
            return
        attr_value = attr.value  # type: ignore[attr-defined]
        if not isinstance(attr_value, str):
            return
        # Is the looked-up attribute an exec primitive?
        if attr_value in {"exec", "eval", "compile", "__import__"}:
            self.signals.append(self._make_signal(
                signal_id="DYN005",
                confidence=Confidence.DEFINITE,
                location=SourceLocation(line=node.lineno, column=node.col_offset),
                description=(
                    f"getattr({target_name}, {attr_value!r}) reaches into "
                    f"builtins to access an exec primitive by string name"
                ),
                context={
                    "form": "getattr",
                    "namespace": target_name,
                    "primitive": attr_value,
                },
            ))

    def _check_namespace_subscript(self, node: ast.Subscript) -> None:
        """DYN005 (subscript form): globals()['eval'] and friends.

        Matches Subscript(value=Call(globals/locals/vars), slice=Constant).
        """
        if not isinstance(node.value, ast.Call):
            return
        ns_name = _is_namespace_function_call(node.value)
        if ns_name is None:
            return
        # Extract the slice, handling both 3.9+ (slice is direct) and
        # older (slice wrapped in ast.Index) forms. ast.Index was
        # deprecated in 3.9; we no longer need to handle it on 3.11+.
        slice_node = node.slice
        if not _is_literal(slice_node):
            return
        slice_value = slice_node.value  # type: ignore[attr-defined]
        if not isinstance(slice_value, str):
            return
        if slice_value in {"exec", "eval", "compile", "__import__"}:
            self.signals.append(self._make_signal(
                signal_id="DYN005",
                confidence=Confidence.DEFINITE,
                location=SourceLocation(line=node.lineno, column=node.col_offset),
                description=(
                    f"{ns_name}()[{slice_value!r}] looks up an exec "
                    f"primitive by string name"
                ),
                context={
                    "form": "subscript",
                    "namespace": ns_name,
                    "primitive": slice_value,
                },
            ))

    def _check_aliased_exec_shape(self, node: ast.Call) -> None:
        """DYN007: Call whose first argument is a decode call.

        This catches `e(base64.b64decode(...))` where `e` may be an
        alias for exec or eval. We cannot resolve the alias, but the
        shape is suspicious enough on its own. Confidence is HIGH
        rather than DEFINITE because legitimate code occasionally
        does this (e.g., a custom logging function that takes
        decoded payload data).
        """
        if not node.args:
            return
        first_arg = node.args[0]
        if not isinstance(first_arg, ast.Call):
            return
        decode_name = _is_decode_call(first_arg)
        if decode_name is None:
            return
        # Skip if the outer call is itself a known exec primitive.
        # Those cases are caught by DYN001-003 with full context.
        if _is_exec_primitive(node.func) is not None:
            return
        # Skip if the outer call is something obviously benign like
        # a print or len. The aliased-exec attack uses a name we can't
        # resolve, so the outer call's name resolution will return
        # None or a single bare identifier.
        outer_name = get_qualified_name(node.func)
        if outer_name in {"print", "len", "str", "repr", "type", "id"}:
            return
        self.signals.append(self._make_signal(
            signal_id="DYN007",
            confidence=Confidence.HIGH,
            location=SourceLocation(line=node.lineno, column=node.col_offset),
            description=(
                f"call shape: outer-call(decode-call(...)); "
                f"outer call may be an aliased exec primitive"
            ),
            context={
                "outer_call": outer_name or "<unresolved>",
                "decode_function": decode_name,
            },
        ))

    # ---- Side-table tracking for DYN006 (compile-then-exec) ----

    def _track_compile_result(self, node: ast.Call) -> None:
        """If this is `x = compile(...)` style, remember x's location."""
        # Walk the parent? We don't have parent links. Instead, the
        # detection is: when we see `name = compile(...)`, record name.
        # That requires Assign tracking, handled in visit_Assign below.
        pass

    def _track_exec_with_named_arg(self, node: ast.Call) -> None:
        """If this is `exec(some_name)` or `eval(some_name)`, record the name."""
        primitive = _is_exec_primitive(node.func)
        if primitive is None:
            return
        if not node.args:
            return
        first = node.args[0]
        if isinstance(first, ast.Name):
            self._exec_calls_by_arg.append((
                first.id,
                SourceLocation(line=node.lineno, column=node.col_offset),
            ))

    def visit_Assign(self, node: ast.Assign) -> None:
        # Detect `x = compile(...)` pattern. Record the variable name
        # that was assigned the compile result.
        if isinstance(node.value, ast.Call):
            primitive = _is_exec_primitive(node.value.func)
            if primitive is not None and primitive.endswith("compile"):
                # Each target could be Name, Tuple, etc. We only handle
                # the simple Name case for v0.1.
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self._compile_results[target.id] = SourceLocation(
                            line=node.lineno,
                            column=node.col_offset,
                        )
        self.generic_visit(node)

    def finalize(self) -> None:
        """Run cross-reference passes after the main AST walk.

        Currently used for DYN006 (compile-then-exec): match each
        exec/eval call whose argument is a Name against compile()
        assignments to that name.
        """
        for arg_name, exec_location in self._exec_calls_by_arg:
            if arg_name in self._compile_results:
                compile_location = self._compile_results[arg_name]
                self.signals.append(self._make_signal(
                    signal_id="DYN006",
                    confidence=Confidence.DEFINITE,
                    location=exec_location,
                    description=(
                        f"two-step dynamic execution: variable {arg_name!r} "
                        f"was assigned a compile() result at line "
                        f"{compile_location.line}, then executed here"
                    ),
                    context={
                        "variable": arg_name,
                        "compile_line": compile_location.line,
                    },
                ))

    # ---- Signal construction helper ----

    def _make_signal(
        self,
        signal_id: str,
        confidence: Confidence,
        location: SourceLocation,
        description: str,
        context: dict,
    ) -> Signal:
        return Signal(
            analyzer="dynamic_execution",
            signal_id=signal_id,
            confidence=confidence,
            scope=self.current_scope,
            location=location,
            description=description,
            context=context,
        )