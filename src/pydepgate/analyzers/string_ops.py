"""
Detects string obfuscation patterns that resolve to sensitive names.

This analyzer uses the safe partial evaluator (analyzers._resolver)
to determine what string expressions would produce at runtime,
without ever executing user code. It then checks whether the
resolved values match names of exec primitives, dangerous stdlib
functions, or dangerous module names.

The "harder they hide it, the stronger the signal" model is realized
by tracking the resolver's operations_used field. An expression that
required many operations to assemble a short identifier-shaped string
is more suspicious than one that needed few. Even when full resolution
fails, the operations themselves carry signal.

Four signal types:

  STR001: Standalone obfuscated expression resolves to a sensitive name.
          The resolved value matches a sensitive name but we did not
          observe it being used in a dangerous call. MEDIUM confidence.

  STR002: Obfuscated expression resolves to a sensitive name AND is
          passed directly to a dangerous function. HIGH or DEFINITE.

  STR003: Variable assigned an obfuscated sensitive name is later used
          in a dangerous function call. HIGH or DEFINITE.

  STR004: Heavily obfuscated expression that resolution could not
          complete. Threshold: 4+ obfuscation operations. MEDIUM,
          unless combined with a dangerous use context (then HIGH).
"""

from __future__ import annotations

import ast
from typing import Iterable

from pydepgate.analyzers.base import (
    Analyzer, Confidence, Scope, Signal,
)
from pydepgate.analyzers._visitor import _ScopeTracker, get_qualified_name
from pydepgate.analyzers._resolver import (
    FailureReason,
    ResolutionResult,
    resolve,
)
from pydepgate.parsers.pysource import ParsedPySource, SourceLocation


# ---- Sensitive name catalogues ----

# Category A: exec primitives. Hitting these via obfuscation is almost
# always intentional evasion.
_SENSITIVE_EXEC = frozenset({
    "exec", "eval", "compile", "__import__",
})

# Category B: dangerous stdlib functions. Reaching one of these via
# obfuscation suggests intent to spawn processes or run shell commands.
_SENSITIVE_STDLIB_FUNCS = frozenset({
    "system", "popen", "spawn", "fork", "execv", "execve",
    "Popen", "call", "check_output", "check_call", "run",
    "getoutput", "getstatusoutput",
    "dlopen", "LoadLibrary",
})

# Category C: dangerous module names. An obfuscated string that
# resolves to one of these is suspicious because it suggests
# constructing a module name at runtime to import dynamically.
_SENSITIVE_MODULES = frozenset({
    "os", "subprocess", "sys", "ctypes",
    "socket", "urllib", "urllib2", "urllib3",
    "requests", "httpx",
    "pickle", "marshal", "shelve",
    "pty", "telnetlib",
})

# All sensitive names, used for substring matching against partial
# resolutions. Each name's category is recorded separately for
# downstream rule logic.
_ALL_SENSITIVE = (
    _SENSITIVE_EXEC | _SENSITIVE_STDLIB_FUNCS | _SENSITIVE_MODULES
)


def _categorize(name: str) -> str | None:
    """Return the category of a sensitive name, or None if not sensitive."""
    if name in _SENSITIVE_EXEC:
        return "exec_primitive"
    if name in _SENSITIVE_STDLIB_FUNCS:
        return "stdlib_function"
    if name in _SENSITIVE_MODULES:
        return "module_name"
    return None


# ---- Obfuscation operation set ----
# Operations that, when present in operations_used, indicate the
# resolver had to do real work to figure out what the value is.
# A simple Constant uses zero of these; a chr-concat-decode uses many.
_OBFUSCATION_OPS = frozenset({
    "chr", "ord",
    "bytes_from_list", "bytes_fromhex", "bytes_decode",
    "string_concat", "bytes_concat",
    "string_mult", "str_join", "str_replace",
    "subscript_slice", "subscript_index",
})


def _obfuscation_score(result: ResolutionResult) -> int:
    """Count how many obfuscation operations the resolver used.

    Variable lookups, fstring construction, and constant references
    are not counted because they do not, by themselves, indicate
    obfuscation. Only operations that actively transform values are
    counted.
    """
    return sum(
        1 for op in result.operations_used if op in _OBFUSCATION_OPS
    )


# ---- Dangerous function detection ----
# These are the call shapes where a resolved sensitive-name argument
# becomes a STR002 signal (DEFINITE confidence). The list is
# deliberately tighter than dynamic_execution's matching because we
# care specifically about positions where a string argument names
# the target of an action.

_DANGEROUS_FUNCTIONS = frozenset({
    "getattr",
    "hasattr",
    "setattr",
    "__import__",
    "importlib.import_module",
    "importlib.__import__",
})


def _is_dangerous_function_call(node: ast.Call) -> str | None:
    """If node is a call to a dangerous function, return its name."""
    name = get_qualified_name(node.func)
    if name in _DANGEROUS_FUNCTIONS:
        return name
    return None


def _is_dangerous_subscript(node: ast.Subscript) -> str | None:
    """If node is a subscript on globals/locals/vars/__builtins__,
    return the namespace name.
    """
    if not isinstance(node.value, ast.Call):
        # Could be Subscript on Name (__builtins__['eval'])
        if isinstance(node.value, ast.Name) and node.value.id in {
            "__builtins__", "builtins",
        }:
            return node.value.id
        return None
    func = node.value.func
    name = get_qualified_name(func)
    if name in {"globals", "locals", "vars"}:
        return name
    return None


# ---- The analyzer ----

class StringOpsAnalyzer(Analyzer):
    """Detects string-obfuscation patterns that resolve to sensitive names."""

    @property
    def name(self) -> str:
        return "string_ops"

    def analyze_python(self, parsed: ParsedPySource) -> Iterable[Signal]:
        if not parsed.is_parseable:
            return ()
        visitor = _Visitor()
        visitor.visit(parsed.ast_tree)
        visitor.finalize()
        return visitor.signals


class _Visitor(_ScopeTracker):
    """AST visitor for string_ops detection."""

    def __init__(self) -> None:
        super().__init__()
        self.signals: list[Signal] = []
        # Maps variable name -> (resolved value, location of assignment).
        # Used by STR003 cross-reference detection.
        self._resolved_assignments: dict[str, tuple[str, SourceLocation]] = {}
        # Tracks calls to dangerous functions where the relevant
        # argument was a Name. Used by STR003: after the walk, check
        # if any of those names had been assigned an obfuscated
        # sensitive value.
        self._dangerous_calls_by_name: list[
            tuple[str, str, SourceLocation]
        ] = []
        # Tracks every variable assignment so we can detect reassignment
        # (which invalidates resolution).
        self._assignment_count: dict[str, int] = {}

    # ---- Assignment tracking ----

    def visit_Assign(self, node: ast.Assign) -> None:
        # Track the count of assignments to each name. Multiple
        # assignments invalidate STR003 detection for that name.
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._assignment_count[target.id] = (
                    self._assignment_count.get(target.id, 0) + 1
                )

        # If this is `name = <expr>`, try to resolve the expression.
        # If the result is a sensitive name, remember it so a future
        # use of `name` in a dangerous call becomes STR003.
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target_name = node.targets[0].id
            result = resolve(node.value)
            if result.resolved and isinstance(result.value, str):
                if result.value in _ALL_SENSITIVE:
                    obf_score = _obfuscation_score(result)
                    if obf_score > 0:
                        # Only track if there was actual obfuscation.
                        # `name = 'eval'` is suspicious but caught by
                        # other analyzers.
                        self._resolved_assignments[target_name] = (
                            result.value,
                            SourceLocation(
                                line=node.lineno,
                                column=node.col_offset,
                            ),
                        )

        self.generic_visit(node)

    # ---- Call detection ----

    def visit_Call(self, node: ast.Call) -> None:
        # STR002: dangerous function called with an argument that
        # resolves to a sensitive name.
        self._check_dangerous_call(node)

        # STR001: standalone walk-pass detection. We only check string
        # expressions in expression statement contexts and as values
        # in assignments (handled via visit_Assign already, but we
        # also run STR001 here so that resolved values appearing in
        # other positions still produce a signal).
        # NOTE: we do NOT recurse into every BinOp on every call;
        # that would be expensive and produce duplicates. The
        # walk-pass is delegated to visit_Expr.

        # Track dangerous calls whose argument is a Name, for STR003.
        self._track_dangerous_call_with_named_arg(node)

        self.generic_visit(node)

    def visit_Expr(self, node: ast.Expr) -> None:
        # STR001 walk-pass: top-level expression statements.
        # Most string-obfuscation builds happen as part of an
        # assignment or call argument; standalone expression
        # statements are rare but we cover them.
        self._maybe_emit_str001(node.value)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        # STR002: subscript-based dangerous access where the slice
        # resolves to a sensitive name.
        ns_name = _is_dangerous_subscript(node)
        if ns_name is not None:
            slice_node = node.slice
            result = resolve(slice_node)
            if result.resolved and isinstance(result.value, str):
                category = _categorize(result.value)
                if category is not None:
                    obf_score = _obfuscation_score(result)
                    if obf_score >= 1:
                        self.signals.append(self._make_signal(
                            signal_id="STR002",
                            confidence=(
                                Confidence.DEFINITE if obf_score >= 2
                                else Confidence.HIGH
                            ),
                            location=SourceLocation(
                                line=node.lineno, column=node.col_offset,
                            ),
                            description=(
                                f"obfuscated string resolves to {result.value!r} "
                                f"and is used as subscript on {ns_name}"
                            ),
                            context={
                                "resolved_value": result.value,
                                "category": category,
                                "obfuscation_score": obf_score,
                                "form": "subscript",
                                "namespace": ns_name,
                                "operations_used": list(result.operations_used),
                            },
                        ))
        self.generic_visit(node)

    # ---- Detection methods ----

    def _check_dangerous_call(self, node: ast.Call) -> None:
        """STR002: getattr/setattr/__import__/etc. with resolved sensitive arg."""
        func_name = _is_dangerous_function_call(node)
        if func_name is None:
            return

        # Determine which argument to resolve based on the function.
        # getattr(target, name): name is args[1].
        # __import__(name): name is args[0].
        # importlib.import_module(name): name is args[0].
        if func_name in {"getattr", "hasattr", "setattr"}:
            if len(node.args) < 2:
                return
            target_arg = node.args[1]
        else:
            if len(node.args) < 1:
                return
            target_arg = node.args[0]

        result = resolve(target_arg)
        self._emit_str002_or_str004(result, node, func_name, target_arg)

    def _emit_str002_or_str004(
        self,
        result: ResolutionResult,
        call_node: ast.Call,
        func_name: str,
        arg_node: ast.AST,
    ) -> None:
        """Decide between STR002 (resolved sensitive) and STR004 (heavy obf)."""
        location = SourceLocation(
            line=call_node.lineno, column=call_node.col_offset,
        )
        obf_score = _obfuscation_score(result)

        if result.resolved and isinstance(result.value, str):
            category = _categorize(result.value)
            if category is not None and obf_score >= 1:
                self.signals.append(self._make_signal(
                    signal_id="STR002",
                    confidence=(
                        Confidence.DEFINITE if obf_score >= 2
                        else Confidence.HIGH
                    ),
                    location=location,
                    description=(
                        f"argument to {func_name}() resolves to {result.value!r} "
                        f"via {obf_score} obfuscation operation"
                        f"{'s' if obf_score != 1 else ''}"
                    ),
                    context={
                        "resolved_value": result.value,
                        "category": category,
                        "obfuscation_score": obf_score,
                        "function": func_name,
                        "operations_used": list(result.operations_used),
                    },
                ))
                return

        # Partial resolution: if the concatenated resolved fragments
        # contain a sensitive name, emit STR002 at HIGH.
        if not result.resolved and result.resolved_fragments:
            joined_fragments = "".join(result.resolved_fragments)
            for sensitive in _ALL_SENSITIVE:
                if sensitive in joined_fragments:
                    category = _categorize(sensitive)
                    self.signals.append(self._make_signal(
                        signal_id="STR002",
                        confidence=Confidence.HIGH,
                        location=location,
                        description=(
                            f"argument to {func_name}() partially resolves "
                            f"to {result.partial_value!r}; resolved fragments "
                            f"({joined_fragments!r}) contain sensitive name "
                            f"{sensitive!r}"
                        ),
                        context={
                            "resolved_partial": result.partial_value,
                            "resolved_fragments": list(
                                result.resolved_fragments
                            ),
                            "matched_sensitive": sensitive,
                            "category": category,
                            "obfuscation_score": obf_score,
                            "function": func_name,
                            "operations_used": list(result.operations_used),
                            "unresolved_fragments": list(
                                result.unresolved_fragments
                            ),
                        },
                    ))
                    return

        # Heavy obfuscation without full resolution: STR004.
        if obf_score >= 4:
            self.signals.append(self._make_signal(
                signal_id="STR004",
                confidence=Confidence.HIGH if func_name else Confidence.MEDIUM,
                location=location,
                description=(
                    f"heavily obfuscated argument to {func_name}() "
                    f"({obf_score} operations); resolution failed: "
                    f"{result.reason}"
                ),
                context={
                    "obfuscation_score": obf_score,
                    "function": func_name,
                    "operations_used": list(result.operations_used),
                    "failure_reason": result.reason,
                    "partial_value": result.partial_value,
                },
            ))

    def _maybe_emit_str001(self, node: ast.AST) -> None:
        """STR001: standalone resolved sensitive-name expression."""
        result = resolve(node)
        if not result.resolved or not isinstance(result.value, str):
            return
        category = _categorize(result.value)
        if category is None:
            return
        obf_score = _obfuscation_score(result)
        if obf_score < 1:
            return
        self.signals.append(self._make_signal(
            signal_id="STR001",
            confidence=Confidence.MEDIUM,
            location=SourceLocation(
                line=node.lineno, column=node.col_offset,
            ),
            description=(
                f"standalone obfuscated expression resolves to "
                f"{result.value!r}; not seen used in a dangerous call here"
            ),
            context={
                "resolved_value": result.value,
                "category": category,
                "obfuscation_score": obf_score,
                "operations_used": list(result.operations_used),
            },
        ))

    def _track_dangerous_call_with_named_arg(self, node: ast.Call) -> None:
        """Record dangerous-call/Name-argument pairs for STR003."""
        func_name = _is_dangerous_function_call(node)
        if func_name is None:
            return

        if func_name in {"getattr", "hasattr", "setattr"}:
            if len(node.args) < 2:
                return
            target_arg = node.args[1]
        else:
            if len(node.args) < 1:
                return
            target_arg = node.args[0]

        if isinstance(target_arg, ast.Name):
            self._dangerous_calls_by_name.append((
                target_arg.id,
                func_name,
                SourceLocation(line=node.lineno, column=node.col_offset),
            ))

    # ---- Cross-reference pass ----

    def finalize(self) -> None:
        """STR003: dangerous calls whose Name argument was assigned an
        obfuscated sensitive value."""
        for arg_name, func_name, call_location in self._dangerous_calls_by_name:
            if arg_name not in self._resolved_assignments:
                continue
            # If the variable was reassigned, the obfuscation tracking
            # is unreliable; skip.
            if self._assignment_count.get(arg_name, 0) > 1:
                continue
            resolved_value, assign_location = self._resolved_assignments[
                arg_name
            ]
            category = _categorize(resolved_value)
            self.signals.append(self._make_signal(
                signal_id="STR003",
                confidence=Confidence.HIGH,
                location=call_location,
                description=(
                    f"variable {arg_name!r} (assigned to {resolved_value!r} "
                    f"at line {assign_location.line} via obfuscation) is "
                    f"used as argument to {func_name}() here"
                ),
                context={
                    "variable": arg_name,
                    "resolved_value": resolved_value,
                    "category": category,
                    "function": func_name,
                    "assignment_line": assign_location.line,
                },
            ))

    # ---- Signal helper ----

    def _make_signal(
        self,
        signal_id: str,
        confidence: Confidence,
        location: SourceLocation,
        description: str,
        context: dict,
    ) -> Signal:
        return Signal(
            analyzer="string_ops",
            signal_id=signal_id,
            confidence=confidence,
            scope=self.current_scope,
            location=location,
            description=description,
            context=context,
        )