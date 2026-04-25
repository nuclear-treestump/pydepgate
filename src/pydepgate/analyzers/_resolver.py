"""
Safe partial evaluator for Python expressions.

The resolver statically computes what a Python expression would
produce at runtime, without ever executing user code. It models
a small, fixed set of operations (string concatenation, slicing,
chr/ord, bytes construction and decoding, integer arithmetic) and
returns "unresolved" for anything outside that set.

Safety property: the resolver never invokes any function or operator
on user-controlled data. Every modeled operation is reimplemented
from scratch using only Python builtins on values the resolver
itself produced. There is no path where untrusted code runs.

Beyond yes/no resolution, the resolver returns structured information
about what it attempted: which operations it used, what it could not
resolve, and a partial textual rendering of expressions that resolved
in part but not in whole. Downstream analyzers use this to produce
diagnostics that explain to users what code is trying to do.

This module is internal to the analyzers package (note the leading
underscore). Analyzers import from it; external code should not.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# Sanity bounds. These prevent the resolver from doing unbounded work
# on adversarial inputs (huge integer arithmetic, deep recursion,
# enormous expression trees).
MAX_INT_VALUE = 2_000_000
MAX_RECURSION_DEPTH = 50
MAX_NODE_COUNT = 1000
MAX_RESULT_LENGTH = 10_000


class FailureReason(Enum):
    """Categorized reasons the resolver could not fully resolve a node."""
    UNMODELED_NODE = "unmodeled_node"
    UNMODELED_OPERATION = "unmodeled_operation"
    UNMODELED_FUNCTION = "unmodeled_function"
    UNRESOLVED_VARIABLE = "unresolved_variable"
    AMBIGUOUS_VARIABLE = "ambiguous_variable"
    EXCEEDS_BOUND = "exceeds_bound"
    RECURSION_LIMIT = "recursion_limit"
    TYPE_MISMATCH = "type_mismatch"
    UNSAFE_VALUE = "unsafe_value"


@dataclass(frozen=True)
class ResolutionResult:
    """The outcome of attempting to resolve an AST node.

    Attributes:
        resolved: True if the entire expression was resolved to a
            concrete value. False otherwise.
        value: The resolved value, if resolved=True. None otherwise.
        partial_value: A textual rendering of the expression with
            unresolved fragments marked as '???'. Set when partial
            resolution succeeded; None otherwise.
        reason: Human-readable description of why resolution failed
            or was partial.
        failure_category: Categorized reason, useful for analyzers
            that want to match on specific failure types.
        operations_used: Names of the operations the resolver applied
            during evaluation. Used for confidence calibration: an
            expression that needed many operations to resolve to a
            short string is more suspicious than one that needed few.
        unresolved_fragments: Textual renderings of each AST node
            the resolver gave up on, via ast.unparse. Empty if the
            expression was fully resolved.
    """
    resolved: bool
    value: Any = None
    partial_value: str | None = None
    reason: str = ""
    failure_category: FailureReason | None = None
    operations_used: tuple[str, ...] = field(default_factory=tuple)
    unresolved_fragments: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def success(
        cls,
        value: Any,
        operations: tuple[str, ...] = (),
    ) -> "ResolutionResult":
        """Construct a successful resolution result."""
        return cls(
            resolved=True,
            value=value,
            operations_used=operations,
        )

    @classmethod
    def failure(
        cls,
        reason: str,
        category: FailureReason,
        partial_value: str | None = None,
        operations: tuple[str, ...] = (),
        unresolved: tuple[str, ...] = (),
    ) -> "ResolutionResult":
        """Construct a failed resolution result."""
        return cls(
            resolved=False,
            reason=reason,
            failure_category=category,
            partial_value=partial_value,
            operations_used=operations,
            unresolved_fragments=unresolved,
        )


# A scope's variable table maps name -> ResolutionResult.
# An entry with resolved=True means the variable is known.
# An entry with resolved=False marks the variable ambiguous; future
# references will not resolve.
VariableTable = dict[str, ResolutionResult]


class _ResolverState:
    """Internal mutable state for one resolution session.

    Tracks: depth (for recursion limit), node count (for total work
    limit), and the stack of variable scopes.
    """

    def __init__(self, scopes: list[VariableTable] | None = None):
        self.depth = 0
        self.node_count = 0
        self.scopes: list[VariableTable] = scopes or [{}]

    def lookup(self, name: str) -> ResolutionResult | None:
        """Find a variable by name in the current scope stack.

        Searches from innermost to outermost scope. Returns None if
        the name is not in any scope.
        """
        for scope in reversed(self.scopes):
            if name in scope:
                return scope[name]
        return None


def resolve(
    node: ast.AST,
    scope_table: VariableTable | None = None,
) -> ResolutionResult:
    """Resolve an AST expression to its value, if possible.

    Args:
        node: The AST node to resolve. Typically an ast.expr subclass.
        scope_table: Optional initial variable table. Used by analyzers
            that have already walked assignments and want the resolver
            to look up variable values.

    Returns:
        A ResolutionResult describing the outcome.
    """
    state = _ResolverState(
        scopes=[scope_table] if scope_table else None,
    )
    return _resolve(node, state)


def _resolve(node: ast.AST, state: _ResolverState) -> ResolutionResult:
    """Recursive resolution dispatch.

    Each AST node type has a dedicated handler. Unmodeled types
    return UNMODELED_NODE.
    """
    state.depth += 1
    state.node_count += 1

    try:
        if state.depth > MAX_RECURSION_DEPTH:
            return ResolutionResult.failure(
                reason=f"recursion depth exceeded {MAX_RECURSION_DEPTH}",
                category=FailureReason.RECURSION_LIMIT,
            )
        if state.node_count > MAX_NODE_COUNT:
            return ResolutionResult.failure(
                reason=f"node count exceeded {MAX_NODE_COUNT}",
                category=FailureReason.EXCEEDS_BOUND,
            )

        if isinstance(node, ast.Constant):
            return _resolve_constant(node)
        if isinstance(node, ast.Name):
            return _resolve_name(node, state)
        if isinstance(node, ast.BinOp):
            return _resolve_binop(node, state)
        if isinstance(node, ast.UnaryOp):
            return _resolve_unaryop(node, state)
        if isinstance(node, ast.Subscript):
            return _resolve_subscript(node, state)
        if isinstance(node, ast.Slice):
            return _resolve_slice(node, state)
        if isinstance(node, ast.Call):
            return _resolve_call(node, state)
        if isinstance(node, ast.Attribute):
            return _resolve_attribute(node, state)
        if isinstance(node, ast.JoinedStr):
            return _resolve_joinedstr(node, state)
        if isinstance(node, ast.FormattedValue):
            return _resolve_formattedvalue(node, state)
        if isinstance(node, ast.List):
            return _resolve_list(node, state)
        if isinstance(node, ast.Tuple):
            return _resolve_list(node, state)  # same handling

        return _unmodeled_node(node)

    finally:
        state.depth -= 1


# ---- Per-node-type handlers ----


def _resolve_constant(node: ast.Constant) -> ResolutionResult:
    """ast.Constant: literal value. Always resolves."""
    value = node.value
    if isinstance(value, str) and len(value) > MAX_RESULT_LENGTH:
        return ResolutionResult.failure(
            reason=f"string literal exceeds {MAX_RESULT_LENGTH} chars",
            category=FailureReason.EXCEEDS_BOUND,
        )
    if isinstance(value, bytes) and len(value) > MAX_RESULT_LENGTH:
        return ResolutionResult.failure(
            reason=f"bytes literal exceeds {MAX_RESULT_LENGTH} bytes",
            category=FailureReason.EXCEEDS_BOUND,
        )
    if isinstance(value, int) and abs(value) > MAX_INT_VALUE:
        return ResolutionResult.failure(
            reason=f"integer literal {value} exceeds bound {MAX_INT_VALUE}",
            category=FailureReason.EXCEEDS_BOUND,
        )
    return ResolutionResult.success(value, operations=("constant",))


def _resolve_name(node: ast.Name, state: _ResolverState) -> ResolutionResult:
    """ast.Name: variable reference. Resolves via scope lookup."""
    looked_up = state.lookup(node.id)
    if looked_up is None:
        return ResolutionResult.failure(
            reason=f"variable {node.id!r} not in resolver scope",
            category=FailureReason.UNRESOLVED_VARIABLE,
            partial_value="???",
            unresolved=(node.id,),
        )
    if not looked_up.resolved:
        # The name is in scope but was previously marked ambiguous.
        return ResolutionResult.failure(
            reason=f"variable {node.id!r} has multiple assignments",
            category=FailureReason.AMBIGUOUS_VARIABLE,
            partial_value="???",
            unresolved=(node.id,),
        )
    # Resolved variable: return the cached value, recording that
    # we did a variable lookup as one of our operations.
    new_ops = looked_up.operations_used + ("variable_lookup",)
    return ResolutionResult.success(looked_up.value, operations=new_ops)


def _resolve_binop(node: ast.BinOp, state: _ResolverState) -> ResolutionResult:
    """ast.BinOp: binary operator. Models +, *, on str/bytes/int."""
    left = _resolve(node.left, state)
    right = _resolve(node.right, state)

    # If either side is fully unresolved, propagate partial info.
    if not left.resolved or not right.resolved:
        return _propagate_partial_binop(node, left, right)

    op = node.op
    lv = left.value
    rv = right.value
    ops = _merge_operations(left, right, "binop")

    try:
        if isinstance(op, ast.Add):
            if isinstance(lv, str) and isinstance(rv, str):
                result = lv + rv
                if len(result) > MAX_RESULT_LENGTH:
                    return ResolutionResult.failure(
                        reason="concatenation result exceeds length bound",
                        category=FailureReason.EXCEEDS_BOUND,
                    )
                return ResolutionResult.success(
                    result, operations=ops + ("string_concat",)
                )
            if isinstance(lv, bytes) and isinstance(rv, bytes):
                result = lv + rv
                if len(result) > MAX_RESULT_LENGTH:
                    return ResolutionResult.failure(
                        reason="bytes concatenation exceeds length bound",
                        category=FailureReason.EXCEEDS_BOUND,
                    )
                return ResolutionResult.success(
                    result, operations=ops + ("bytes_concat",)
                )
            if isinstance(lv, int) and isinstance(rv, int):
                result = lv + rv
                if abs(result) > MAX_INT_VALUE:
                    return ResolutionResult.failure(
                        reason="integer addition exceeds bound",
                        category=FailureReason.EXCEEDS_BOUND,
                    )
                return ResolutionResult.success(
                    result, operations=ops + ("int_add",)
                )
        elif isinstance(op, ast.Sub):
            if isinstance(lv, int) and isinstance(rv, int):
                result = lv - rv
                if abs(result) > MAX_INT_VALUE:
                    return ResolutionResult.failure(
                        reason="integer subtraction exceeds bound",
                        category=FailureReason.EXCEEDS_BOUND,
                    )
                return ResolutionResult.success(
                    result, operations=ops + ("int_sub",)
                )
        elif isinstance(op, ast.Mult):
            if isinstance(lv, str) and isinstance(rv, int):
                if rv < 0 or rv * len(lv) > MAX_RESULT_LENGTH:
                    return ResolutionResult.failure(
                        reason="string multiplication out of safe range",
                        category=FailureReason.EXCEEDS_BOUND,
                    )
                return ResolutionResult.success(
                    lv * rv, operations=ops + ("string_mult",)
                )
            if isinstance(lv, int) and isinstance(rv, str):
                return _resolve_binop_swap(node, state)  # handle commutative case
            if isinstance(lv, int) and isinstance(rv, int):
                result = lv * rv
                if abs(result) > MAX_INT_VALUE:
                    return ResolutionResult.failure(
                        reason="integer multiplication exceeds bound",
                        category=FailureReason.EXCEEDS_BOUND,
                    )
                return ResolutionResult.success(
                    result, operations=ops + ("int_mult",)
                )
        elif isinstance(op, ast.Mod):
            if isinstance(lv, int) and isinstance(rv, int) and rv != 0:
                return ResolutionResult.success(
                    lv % rv, operations=ops + ("int_mod",)
                )

    except (TypeError, ValueError) as exc:
        return ResolutionResult.failure(
            reason=f"binop type or value error: {exc}",
            category=FailureReason.TYPE_MISMATCH,
        )

    return ResolutionResult.failure(
        reason=f"unmodeled binop combination: {type(op).__name__} on "
               f"{type(lv).__name__} and {type(rv).__name__}",
        category=FailureReason.UNMODELED_OPERATION,
    )


def _resolve_binop_swap(
    node: ast.BinOp, state: _ResolverState
) -> ResolutionResult:
    """Helper: swap operands for commutative operations."""
    swapped = ast.BinOp(left=node.right, op=node.op, right=node.left)
    return _resolve(swapped, state)


def _resolve_unaryop(
    node: ast.UnaryOp, state: _ResolverState
) -> ResolutionResult:
    """ast.UnaryOp: -x, +x, not x. Mostly for negative integer literals."""
    operand = _resolve(node.operand, state)
    if not operand.resolved:
        return operand
    v = operand.value
    op = node.op
    ops = operand.operations_used + ("unary_op",)
    if isinstance(op, ast.USub) and isinstance(v, int):
        return ResolutionResult.success(-v, operations=ops)
    if isinstance(op, ast.UAdd) and isinstance(v, int):
        return ResolutionResult.success(+v, operations=ops)
    return ResolutionResult.failure(
        reason=f"unmodeled unaryop: {type(op).__name__} on {type(v).__name__}",
        category=FailureReason.UNMODELED_OPERATION,
    )


def _resolve_subscript(
    node: ast.Subscript, state: _ResolverState
) -> ResolutionResult:
    """ast.Subscript: container[index] and container[slice]."""
    value = _resolve(node.value, state)
    if not value.resolved:
        return ResolutionResult.failure(
            reason=f"subscript target not resolvable: {value.reason}",
            category=FailureReason.UNRESOLVED_VARIABLE,
            partial_value=f"{_partial_render(value)}[...]",
            unresolved=value.unresolved_fragments,
        )

    container = value.value

    # Slice access (e.g. 'abc'[::-1])
    if isinstance(node.slice, ast.Slice):
        slice_result = _resolve_slice_object(node.slice, state)
        if not slice_result.resolved:
            return slice_result
        try:
            sliced = container[slice_result.value]
        except (TypeError, IndexError, ValueError) as exc:
            return ResolutionResult.failure(
                reason=f"slice operation failed: {exc}",
                category=FailureReason.TYPE_MISMATCH,
            )
        ops = value.operations_used + ("subscript_slice",)
        return ResolutionResult.success(sliced, operations=ops)

    # Index access (e.g. 'abc'[0], somelist[2])
    index = _resolve(node.slice, state)
    if not index.resolved:
        return ResolutionResult.failure(
            reason=f"subscript index not resolvable: {index.reason}",
            category=FailureReason.UNRESOLVED_VARIABLE,
        )
    try:
        item = container[index.value]
    except (TypeError, IndexError, KeyError) as exc:
        return ResolutionResult.failure(
            reason=f"subscript indexing failed: {exc}",
            category=FailureReason.TYPE_MISMATCH,
        )
    ops = value.operations_used + index.operations_used + ("subscript_index",)
    return ResolutionResult.success(item, operations=ops)


def _resolve_slice(
    node: ast.Slice, state: _ResolverState
) -> ResolutionResult:
    """An ast.Slice node, when it appears on its own (rare).

    Slices are usually inside a Subscript and handled there. This is
    a fallback for unusual ASTs.
    """
    return _resolve_slice_object(node, state)


def _resolve_slice_object(
    node: ast.Slice, state: _ResolverState
) -> ResolutionResult:
    """Build a Python slice object from an ast.Slice."""
    def _resolve_or_none(part: ast.AST | None) -> ResolutionResult:
        if part is None:
            return ResolutionResult.success(None, operations=())
        return _resolve(part, state)

    lo = _resolve_or_none(node.lower)
    hi = _resolve_or_none(node.upper)
    step = _resolve_or_none(node.step)

    if not (lo.resolved and hi.resolved and step.resolved):
        return ResolutionResult.failure(
            reason="slice bounds not resolvable",
            category=FailureReason.UNRESOLVED_VARIABLE,
        )

    return ResolutionResult.success(
        slice(lo.value, hi.value, step.value),
        operations=("slice_construct",),
    )


def _resolve_call(
    node: ast.Call, state: _ResolverState
) -> ResolutionResult:
    """ast.Call: function calls. Modeled functions only."""
    # Resolve the function reference. We need to know what's being called.
    func = node.func

    # chr(int)
    if isinstance(func, ast.Name) and func.id == "chr":
        return _model_chr(node, state)
    # ord(str)
    if isinstance(func, ast.Name) and func.id == "ord":
        return _model_ord(node, state)
    # bytes([int, int, ...])
    if isinstance(func, ast.Name) and func.id == "bytes":
        return _model_bytes_constructor(node, state)
    # str.join, str.replace, bytes.fromhex, bytes.decode
    if isinstance(func, ast.Attribute):
        return _model_method_call(node, state)
    # Anything else: not modeled.
    func_text = _safe_unparse(func)
    return ResolutionResult.failure(
        reason=f"unmodeled function call: {func_text}",
        category=FailureReason.UNMODELED_FUNCTION,
        partial_value=f"{func_text}(...)",
        unresolved=(func_text,),
    )


def _resolve_attribute(
    node: ast.Attribute, state: _ResolverState
) -> ResolutionResult:
    """ast.Attribute: x.y. Mostly used for resolved-value method lookup."""
    # Resolving an attribute typically requires knowing what the value is
    # AND modeling the attribute. We don't model attribute lookups in
    # general (too much variance). The Call handler models specific
    # method calls directly, which covers the common cases.
    return ResolutionResult.failure(
        reason=f"unmodeled attribute access: {_safe_unparse(node)}",
        category=FailureReason.UNMODELED_OPERATION,
        partial_value=_safe_unparse(node),
        unresolved=(_safe_unparse(node),),
    )


def _resolve_joinedstr(
    node: ast.JoinedStr, state: _ResolverState
) -> ResolutionResult:
    """ast.JoinedStr: f-string. Resolves if every part is resolvable."""
    parts: list[str] = []
    operations: tuple[str, ...] = ("fstring",)
    unresolved: list[str] = []
    fully_resolved = True
    # Track the most specific failure category we encountered. If only
    # one part failed, we preserve its category. If multiple parts failed
    # with different categories, we fall back to UNRESOLVED_VARIABLE.
    failure_categories: list[FailureReason] = []

    for part in node.values:
        result = _resolve(part, state)
        if result.resolved:
            parts.append(str(result.value))
            operations = operations + result.operations_used
        else:
            fully_resolved = False
            if result.partial_value is not None:
                parts.append(result.partial_value)
            else:
                parts.append("???")
            unresolved.extend(result.unresolved_fragments)
            if result.failure_category is not None:
                failure_categories.append(result.failure_category)

    if fully_resolved:
        return ResolutionResult.success(
            "".join(parts), operations=operations
        )

    # Pick the most informative failure category. If there's exactly
    # one, use it. If multiple parts failed with the same category,
    # use that. Otherwise default to UNRESOLVED_VARIABLE.
    if len(set(failure_categories)) == 1 and failure_categories:
        category = failure_categories[0]
        # Build a reason that reflects the actual failure.
        reason = (
            f"f-string contains unresolved component "
            f"({category.value})"
        )
    else:
        category = FailureReason.UNRESOLVED_VARIABLE
        reason = "f-string contains unresolved interpolation"

    return ResolutionResult.failure(
        reason=reason,
        category=category,
        partial_value="".join(parts),
        operations=operations,
        unresolved=tuple(unresolved),
    )


def _resolve_formattedvalue(
    node: ast.FormattedValue, state: _ResolverState
) -> ResolutionResult:
    """ast.FormattedValue: a {...} interpolation inside an f-string.

    Supports plain interpolation only. Format specs and conversions
    return unresolved with diagnostic info per the design.
    """
    # Reject conversions (!r, !s, !a)
    if node.conversion != -1:
        text = _safe_unparse(node)
        return ResolutionResult.failure(
            reason=f"f-string conversion not modeled: {text}",
            category=FailureReason.UNMODELED_OPERATION,
            partial_value=text,
            unresolved=(text,),
        )
    # Reject format specs
    if node.format_spec is not None:
        text = _safe_unparse(node)
        return ResolutionResult.failure(
            reason=f"f-string format spec not modeled: {text}",
            category=FailureReason.UNMODELED_OPERATION,
            partial_value=text,
            unresolved=(text,),
        )
    # Plain {expression}
    inner = _resolve(node.value, state)
    if inner.resolved:
        return ResolutionResult.success(
            str(inner.value),
            operations=inner.operations_used + ("fstring_interpolate",),
        )
    return ResolutionResult.failure(
        reason=inner.reason,
        category=inner.failure_category or FailureReason.UNRESOLVED_VARIABLE,
        partial_value=inner.partial_value,
        operations=inner.operations_used,
        unresolved=inner.unresolved_fragments,
    )


def _resolve_list(
    node: ast.List | ast.Tuple, state: _ResolverState
) -> ResolutionResult:
    """ast.List or ast.Tuple: resolve each element if all are resolvable."""
    elements: list[Any] = []
    operations: tuple[str, ...] = ("list_construct",)
    for elt in node.elts:
        result = _resolve(elt, state)
        if not result.resolved:
            return ResolutionResult.failure(
                reason=f"list/tuple element not resolvable: {result.reason}",
                category=FailureReason.UNRESOLVED_VARIABLE,
            )
        elements.append(result.value)
        operations = operations + result.operations_used
    if isinstance(node, ast.Tuple):
        return ResolutionResult.success(tuple(elements), operations=operations)
    return ResolutionResult.success(elements, operations=operations)


# ---- Modeled function calls ----


def _model_chr(node: ast.Call, state: _ResolverState) -> ResolutionResult:
    """chr(int) -> str."""
    if len(node.args) != 1:
        return ResolutionResult.failure(
            reason=f"chr() called with {len(node.args)} arguments",
            category=FailureReason.UNMODELED_OPERATION,
        )
    arg = _resolve(node.args[0], state)
    if not arg.resolved:
        return arg
    if not isinstance(arg.value, int):
        return ResolutionResult.failure(
            reason=f"chr() argument is not an int: {type(arg.value).__name__}",
            category=FailureReason.TYPE_MISMATCH,
        )
    if arg.value < 0 or arg.value > 0x10FFFF:
        return ResolutionResult.failure(
            reason=f"chr() argument {arg.value} out of Unicode range",
            category=FailureReason.UNSAFE_VALUE,
        )
    return ResolutionResult.success(
        chr(arg.value), operations=arg.operations_used + ("chr",)
    )


def _model_ord(node: ast.Call, state: _ResolverState) -> ResolutionResult:
    """ord(str) -> int. Only for single-character strings."""
    if len(node.args) != 1:
        return ResolutionResult.failure(
            reason=f"ord() called with {len(node.args)} arguments",
            category=FailureReason.UNMODELED_OPERATION,
        )
    arg = _resolve(node.args[0], state)
    if not arg.resolved:
        return arg
    if not isinstance(arg.value, str) or len(arg.value) != 1:
        return ResolutionResult.failure(
            reason=f"ord() argument must be a 1-char string",
            category=FailureReason.TYPE_MISMATCH,
        )
    return ResolutionResult.success(
        ord(arg.value), operations=arg.operations_used + ("ord",)
    )


def _model_bytes_constructor(
    node: ast.Call, state: _ResolverState
) -> ResolutionResult:
    """bytes([int, int, ...]) -> bytes."""
    if len(node.args) != 1:
        return ResolutionResult.failure(
            reason=f"bytes() with {len(node.args)} arguments not modeled",
            category=FailureReason.UNMODELED_OPERATION,
        )
    arg = _resolve(node.args[0], state)
    if not arg.resolved:
        return arg
    if not isinstance(arg.value, list):
        return ResolutionResult.failure(
            reason=f"bytes() argument is not a list",
            category=FailureReason.TYPE_MISMATCH,
        )
    for item in arg.value:
        if not isinstance(item, int) or item < 0 or item > 255:
            return ResolutionResult.failure(
                reason=f"bytes() list contains non-byte value: {item!r}",
                category=FailureReason.TYPE_MISMATCH,
            )
    if len(arg.value) > MAX_RESULT_LENGTH:
        return ResolutionResult.failure(
            reason="bytes() argument list too long",
            category=FailureReason.EXCEEDS_BOUND,
        )
    return ResolutionResult.success(
        bytes(arg.value), operations=arg.operations_used + ("bytes_from_list",)
    )


def _model_method_call(
    node: ast.Call, state: _ResolverState
) -> ResolutionResult:
    """Models specific method calls on resolvable receivers.

    Currently modeled:
      - 'sep'.join(['a','b','c'])
      - 'string'.replace('x', 'y')
      - bytes.fromhex('48656c6c6f')
      - resolved_bytes.decode() / .decode('utf-8') / .decode('ascii')
    """
    func = node.func
    assert isinstance(func, ast.Attribute)
    method_name = func.attr

    # Special case: bytes.fromhex(literal). The receiver is the bytes
    # type itself (a Name node 'bytes'), not an instance.
    if (
        method_name == "fromhex"
        and isinstance(func.value, ast.Name)
        and func.value.id == "bytes"
    ):
        if len(node.args) != 1:
            return ResolutionResult.failure(
                reason="bytes.fromhex() with wrong arg count",
                category=FailureReason.UNMODELED_OPERATION,
            )
        arg = _resolve(node.args[0], state)
        if not arg.resolved:
            return arg
        if not isinstance(arg.value, str):
            return ResolutionResult.failure(
                reason="bytes.fromhex() argument is not a string",
                category=FailureReason.TYPE_MISMATCH,
            )
        try:
            result = bytes.fromhex(arg.value)
        except ValueError as exc:
            return ResolutionResult.failure(
                reason=f"bytes.fromhex() failed: {exc}",
                category=FailureReason.TYPE_MISMATCH,
            )
        return ResolutionResult.success(
            result, operations=arg.operations_used + ("bytes_fromhex",)
        )

    # Other methods require resolving the receiver.
    receiver = _resolve(func.value, state)
    if not receiver.resolved:
        text = _safe_unparse(node)
        return ResolutionResult.failure(
            reason=f"method receiver not resolvable: {receiver.reason}",
            category=FailureReason.UNRESOLVED_VARIABLE,
            partial_value=text,
            unresolved=(text,),
        )

    rv = receiver.value
    base_ops = receiver.operations_used

    if method_name == "join" and isinstance(rv, str):
        if len(node.args) != 1:
            return ResolutionResult.failure(
                reason="str.join() with wrong arg count",
                category=FailureReason.UNMODELED_OPERATION,
            )
        arg = _resolve(node.args[0], state)
        if not arg.resolved:
            return arg
        if not isinstance(arg.value, list):
            return ResolutionResult.failure(
                reason="str.join() argument is not a list",
                category=FailureReason.TYPE_MISMATCH,
            )
        for item in arg.value:
            if not isinstance(item, str):
                return ResolutionResult.failure(
                    reason="str.join() list has non-string elements",
                    category=FailureReason.TYPE_MISMATCH,
                )
        try:
            result = rv.join(arg.value)
        except (TypeError, ValueError) as exc:
            return ResolutionResult.failure(
                reason=f"str.join() failed: {exc}",
                category=FailureReason.TYPE_MISMATCH,
            )
        if len(result) > MAX_RESULT_LENGTH:
            return ResolutionResult.failure(
                reason="str.join() result too long",
                category=FailureReason.EXCEEDS_BOUND,
            )
        return ResolutionResult.success(
            result,
            operations=base_ops + arg.operations_used + ("str_join",),
        )

    if method_name == "replace" and isinstance(rv, str):
        if len(node.args) not in (2, 3):
            return ResolutionResult.failure(
                reason="str.replace() with wrong arg count",
                category=FailureReason.UNMODELED_OPERATION,
            )
        old = _resolve(node.args[0], state)
        new = _resolve(node.args[1], state)
        if not old.resolved or not new.resolved:
            return ResolutionResult.failure(
                reason="str.replace() arguments not resolvable",
                category=FailureReason.UNRESOLVED_VARIABLE,
            )
        if not isinstance(old.value, str) or not isinstance(new.value, str):
            return ResolutionResult.failure(
                reason="str.replace() arguments must be strings",
                category=FailureReason.TYPE_MISMATCH,
            )
        try:
            result = rv.replace(old.value, new.value)
        except (TypeError, ValueError) as exc:
            return ResolutionResult.failure(
                reason=f"str.replace() failed: {exc}",
                category=FailureReason.TYPE_MISMATCH,
            )
        return ResolutionResult.success(
            result,
            operations=base_ops + ("str_replace",),
        )

    if method_name == "decode" and isinstance(rv, bytes):
        encoding = "utf-8"
        if len(node.args) >= 1:
            arg = _resolve(node.args[0], state)
            if not arg.resolved:
                return arg
            if isinstance(arg.value, str):
                encoding = arg.value
            else:
                return ResolutionResult.failure(
                    reason="bytes.decode() encoding argument not a string",
                    category=FailureReason.TYPE_MISMATCH,
                )
        if encoding not in ("utf-8", "utf8", "ascii", "latin-1", "latin1"):
            return ResolutionResult.failure(
                reason=f"bytes.decode() unsupported encoding: {encoding}",
                category=FailureReason.UNMODELED_OPERATION,
            )
        try:
            result = rv.decode(encoding)
        except (UnicodeDecodeError, LookupError) as exc:
            return ResolutionResult.failure(
                reason=f"bytes.decode() failed: {exc}",
                category=FailureReason.TYPE_MISMATCH,
            )
        return ResolutionResult.success(
            result, operations=base_ops + ("bytes_decode",)
        )

    return ResolutionResult.failure(
        reason=f"unmodeled method: {type(rv).__name__}.{method_name}",
        category=FailureReason.UNMODELED_FUNCTION,
    )


# ---- Helpers ----


def _unmodeled_node(node: ast.AST) -> ResolutionResult:
    """Default fallback for AST node types we do not model."""
    text = _safe_unparse(node)
    return ResolutionResult.failure(
        reason=f"unmodeled AST node type: {type(node).__name__}",
        category=FailureReason.UNMODELED_NODE,
        partial_value=text,
        unresolved=(text,),
    )


def _safe_unparse(node: ast.AST) -> str:
    """Render an AST node as text, with a fallback if unparse fails."""
    try:
        return ast.unparse(node)
    except Exception:
        return f"<{type(node).__name__}>"


def _propagate_partial_binop(
    node: ast.BinOp,
    left: ResolutionResult,
    right: ResolutionResult,
) -> ResolutionResult:
    """Build a partial-resolution result for a BinOp where one side is
    unresolved. Preserves the most specific failure category from the
    failing operand(s).
    """
    op = node.op
    op_text = _binop_symbol(op)
    left_text = _partial_render(left)
    right_text = _partial_render(right)
    partial = f"{left_text} {op_text} {right_text}"
    operations = _merge_operations(left, right, "binop_partial")
    unresolved = left.unresolved_fragments + right.unresolved_fragments

    # Preserve a specific failure category if exactly one side failed,
    # or if both failed with the same category.
    failure_categories = []
    if not left.resolved and left.failure_category is not None:
        failure_categories.append(left.failure_category)
    if not right.resolved and right.failure_category is not None:
        failure_categories.append(right.failure_category)

    if len(set(failure_categories)) == 1 and failure_categories:
        category = failure_categories[0]
        # Use the more specific reason.
        reason = (
            left.reason if not left.resolved
            else right.reason
        )
    else:
        category = FailureReason.UNRESOLVED_VARIABLE
        reason = "binop has unresolved operand"

    return ResolutionResult.failure(
        reason=reason,
        category=category,
        partial_value=partial,
        operations=operations,
        unresolved=unresolved,
    )


def _binop_symbol(op: ast.AST) -> str:
    """Return the Python operator text for an AST binop node."""
    return {
        ast.Add: "+",
        ast.Sub: "-",
        ast.Mult: "*",
        ast.Div: "/",
        ast.Mod: "%",
        ast.Pow: "**",
        ast.FloorDiv: "//",
        ast.LShift: "<<",
        ast.RShift: ">>",
        ast.BitAnd: "&",
        ast.BitOr: "|",
        ast.BitXor: "^",
    }.get(type(op), "?")


def _partial_render(result: ResolutionResult) -> str:
    """Render a ResolutionResult as text for use inside partial_value."""
    if result.resolved:
        return repr(result.value)
    if result.partial_value is not None:
        return result.partial_value
    return "???"


def _merge_operations(
    a: ResolutionResult, b: ResolutionResult, suffix: str
) -> tuple[str, ...]:
    """Combine operation lists from two sub-resolutions."""
    return a.operations_used + b.operations_used + (suffix,)