"""
Shared AST visitor infrastructure for pydepgate analyzers.

This module is internal (note the leading underscore). Analyzers
import from here for common AST-walking utilities; external code
should not import from this module.

The two utilities here are:

  _ScopeTracker: an ast.NodeVisitor subclass that maintains a stack
                 of Scope values as it descends through function and
                 class definitions. Subclasses can read self.current_scope
                 to know whether they are at module level, inside a
                 function, etc.

  get_qualified_name: extract a dotted name from an AST node. Returns
                      'base64.b64decode' for an Attribute node, 'eval'
                      for a Name node, None for anything else (calls,
                      subscripts, etc.).
"""

from __future__ import annotations

import ast

from pydepgate.analyzers.base import Scope


class _ScopeTracker(ast.NodeVisitor):
    """An ast.NodeVisitor that tracks the current scope.

    Subclasses override visit_* methods and read self.current_scope to
    know where in the code structure they are. The tracker descends
    into function definitions, async function definitions, and class
    definitions, pushing the appropriate Scope onto its stack.

    Note: this tracker does NOT descend into nested scopes implicitly.
    Subclasses must call self.generic_visit(node) at the end of their
    own visit_* methods (after their detection logic) to continue
    walking the tree. This matches the standard NodeVisitor convention.
    """

    def __init__(self) -> None:
        self._scope_stack: list[Scope] = [Scope.MODULE]

    @property
    def current_scope(self) -> Scope:
        """The scope at the current point in the AST walk."""
        return self._scope_stack[-1]

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # A function defined inside another function is "nested";
        # a function at module level (or directly in a class body)
        # is just FUNCTION.
        if self.current_scope in (Scope.MODULE, Scope.CLASS_BODY):
            entering = Scope.FUNCTION
        else:
            entering = Scope.NESTED_FUNCTION
        self._scope_stack.append(entering)
        self.generic_visit(node)
        self._scope_stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        # Same logic as visit_FunctionDef. Reuse rather than duplicate.
        self.visit_FunctionDef(node)  # type: ignore[arg-type]

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._scope_stack.append(Scope.CLASS_BODY)
        self.generic_visit(node)
        self._scope_stack.pop()


def get_qualified_name(node: ast.AST) -> str | None:
    """Extract a dotted name from an AST node.

    Returns:
      - 'eval' for a Name node with id='eval'
      - 'base64.b64decode' for an Attribute(value=Name(id='base64'), attr='b64decode')
      - 'os.path.join' for nested Attribute nodes
      - None for any node that is not a simple name reference
        (Call, Subscript, BinOp, etc.)

    This is the basic name-extraction utility for analyzers that match
    on function calls. It handles only the static case: a name written
    out in the source. Aliased or computed names will return either a
    different name (for aliases) or None (for computations), and the
    analyzer is responsible for deciding what to do with that.
    """
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = get_qualified_name(node.value)
        if parent is None:
            return None
        return f"{parent}.{node.attr}"
    return None