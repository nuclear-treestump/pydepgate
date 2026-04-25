"""Tests for pydepgate.analyzers._resolver."""

import ast
import unittest

from pydepgate.analyzers._resolver import (
    FailureReason,
    MAX_INT_VALUE,
    MAX_RESULT_LENGTH,
    ResolutionResult,
    resolve,
)


def _resolve_expr(source: str, scope: dict | None = None) -> ResolutionResult:
    """Helper: parse a Python expression and resolve it."""
    tree = ast.parse(source, mode="eval")
    return resolve(tree.body, scope_table=scope)


# =============================================================================
# Tier 1: Safety
# =============================================================================

class SafetyTests(unittest.TestCase):
    """The resolver must never execute user code or crash on hostile input."""

    def test_does_not_execute_function_calls(self):
        # If the resolver were unsafely evaluating, this would set a global.
        result = _resolve_expr(
            "(__import__('sys').__setattr__('PYDEPGATE_PWNED', True), 'ev'+'al')[1]"
        )
        # The tuple/subscript pattern is unmodeled, so we should fail safely.
        # The critical assertion is that the side effect did not happen.
        import sys
        self.assertFalse(hasattr(sys, "PYDEPGATE_PWNED"))

    def test_does_not_evaluate_arbitrary_calls(self):
        # If we ran exec, this would set a global. It must not.
        result = _resolve_expr("exec('global X; X=1')")
        # The result is unresolved (exec is not modeled).
        self.assertFalse(result.resolved)
        self.assertEqual(result.failure_category, FailureReason.UNMODELED_FUNCTION)

    def test_handles_malformed_chr_argument(self):
        # chr() with a string would TypeError at runtime.
        # The resolver should not propagate that as an exception.
        result = _resolve_expr("chr('not an int')")
        self.assertFalse(result.resolved)
        self.assertEqual(result.failure_category, FailureReason.TYPE_MISMATCH)

    def test_handles_chr_out_of_range(self):
        result = _resolve_expr(f"chr({0x110000})")
        self.assertFalse(result.resolved)
        self.assertEqual(result.failure_category, FailureReason.UNSAFE_VALUE)

    def test_handles_huge_string_multiplication(self):
        result = _resolve_expr("'a' * 1000000000")
        self.assertFalse(result.resolved)
        self.assertEqual(result.failure_category, FailureReason.EXCEEDS_BOUND)

    def test_handles_huge_int_arithmetic(self):
        result = _resolve_expr(f"{MAX_INT_VALUE} + 100")
        self.assertFalse(result.resolved)
        self.assertEqual(result.failure_category, FailureReason.EXCEEDS_BOUND)


# =============================================================================
# Tier 2: Basic resolution
# =============================================================================

class ConstantTests(unittest.TestCase):

    def test_string_literal(self):
        result = _resolve_expr("'hello'")
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, "hello")

    def test_bytes_literal(self):
        result = _resolve_expr("b'hello'")
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, b"hello")

    def test_integer_literal(self):
        result = _resolve_expr("42")
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, 42)

    def test_negative_integer_literal(self):
        result = _resolve_expr("-1")
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, -1)

    def test_none_literal(self):
        result = _resolve_expr("None")
        self.assertTrue(result.resolved)
        self.assertIsNone(result.value)

    def test_bool_literal(self):
        result = _resolve_expr("True")
        self.assertTrue(result.resolved)
        self.assertIs(result.value, True)


class StringConcatTests(unittest.TestCase):

    def test_simple_concat(self):
        result = _resolve_expr("'ev' + 'al'")
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, "eval")
        self.assertIn("string_concat", result.operations_used)

    def test_three_piece_concat(self):
        result = _resolve_expr("'i' + 'mp' + 'ort'")
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, "import")

    def test_concat_with_chr(self):
        result = _resolve_expr("'e' + chr(118) + 'al'")
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, "eval")

    def test_string_multiplication(self):
        result = _resolve_expr("'ab' * 3")
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, "ababab")


class BytesTests(unittest.TestCase):

    def test_bytes_concat(self):
        result = _resolve_expr("b'ev' + b'al'")
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, b"eval")

    def test_bytes_from_list(self):
        result = _resolve_expr("bytes([101, 118, 97, 108])")
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, b"eval")

    def test_bytes_fromhex(self):
        result = _resolve_expr("bytes.fromhex('6576616c')")
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, b"eval")

    def test_bytes_decode(self):
        result = _resolve_expr("bytes([101, 118, 97, 108]).decode()")
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, "eval")

    def test_bytes_decode_with_encoding(self):
        result = _resolve_expr("bytes([101, 118, 97, 108]).decode('ascii')")
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, "eval")

    def test_bytes_decode_unsupported_encoding(self):
        result = _resolve_expr("bytes([101]).decode('rot_13')")
        self.assertFalse(result.resolved)
        self.assertEqual(result.failure_category, FailureReason.UNMODELED_OPERATION)


class ChrOrdTests(unittest.TestCase):

    def test_chr(self):
        result = _resolve_expr("chr(101)")
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, "e")

    def test_chr_with_arithmetic(self):
        result = _resolve_expr("chr(100 + 1)")
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, "e")

    def test_ord(self):
        result = _resolve_expr("ord('e')")
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, 101)


class SliceTests(unittest.TestCase):

    def test_slice_reverse(self):
        result = _resolve_expr("'lave'[::-1]")
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, "eval")

    def test_slice_range(self):
        result = _resolve_expr("'helloeval'[5:9]")
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, "eval")

    def test_index_access(self):
        result = _resolve_expr("'eval'[0]")
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, "e")


class JoinReplaceTests(unittest.TestCase):

    def test_empty_join(self):
        result = _resolve_expr("''.join(['e','v','a','l'])")
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, "eval")

    def test_separator_join(self):
        result = _resolve_expr("'-'.join(['e','v','a','l'])")
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, "e-v-a-l")

    def test_replace(self):
        result = _resolve_expr("'eXvXaXlX'.replace('X', '')")
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, "eval")


# =============================================================================
# Tier 3: Variable tracking
# =============================================================================

class VariableTrackingTests(unittest.TestCase):

    def test_resolved_variable(self):
        scope = {"name": ResolutionResult.success("eval")}
        result = _resolve_expr("name", scope=scope)
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, "eval")

    def test_unresolved_variable(self):
        result = _resolve_expr("undefined_var")
        self.assertFalse(result.resolved)
        self.assertEqual(result.failure_category, FailureReason.UNRESOLVED_VARIABLE)
        self.assertIn("undefined_var", result.unresolved_fragments)

    def test_ambiguous_variable(self):
        # Manually construct an ambiguous variable.
        scope = {
            "name": ResolutionResult.failure(
                reason="reassigned", category=FailureReason.AMBIGUOUS_VARIABLE
            )
        }
        result = _resolve_expr("name", scope=scope)
        self.assertFalse(result.resolved)
        self.assertEqual(result.failure_category, FailureReason.AMBIGUOUS_VARIABLE)

    def test_variable_in_concat(self):
        scope = {"middle": ResolutionResult.success("v")}
        result = _resolve_expr("'e' + middle + 'al'", scope=scope)
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, "eval")


# =============================================================================
# Tier 4: Partial resolution
# =============================================================================

class PartialResolutionTests(unittest.TestCase):

    def test_unresolved_variable_in_concat_produces_partial(self):
        result = _resolve_expr("'ev' + secret + 'al'")
        self.assertFalse(result.resolved)
        self.assertIsNotNone(result.partial_value)
        # Partial value contains the resolved fragments and a marker
        # for the unresolved one.
        self.assertIn("'ev'", result.partial_value)
        self.assertIn("'al'", result.partial_value)

    def test_unresolved_function_call_produces_partial(self):
        result = _resolve_expr("'pre' + secret_func() + 'suf'")
        self.assertFalse(result.resolved)
        self.assertIsNotNone(result.partial_value)
        self.assertIn("'pre'", result.partial_value)
        self.assertIn("'suf'", result.partial_value)

    def test_fstring_with_unresolved_interpolation(self):
        # f-string with one resolvable and one unresolvable piece.
        result = _resolve_expr("f'prefix_{some_var}_suffix'")
        self.assertFalse(result.resolved)
        self.assertIsNotNone(result.partial_value)
        self.assertIn("prefix_", result.partial_value)
        self.assertIn("_suffix", result.partial_value)

    def test_unresolved_fragments_recorded(self):
        result = _resolve_expr("'a' + b + 'c'")
        self.assertFalse(result.resolved)
        self.assertIn("b", result.unresolved_fragments)


# =============================================================================
# Tier 5: f-strings
# =============================================================================

class FStringTests(unittest.TestCase):

    def test_fstring_with_no_interpolation(self):
        result = _resolve_expr("f'hello'")
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, "hello")

    def test_fstring_with_literal_interpolation(self):
        result = _resolve_expr("f'{\"ev\"}{\"al\"}'")
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, "eval")

    def test_fstring_with_resolved_variable(self):
        scope = {"x": ResolutionResult.success("eval")}
        result = _resolve_expr("f'name_{x}'", scope=scope)
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, "name_eval")

    def test_fstring_with_format_spec_unresolved(self):
        result = _resolve_expr("f'{42:>5}'")
        self.assertFalse(result.resolved)
        self.assertEqual(result.failure_category, FailureReason.UNMODELED_OPERATION)

    def test_fstring_with_conversion_unresolved(self):
        result = _resolve_expr("f'{42!r}'")
        self.assertFalse(result.resolved)
        self.assertEqual(result.failure_category, FailureReason.UNMODELED_OPERATION)


# =============================================================================
# Tier 6: Adversarial / robustness
# =============================================================================

class AdversarialTests(unittest.TestCase):

    def test_deeply_nested_concat(self):
        # 30 levels of concat. Should still resolve.
        expr = " + ".join(f"'{c}'" for c in "abcdefghijklmnopqrstuvwxyz0123")
        result = _resolve_expr(expr)
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, "abcdefghijklmnopqrstuvwxyz0123")

    def test_extremely_deep_recursion_aborts(self):
        # Build a 100-element BinOp chain via string concatenation.
        # Each '+' is one recursion level in _resolve_binop.
        # MAX_RECURSION_DEPTH is 50, so this should abort.
        expr = " + ".join(["'a'"] * 100)
        result = _resolve_expr(expr)
        self.assertFalse(result.resolved)
        self.assertEqual(result.failure_category, FailureReason.RECURSION_LIMIT)

    def test_unmodeled_expression_returns_partial(self):
        # Conditional expression is not modeled; should fail gracefully.
        result = _resolve_expr("'a' if True else 'b'")
        self.assertFalse(result.resolved)
        # It's an unmodeled node type.
        self.assertEqual(result.failure_category, FailureReason.UNMODELED_NODE)
        self.assertIsNotNone(result.partial_value)

    def test_dict_literal_unmodeled(self):
        result = _resolve_expr("{'key': 'value'}")
        self.assertFalse(result.resolved)
        self.assertEqual(result.failure_category, FailureReason.UNMODELED_NODE)


# =============================================================================
# Tier 7: Operations tracking
# =============================================================================

class OperationsTrackingTests(unittest.TestCase):
    """The operations_used field reflects what the resolver did.
    This is what enables the 'harder they hide it the stronger the
    signal' model in downstream analyzers."""

    def test_simple_constant_has_one_operation(self):
        result = _resolve_expr("'hello'")
        self.assertEqual(result.operations_used, ("constant",))

    def test_concat_records_operations(self):
        result = _resolve_expr("'ev' + 'al'")
        self.assertIn("string_concat", result.operations_used)
        # And the constants underneath also recorded.
        self.assertEqual(result.operations_used.count("constant"), 2)

    def test_chr_concat_has_many_operations(self):
        result = _resolve_expr(
            "chr(101) + chr(118) + chr(97) + chr(108)"
        )
        self.assertTrue(result.resolved)
        # 4 chr operations + 3 concats + 4 underlying constants = many operations.
        self.assertEqual(result.operations_used.count("chr"), 4)
        self.assertGreaterEqual(result.operations_used.count("string_concat"), 3)

    def test_bytes_decode_operation_recorded(self):
        result = _resolve_expr("bytes([101, 118, 97, 108]).decode()")
        self.assertIn("bytes_from_list", result.operations_used)
        self.assertIn("bytes_decode", result.operations_used)


# =============================================================================
# Tier 8: Real-world-ish payloads
# =============================================================================

class RealWorldPatternTests(unittest.TestCase):
    """Patterns from actual obfuscation seen in PyPI malware."""

    def test_eval_assembled_from_chars(self):
        result = _resolve_expr(
            "chr(101) + chr(118) + chr(97) + chr(108)"
        )
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, "eval")

    def test_exec_via_reverse(self):
        result = _resolve_expr("'cexe'[::-1]")
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, "exec")

    def test_compile_assembled_via_concat(self):
        result = _resolve_expr("'co' + 'mp' + 'ile'")
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, "compile")

    def test_import_via_join(self):
        result = _resolve_expr("''.join(['_','_','i','m','p','o','r','t','_','_'])")
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, "__import__")

    def test_os_via_bytes_fromhex(self):
        result = _resolve_expr("bytes.fromhex('6f73').decode()")
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, "os")

    def test_eval_via_bytes_then_decode(self):
        result = _resolve_expr("bytes([101, 118, 97, 108]).decode('ascii')")
        self.assertTrue(result.resolved)
        self.assertEqual(result.value, "eval")


if __name__ == "__main__":
    unittest.main()