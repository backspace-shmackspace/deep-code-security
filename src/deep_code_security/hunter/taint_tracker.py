"""Intraprocedural taint propagation engine using a worklist algorithm."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from deep_code_security.hunter.models import Sink, Source, TaintPath, TaintStep
from deep_code_security.hunter.registry import Registry
from deep_code_security.shared.language import Language

__all__ = ["TaintEngine", "TaintState", "find_taint_paths"]

logger = logging.getLogger(__name__)

# Format string argument index (0-based) for printf-family functions.
# Only the argument at this position is the format string; subsequent arguments
# are %-substitution values and must NOT trigger a CWE-134 finding even if tainted.
_FORMAT_STRING_ARG_INDEX: dict[str, int] = {
    "printf": 0,
    "vprintf": 0,
    "fprintf": 1,
    "vfprintf": 1,
    "sprintf": 1,
    "vsprintf": 1,
    "snprintf": 2,
    "vsnprintf": 2,
    "syslog": 1,
    "vsyslog": 1,
}

# Per-language AST node type mappings for taint propagation
_LANGUAGE_NODE_TYPES: dict[str, dict[str, list[str]]] = {
    "python": {
        "assignment": ["assignment"],
        "augmented_assignment": ["augmented_assignment"],
        "binary_op": ["binary_operator"],
        "call": ["call"],
        "function_def": ["function_definition"],
        "argument_list": ["argument_list"],
        "string_concat": ["binary_operator"],  # with + operator
        "f_string": ["string"],  # f-strings contain interpolation
        "return": ["return_statement"],
    },
    "go": {
        "assignment": ["assignment_statement", "short_var_decl"],
        "augmented_assignment": ["assignment_statement"],
        "binary_op": ["binary_expression"],
        "call": ["call_expression"],
        "function_def": ["function_declaration", "method_declaration"],
        "argument_list": ["argument_list"],
        "string_concat": ["binary_expression"],
        "return": ["return_statement"],
    },
    "c": {
        "assignment": ["assignment_expression", "init_declarator"],
        "augmented_assignment": ["assignment_expression"],
        "binary_op": ["binary_expression"],
        "call": ["call_expression"],
        "function_def": ["function_definition"],
        "argument_list": ["argument_list"],
        "string_concat": ["binary_expression"],
        "return": ["return_statement"],
    },
}

# Categories that conditional bounds checks can sanitize
_SIZE_SANITIZABLE_CATEGORIES: frozenset[str] = frozenset({
    "buffer_overflow",    # CWE-120
    "memory_corruption",  # CWE-119
    "integer_overflow",   # CWE-190
})


@dataclass
class TaintState:
    """Tracks tainted variables within a function scope."""

    # Set of tainted variable names
    tainted_vars: set[str] = field(default_factory=set)
    # Map from variable name to the step that tainted it
    taint_steps: dict[str, TaintStep] = field(default_factory=dict)
    # Variables that have been conditionally sanitized.
    # Maps variable name -> set of sink categories that are neutralized.
    sanitized_vars: dict[str, set[str]] = field(default_factory=dict)

    def add_taint(self, var_name: str, step: TaintStep) -> None:
        """Mark a variable as tainted.

        Clears any prior conditional sanitization for the variable,
        because re-assignment from a tainted source invalidates the
        previous bounds check.

        Args:
            var_name: Variable name to taint.
            step: The taint step describing how this variable became tainted.
        """
        self.tainted_vars.add(var_name)
        self.taint_steps[var_name] = step
        # Clear stale sanitization: re-taint invalidates prior bounds check
        self.sanitized_vars.pop(var_name, None)

    def add_sanitization(self, var_name: str, categories: set[str]) -> None:
        """Mark a tainted variable as conditionally sanitized for specific categories.

        Args:
            var_name: Variable name that has been bounds-checked.
            categories: Sink categories that the bounds check neutralizes.
        """
        if var_name in self.tainted_vars:
            existing = self.sanitized_vars.get(var_name, set())
            self.sanitized_vars[var_name] = existing | categories

    def is_sanitized_for(self, var_name: str, category: str) -> bool:
        """Check if a variable is sanitized for a specific sink category.

        Args:
            var_name: Variable name to check.
            category: Sink category to check against.

        Returns:
            True if the variable has been conditionally sanitized for this category.
        """
        return category in self.sanitized_vars.get(var_name, set())

    def is_tainted(self, var_name: str) -> bool:
        """Check if a variable is tainted.

        Args:
            var_name: Variable name to check.

        Returns:
            True if the variable is tainted.
        """
        return var_name in self.tainted_vars

    def copy(self) -> TaintState:
        """Create a deep copy of this taint state."""
        new_state = TaintState()
        new_state.tainted_vars = self.tainted_vars.copy()
        new_state.taint_steps = self.taint_steps.copy()
        new_state.sanitized_vars = {
            k: v.copy() for k, v in self.sanitized_vars.items()
        }
        return new_state


class TaintEngine:
    """Intraprocedural taint tracking engine.

    Uses a worklist algorithm:
    1. Seed worklist with source variable names
    2. Process each statement: propagate taint through assignments, concatenations, etc.
    3. When a tainted variable reaches a sink argument, record the TaintPath
    """

    def __init__(self, language: Language, registry: Registry) -> None:
        self.language = language
        self.registry = registry
        self.node_types = _LANGUAGE_NODE_TYPES.get(language.value, {})

    def find_taint_paths(
        self,
        tree: Any,
        sources: list[Source],
        sinks: list[Sink],
        file_path: str,
    ) -> list[tuple[Source, Sink, TaintPath]]:
        """Find all taint paths from sources to sinks within the same function.

        Args:
            tree: tree_sitter.Tree for the file.
            sources: Sources found in this file.
            sinks: Sinks found in this file.
            file_path: Path to the source file.

        Returns:
            List of (Source, Sink, TaintPath) tuples.
        """
        if not sources or not sinks:
            return []

        results: list[tuple[Source, Sink, TaintPath]] = []

        # Group sources and sinks by function scope
        function_nodes = self._find_function_nodes(tree.root_node)

        # For each function, find sources and sinks within it
        for func_node in function_nodes:
            func_start = func_node.start_point[0] + 1
            func_end = func_node.end_point[0] + 1

            func_sources = [
                s for s in sources if func_start <= s.line <= func_end
            ]
            func_sinks = [
                s for s in sinks if func_start <= s.line <= func_end
            ]

            if not func_sources or not func_sinks:
                continue

            # Run taint analysis within this function
            func_results = self._analyze_function(
                func_node, func_sources, func_sinks, file_path
            )
            results.extend(func_results)

        # Also check top-level code (not inside any function)
        if function_nodes:
            func_ranges = [
                (fn.start_point[0] + 1, fn.end_point[0] + 1)
                for fn in function_nodes
            ]
            top_level_sources = [
                s for s in sources
                if not any(start <= s.line <= end for start, end in func_ranges)
            ]
            top_level_sinks = [
                s for s in sinks
                if not any(start <= s.line <= end for start, end in func_ranges)
            ]
        else:
            top_level_sources = sources
            top_level_sinks = sinks

        if top_level_sources and top_level_sinks:
            top_results = self._analyze_function(
                tree.root_node, top_level_sources, top_level_sinks, file_path
            )
            results.extend(top_results)

        return results

    def _find_function_nodes(self, root_node: Any) -> list[Any]:
        """Find all function definition nodes in the AST.

        Args:
            root_node: Root AST node to search.

        Returns:
            List of function definition nodes.
        """
        func_types = self.node_types.get("function_def", ["function_definition"])
        result: list[Any] = []
        self._collect_by_types(root_node, func_types, result)
        return result

    def _collect_by_types(
        self, node: Any, types: list[str], result: list[Any]
    ) -> None:
        """Recursively collect all nodes of given types.

        Args:
            node: Starting AST node.
            types: Node type names to collect.
            result: List to append matching nodes to.
        """
        if node.type in types:
            result.append(node)
        for child in node.children:
            self._collect_by_types(child, types, result)

    def _analyze_function(
        self,
        func_node: Any,
        sources: list[Source],
        sinks: list[Sink],
        file_path: str,
    ) -> list[tuple[Source, Sink, TaintPath]]:
        """Analyze a function for taint paths between sources and sinks.

        Args:
            func_node: Function AST node (or root for top-level code).
            sources: Sources within this function.
            sinks: Sinks within this function.
            file_path: Path to the source file.

        Returns:
            List of (Source, Sink, TaintPath) tuples.
        """
        results: list[tuple[Source, Sink, TaintPath]] = []

        for source in sources:
            # Initialize taint state with the source variable
            state = TaintState()

            # Seed: the source itself is tainted
            # Find the variable name assigned from the source
            source_var = self._find_assigned_var_near_line(
                func_node, source.line, file_path
            )

            initial_step = TaintStep(
                file=file_path,
                line=source.line,
                column=source.column,
                variable=source_var or source.function,
                transform="source",
            )

            if source_var:
                state.add_taint(source_var, initial_step)
            # Also mark the source pattern itself as a tainted "pseudo-variable"
            state.add_taint(source.function, initial_step)

            # Propagate taint through the function
            self._propagate_taint(func_node, state, file_path)

            # Check if any sink is reachable from the tainted state
            for sink in sinks:
                if sink.line <= source.line:
                    continue  # Sink before source in code (simplistic check)

                # Check if a tainted variable appears as an argument to the sink
                is_reachable, path_steps, sanitizer_info = self._check_sink_reachability(
                    func_node, sink, state, file_path
                )

                if is_reachable:
                    # Build the taint path
                    all_steps = [initial_step] + path_steps

                    # Check for sanitizers
                    sanitized = sanitizer_info is not None
                    sanitizer_name = sanitizer_info

                    taint_path = TaintPath(
                        steps=all_steps,
                        sanitized=sanitized,
                        sanitizer=sanitizer_name,
                    )
                    results.append((source, sink, taint_path))
                    logger.debug(
                        "Taint path: %s (line %d) -> %s (line %d)",
                        source.function, source.line,
                        sink.function, sink.line,
                    )

        return results

    def _find_assigned_var_near_line(
        self, func_node: Any, line: int, file_path: str
    ) -> str | None:
        """Find the variable name that receives a value near the given line.

        Looks for assignment statements where the right-hand side is at or near
        the source line.

        Args:
            func_node: Function AST node to search.
            line: Source code line to search around.
            file_path: File path (for context).

        Returns:
            Variable name if found, None otherwise.
        """
        assignment_types = self.node_types.get("assignment", ["assignment"])

        def find_assignment(node: Any) -> str | None:
            node_line = node.start_point[0] + 1
            if abs(node_line - line) <= 2 and node.type in assignment_types:
                # Try to extract LHS variable name
                var_name = self._extract_lhs_name(node)
                if var_name:
                    return var_name
            for child in node.children:
                result = find_assignment(child)
                if result:
                    return result
            return None

        return find_assignment(func_node)

    def _extract_lhs_name(self, assignment_node: Any) -> str | None:
        """Extract the variable name from an assignment left-hand side.

        Args:
            assignment_node: Assignment AST node.

        Returns:
            Variable name if extractable, None otherwise.
        """
        # For Python: assignment -> identifier = ...
        # For Go: short_var_decl -> identifier := ...
        for child in assignment_node.children:
            if child.type in ("identifier", "expression_list"):
                if child.type == "identifier":
                    return child.text.decode("utf-8", errors="replace")
                # expression_list: first child
                if child.children:
                    first = child.children[0]
                    if first.type == "identifier":
                        return first.text.decode("utf-8", errors="replace")
            # C-specific: pointer_declarator wraps the identifier
            # e.g., char *p = recv(...) has init_declarator children
            # [pointer_declarator, "=", call_expression]
            if child.type == "pointer_declarator":
                return self._node_to_var_name(child)
            # C-specific: subscript_expression on LHS
            # e.g., buf[i] = tainted has subscript_expression
            if child.type == "subscript_expression":
                return self._node_to_var_name(child)
        return None

    def _propagate_taint(
        self, func_node: Any, state: TaintState, file_path: str
    ) -> None:
        """Propagate taint through all statements in the function body.

        This is a simplified single-pass propagation (not a full fixpoint).
        For v1, we do one forward pass through the AST.

        For C, also processes if_statement nodes to detect conditional
        bounds-check patterns (Pattern 1: if-statement clamp).

        Args:
            func_node: Function AST node.
            state: Mutable taint state to update.
            file_path: File path.
        """
        assignment_types = self.node_types.get("assignment", ["assignment"])
        aug_assignment_types = self.node_types.get("augmented_assignment", [])
        binary_op_types = self.node_types.get("binary_op", ["binary_operator"])

        def visit(node: Any) -> None:
            if node.type in assignment_types or node.type in aug_assignment_types:
                self._handle_assignment(node, state, file_path, binary_op_types)
            elif node.type == "if_statement" and self.language == Language.C:
                self._handle_if_sanitizer(node, state)
                # Still recurse into children to propagate taint through the body
                for child in node.children:
                    visit(child)
            else:
                for child in node.children:
                    visit(child)

        visit(func_node)

    def _handle_assignment(
        self,
        node: Any,
        state: TaintState,
        file_path: str,
        binary_op_types: list[str],
    ) -> None:
        """Handle a single assignment statement for taint propagation.

        Args:
            node: Assignment AST node.
            state: Mutable taint state.
            file_path: File path.
            binary_op_types: Node types for binary operations.
        """
        # Find LHS identifier(s) and RHS expression
        lhs_names: list[str] = []
        rhs_node: Any = None

        children = list(node.children)

        if self.language == Language.PYTHON:
            # Python: assignment has left, right
            # assignment node children: [identifier, "=", value]
            non_op = [c for c in children if c.type not in ("=", "+=", "-=", "*=")]
            if len(non_op) >= 2:
                lhs_node = non_op[0]
                rhs_node = non_op[-1]
                name = self._node_to_var_name(lhs_node)
                if name:
                    lhs_names.append(name)

        elif self.language == Language.GO:
            # Go: short_var_decl: [left, ":=", right]
            # assignment_statement: [left, "=", right]
            non_op = [c for c in children if c.type not in (":=", "=", "+=", ",")]
            if len(non_op) >= 2:
                lhs_node = non_op[0]
                rhs_node = non_op[-1]
                # Handle expression_list on LHS
                if lhs_node.type == "expression_list":
                    for child in lhs_node.children:
                        name = self._node_to_var_name(child)
                        if name:
                            lhs_names.append(name)
                else:
                    name = self._node_to_var_name(lhs_node)
                    if name:
                        lhs_names.append(name)

        elif self.language == Language.C:
            # C: init_declarator or assignment_expression
            non_op = [c for c in children if c.type not in ("=", "+=")]
            if len(non_op) >= 2:
                lhs_node = non_op[0]
                rhs_node = non_op[-1]
                name = self._node_to_var_name(lhs_node)
                if name:
                    lhs_names.append(name)

        if rhs_node is None or not lhs_names:
            return

        # Check if RHS contains tainted variables
        rhs_tainted = self._is_rhs_tainted(rhs_node, state, binary_op_types)
        if rhs_tainted:
            transform = self._classify_rhs_transform(rhs_node, binary_op_types)
            for lhs_name in lhs_names:
                step = TaintStep(
                    file=file_path,
                    line=node.start_point[0] + 1,
                    column=node.start_point[1],
                    variable=lhs_name,
                    transform=transform,
                )
                state.add_taint(lhs_name, step)

            # Pattern 2: Ternary clamp detection.
            # Check AFTER add_taint (R-1 ordering: variable must be in tainted_vars
            # for add_sanitization to take effect).
            if rhs_node is not None and rhs_node.type == "conditional_expression":
                if self.language == Language.C:
                    clamped = self._check_ternary_clamp(rhs_node, state)
                    if clamped:
                        for lhs_name in lhs_names:
                            state.add_sanitization(
                                lhs_name, _SIZE_SANITIZABLE_CATEGORIES
                            )

    def _node_to_var_name(self, node: Any) -> str | None:
        """Extract a variable name from a node.

        Args:
            node: AST node.

        Returns:
            Variable name string or None.
        """
        if node.type == "identifier":
            return node.text.decode("utf-8", errors="replace")
        # Go: qualified identifier
        if node.type in ("qualified_type", "type_identifier"):
            return node.text.decode("utf-8", errors="replace")
        # C-specific: unwrap pointer_declarator to get the actual identifier
        if node.type == "pointer_declarator":
            for child in node.children:
                if child.type == "identifier":
                    return child.text.decode("utf-8", errors="replace")
                # Recursive: pointer to pointer (char **pp)
                if child.type == "pointer_declarator":
                    return self._node_to_var_name(child)
        # C-specific: array subscript -- extract base array name
        if node.type == "subscript_expression":
            for child in node.children:
                if child.type == "identifier":
                    return child.text.decode("utf-8", errors="replace")
        # C-specific: parenthesized expression -- unwrap
        if node.type == "parenthesized_expression":
            for child in node.children:
                result = self._node_to_var_name(child)
                if result:
                    return result
        return None

    def _node_to_comparison_operand(self, node: Any) -> str | None:
        """Extract a comparison operand name from a node.

        Like _node_to_var_name but also accepts number_literal nodes,
        returning the literal text (e.g., "4096"). This is used only
        for comparison extraction in conditional sanitizer recognition.

        A number_literal operand is never tainted (it is a constant),
        so it serves as a valid bound in a comparison like (n > 4096).

        Args:
            node: AST node.

        Returns:
            Variable name or literal string, or None.
        """
        # Try identifier extraction first
        var_name = self._node_to_var_name(node)
        if var_name is not None:
            return var_name
        # Accept number_literal as a bound operand
        if node.type == "number_literal":
            return node.text.decode("utf-8", errors="replace")
        return None

    def _is_rhs_tainted(
        self, node: Any, state: TaintState, binary_op_types: list[str]
    ) -> bool:
        """Check if a RHS expression node contains tainted variables.

        Args:
            node: RHS AST node.
            state: Current taint state.
            binary_op_types: Binary operation node types.

        Returns:
            True if the expression references any tainted variable.
        """
        if node.type == "identifier":
            var_name = node.text.decode("utf-8", errors="replace")
            return state.is_tainted(var_name)

        # Check for source pattern references (e.g., attribute like request.form)
        if node.type in ("attribute", "selector_expression", "member_expression", "field_expression"):
            node_text = node.text.decode("utf-8", errors="replace")
            # Check if any tainted "function" (source pattern) appears in the text
            for tainted_var in state.tainted_vars:
                if tainted_var in node_text:
                    return True

        # Recursively check children
        for child in node.children:
            if self._is_rhs_tainted(child, state, binary_op_types):
                return True

        return False

    def _classify_rhs_transform(
        self, rhs_node: Any, binary_op_types: list[str]
    ) -> str:
        """Classify how a RHS expression propagates taint.

        Args:
            rhs_node: RHS AST node.
            binary_op_types: Binary operation node types.

        Returns:
            Transform description string.
        """
        if rhs_node.type in binary_op_types:
            # Check operator for concatenation
            for child in rhs_node.children:
                if child.type == "+" or (hasattr(child, 'text') and child.text == b"+"):
                    return "concatenation"
            return "binary_operation"

        if rhs_node.type in ("string", "interpreted_string_literal"):
            # Check for f-string interpolation
            for child in rhs_node.children:
                if child.type == "interpolation":
                    return "f-string"
            return "assignment"

        if rhs_node.type == "formatted_string_expression":
            return "f-string"

        if rhs_node.type in ("call", "call_expression"):
            return "function_call"

        # C-specific: type cast propagates taint
        if rhs_node.type == "cast_expression":
            return "type_cast"

        # C-specific: pointer dereference propagates taint
        if rhs_node.type == "pointer_expression":
            return "pointer_dereference"

        # C-specific: array access propagates taint
        if rhs_node.type == "subscript_expression":
            return "array_access"

        return "assignment"

    def _handle_if_sanitizer(
        self,
        if_node: Any,
        state: TaintState,
    ) -> None:
        """Check if an if-statement represents a conditional bounds check.

        Pattern: if (tainted_var > bound) tainted_var = bound;

        If matched, marks tainted_var as sanitized for size-related CWEs.

        Args:
            if_node: The if_statement AST node.
            state: Mutable taint state.
        """
        # Extract condition and body from the if_statement
        condition = None
        body = None
        for child in if_node.children:
            if child.type == "parenthesized_expression":
                condition = child
            elif child.type in ("expression_statement", "compound_statement"):
                body = child

        if condition is None or body is None:
            return

        # Extract the binary comparison from the condition
        cmp_info = self._extract_comparison(condition)
        if cmp_info is None:
            return
        cmp_var, cmp_op, cmp_bound = cmp_info

        # Check if the compared variable is tainted
        if not state.is_tainted(cmp_var):
            return

        # Check if the body reassigns the compared variable to a non-tainted value
        if not self._find_nontainted_reassignment_in_body(body, cmp_var, state):
            return

        # Pattern matches: tainted variable is bounds-checked and reassigned
        state.add_sanitization(cmp_var, _SIZE_SANITIZABLE_CATEGORIES)

    def _extract_comparison(
        self, paren_node: Any
    ) -> tuple[str, str, str] | None:
        """Extract (variable, operator, bound) from a parenthesized comparison.

        Handles: (n > max), (n >= max), (n < max), (n <= max)
        Also handles numeric literal bounds: (n > 4096), (n >= sizeof(buf))
        Also handles the reverse: (max < n) -> returned as-is (left, op, right).

        Args:
            paren_node: A parenthesized_expression AST node.

        Returns:
            Tuple of (left_name, operator, right_name) or None.
        """
        # Unwrap parenthesized_expression
        binary = None
        for child in paren_node.children:
            if child.type == "binary_expression":
                binary = child
                break
        if binary is None:
            return None

        # Extract left, operator, right
        children = list(binary.children)
        if len(children) != 3:
            return None

        left_node, op_node, right_node = children
        op_text = op_node.text.decode("utf-8", errors="replace") if hasattr(op_node, 'text') else ""
        if op_text not in (">", ">=", "<", "<="):
            return None

        left_name = self._node_to_comparison_operand(left_node)
        right_name = self._node_to_comparison_operand(right_node)
        if left_name is None or right_name is None:
            return None

        return (left_name, op_text, right_name)

    def _extract_comparison_from_node(
        self, node: Any
    ) -> tuple[str, str, str] | None:
        """Extract comparison info, handling both parenthesized and bare binary_expression.

        Args:
            node: A parenthesized_expression or binary_expression AST node.

        Returns:
            Tuple of (left_name, operator, right_name) or None.
        """
        if node.type == "parenthesized_expression":
            return self._extract_comparison(node)
        elif node.type == "binary_expression":
            children = list(node.children)
            if len(children) != 3:
                return None
            left, op, right = children
            op_text = op.text.decode("utf-8", errors="replace") if hasattr(op, 'text') else ""
            if op_text not in (">", ">=", "<", "<="):
                return None
            left_name = self._node_to_comparison_operand(left)
            right_name = self._node_to_comparison_operand(right)
            if left_name and right_name:
                return (left_name, op_text, right_name)
        return None

    def _find_nontainted_reassignment_in_body(
        self, body_node: Any, var_name: str, state: TaintState
    ) -> bool:
        """Check if the body of an if-statement reassigns the given variable
        to a non-tainted value.

        Handles both:
          - expression_statement { assignment_expression { identifier = ... } }
          - compound_statement { expression_statement { assignment_expression ... } }

        Args:
            body_node: The if-body AST node (expression_statement or compound_statement).
            var_name: The variable name to look for on the LHS.
            state: Current taint state (used to check RHS taintedness).

        Returns:
            True if the variable is reassigned to a non-tainted value.
        """
        def check_node(node: Any) -> bool:
            if node.type == "assignment_expression":
                lhs = self._extract_lhs_name(node)
                if lhs == var_name:
                    # Verify the RHS is not tainted
                    rhs = self._extract_assignment_rhs(node)
                    if rhs is not None and not self._is_rhs_tainted(
                        rhs, state, []
                    ):
                        return True
                    # RHS is tainted or could not be extracted -- not a valid clamp
                    return False
            for child in node.children:
                if check_node(child):
                    return True
            return False

        return check_node(body_node)

    def _extract_assignment_rhs(self, assign_node: Any) -> Any | None:
        """Extract the RHS node from an assignment expression.

        For `n = max`, returns the node for `max`.
        For `n = max - 1`, returns the node for `max - 1`.

        Args:
            assign_node: An assignment_expression AST node.

        Returns:
            The RHS AST node, or None if it cannot be extracted.
        """
        children = list(assign_node.children)
        # assignment_expression children: [lhs, "=", rhs]
        for i, child in enumerate(children):
            if hasattr(child, 'text') and child.type not in (
                "identifier", "pointer_declarator", "subscript_expression",
                "field_expression",
            ):
                text = child.text.decode("utf-8", errors="replace") if hasattr(child, 'text') else ""
                if text in ("=", "+=", "-=", "*=", "/="):
                    # Return the node after the operator
                    if i + 1 < len(children):
                        return children[i + 1]
        return None

    def _check_ternary_clamp(
        self, cond_expr: Any, state: TaintState
    ) -> bool:
        """Check if a conditional_expression is a min/max clamp pattern.

        Patterns (clamp to upper bound):
            (tainted > bound) ? bound : tainted  -> clamp: true branch is bound
            (tainted < bound) ? tainted : bound   -> clamp: false branch is bound

        Anti-patterns (NOT a clamp -- these are MAX operations):
            (tainted > bound) ? tainted : bound  -> MAX: true branch is tainted
            (tainted < bound) ? bound : tainted   -> MAX: false branch is tainted

        The key invariant: in the "overflow" branch (when the tainted variable
        exceeds the bound), the result must be the bound, not the tainted variable.

        Args:
            cond_expr: A conditional_expression AST node.
            state: Current taint state.

        Returns:
            True if this is a bounds clamp involving a tainted variable.
        """
        children = list(cond_expr.children)
        # conditional_expression children:
        # [condition, "?", true_branch, ":", false_branch]
        # condition may be parenthesized_expression or binary_expression

        # Find semantic children (skip punctuation)
        semantic = [c for c in children if c.type not in ("?", ":")]
        if len(semantic) != 3:
            return False
        condition, true_branch, false_branch = semantic

        # Extract comparison from condition
        cmp_info = self._extract_comparison_from_node(condition)
        if cmp_info is None:
            return False
        cmp_var, cmp_op, cmp_bound = cmp_info

        # Determine which operand is tainted
        var_is_tainted = state.is_tainted(cmp_var)
        bound_is_tainted = state.is_tainted(cmp_bound)

        # Exactly one must be tainted for this to be a meaningful clamp
        if not var_is_tainted and not bound_is_tainted:
            return False
        # If both are tainted, we cannot determine which is the bound
        if var_is_tainted and bound_is_tainted:
            return False

        # Identify the tainted operand and the bound operand
        tainted_name = cmp_var if var_is_tainted else cmp_bound
        bound_name = cmp_bound if var_is_tainted else cmp_var

        # Get branch values
        true_name = self._node_to_comparison_operand(true_branch)
        false_name = self._node_to_comparison_operand(false_branch)

        if true_name is None or false_name is None:
            return False

        # Verify branch ordering is consistent with a clamp, not a MAX.
        #
        # For (tainted > bound) or (tainted >= bound):
        #   Clamp: true_branch=bound, false_branch=tainted
        #   MAX:   true_branch=tainted, false_branch=bound  (NOT a clamp)
        #
        # For (tainted < bound) or (tainted <= bound):
        #   Clamp: true_branch=tainted, false_branch=bound
        #   MAX:   true_branch=bound, false_branch=tainted  (NOT a clamp)
        #
        # If the tainted variable is on the RIGHT of the comparison
        # (bound < tainted), the operator sense is inverted.
        if var_is_tainted:
            # tainted is on the left: (tainted OP bound)
            if cmp_op in (">", ">="):
                # Overflow branch is "then". Then-branch must be bound.
                return true_name == bound_name and false_name == tainted_name
            else:  # < or <=
                # Overflow branch is "else". Else-branch must be bound.
                return true_name == tainted_name and false_name == bound_name
        else:
            # tainted is on the right: (bound OP tainted)
            # (bound > tainted) means tainted is small -- this is the
            # "underflow" direction. (bound < tainted) means tainted exceeds.
            if cmp_op in ("<", "<="):
                # bound < tainted: overflow branch is "then". Then = bound.
                return true_name == bound_name and false_name == tainted_name
            else:  # > or >=
                # bound > tainted: tainted is small. Then = tainted, else = bound.
                return true_name == tainted_name and false_name == bound_name

    def _check_sink_reachability(
        self,
        func_node: Any,
        sink: Sink,
        state: TaintState,
        file_path: str,
    ) -> tuple[bool, list[TaintStep], str | None]:
        """Check if any tainted variable reaches the sink as an argument.

        Args:
            func_node: Function AST node.
            sink: Sink to check.
            state: Current taint state.
            file_path: File path.

        Returns:
            Tuple of (is_reachable, path_steps, sanitizer_name).
        """
        # Find the AST node at the sink's line
        sink_node = self._find_node_at_line(func_node, sink.line)
        if sink_node is None:
            # No AST node found at sink line -- cannot confirm taint reaches sink.
            # Returning True here would produce false positives (any tainted var
            # in the function would be flagged regardless of whether it flows to
            # the sink arguments). Return False conservatively.
            return False, [], None

        # Primary path: structured argument analysis
        tainted_arg, sanitizer = self._check_args_for_taint(
            sink_node, state, sink.category
        )

        if tainted_arg is not None:
            # Check for conditional sanitization from taint state
            if sanitizer is None and state.is_sanitized_for(tainted_arg, sink.category):
                sanitizer = "conditional_bounds_check"

            sink_step = TaintStep(
                file=file_path,
                line=sink.line,
                column=sink.column,
                variable=tainted_arg,
                transform="sink_argument",
            )
            return True, [sink_step], sanitizer

        # Fallback path: substring match for direct source patterns in args.
        # This path MUST also check conditional sanitization (F-1 fix).
        #
        # Skip for format_string sinks: the structured path already checked the
        # format argument position specifically.  The substring scan would fire
        # whenever a tainted variable appears anywhere in the call text (e.g.
        # printf("literal %s\n", tainted_var)), which is the false positive class
        # this check is designed to prevent.
        if sink.category == "format_string":
            return False, [], None
        for tainted_var in state.tainted_vars:
            node_text = sink_node.text.decode("utf-8", errors="replace") if sink_node else ""
            if tainted_var in node_text:
                # Check conditional sanitization on the fallback path
                fallback_sanitizer = None
                if state.is_sanitized_for(tainted_var, sink.category):
                    fallback_sanitizer = "conditional_bounds_check"

                sink_step = TaintStep(
                    file=file_path,
                    line=sink.line,
                    column=sink.column,
                    variable=tainted_var,
                    transform="sink_argument",
                )
                return True, [sink_step], fallback_sanitizer

        return False, [], None

    def _find_node_at_line(self, root_node: Any, line: int) -> Any | None:
        """Find a relevant AST node at or near the given line.

        Args:
            root_node: Root node to search from.
            line: Target line number (1-based).

        Returns:
            Matching AST node or None.
        """
        # We want a call or statement node at this line
        call_types = self.node_types.get("call", ["call"])
        target_types = set(call_types + ["expression_statement"])

        def find_at_line(node: Any) -> Any | None:
            node_line = node.start_point[0] + 1
            if node_line == line and node.type in target_types:
                return node
            if node_line > line + 2:
                return None  # Past the target line
            for child in node.children:
                result = find_at_line(child)
                if result is not None:
                    return result
            return None

        return find_at_line(root_node)

    def _get_call_function_name(self, call_node: Any) -> str | None:
        """Return the function name identifier from a call_expression node."""
        for child in call_node.children:
            if child.type == "identifier":
                return child.text.decode("utf-8", errors="replace")
        return None

    def _check_args_for_taint(
        self,
        call_node: Any,
        state: TaintState,
        sink_category: str,
    ) -> tuple[str | None, str | None]:
        """Check if any arguments to a call are tainted.

        Args:
            call_node: Call AST node.
            state: Current taint state.
            sink_category: Sink category for sanitizer lookup.

        Returns:
            Tuple of (tainted_var_name, sanitizer_name) or (None, None).
        """
        # Find argument list node
        arg_types = self.node_types.get("argument_list", ["argument_list"])

        def find_args(node: Any) -> Any | None:
            if node.type in arg_types:
                return node
            for child in node.children:
                result = find_args(child)
                if result:
                    return result
            return None

        args_node = find_args(call_node)
        if args_node is None:
            return None, None

        # Check sanitizers
        sink_sanitizers = self.registry.get_sanitizers_for(sink_category)

        def check_sanitizer(node: Any) -> str | None:
            node_text = node.text.decode("utf-8", errors="replace")
            for san in sink_sanitizers:
                if san.pattern in node_text:
                    return san.pattern
            return None

        # Check each argument
        def is_arg_tainted(node: Any) -> tuple[str | None, str | None]:
            if node.type == "identifier":
                var_name = node.text.decode("utf-8", errors="replace")
                if state.is_tainted(var_name):
                    # Check if this var passes through a sanitizer
                    san = check_sanitizer(node.parent) if node.parent else None
                    return var_name, san
            # Check for direct attribute access that matches a tainted pattern
            node_text = node.text.decode("utf-8", errors="replace")
            for tainted_var in state.tainted_vars:
                if tainted_var in node_text:
                    san = check_sanitizer(node)
                    return tainted_var, san
            for child in node.children:
                result, san = is_arg_tainted(child)
                if result:
                    return result, san
            return None, None

        if sink_category == "format_string":
            # For format string sinks, only taint in the FORMAT argument position
            # counts as a vulnerability.  Tainted data in subsequent %-substitution
            # positions (e.g. printf("literal %s\n", argv[1])) is not exploitable
            # as a format string attack and must not generate a finding.
            fn_name = self._get_call_function_name(call_node)
            fmt_idx = _FORMAT_STRING_ARG_INDEX.get(fn_name or "", 0)
            named_args = [c for c in args_node.children if c.is_named]
            if fmt_idx < len(named_args):
                return is_arg_tainted(named_args[fmt_idx])
            return None, None

        return is_arg_tainted(args_node)


def find_taint_paths(
    tree: Any,
    sources: list[Source],
    sinks: list[Sink],
    language: Language,
    registry: Registry,
    file_path: str,
) -> list[tuple[Source, Sink, TaintPath]]:
    """Convenience function to find taint paths.

    Args:
        tree: tree_sitter.Tree.
        sources: Sources in this file.
        sinks: Sinks in this file.
        language: Programming language.
        registry: Language registry.
        file_path: Path to the source file.

    Returns:
        List of (Source, Sink, TaintPath) tuples.
    """
    engine = TaintEngine(language=language, registry=registry)
    return engine.find_taint_paths(tree, sources, sinks, file_path)
