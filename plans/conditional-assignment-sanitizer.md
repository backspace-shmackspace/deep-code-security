# Plan: Conditional Assignment Sanitizer for C Hunter

## Status: DRAFT

## Goals

1. Reduce false positives from the C hunter when a tainted variable is bounds-checked via a conditional assignment pattern (`if (n > max) n = max;` or ternary `n = (n > max) ? max : n;`) before reaching a CWE-119/CWE-120/CWE-190 sink.
2. Model these conditional assignments as **sanitizers** within the taint tracker, so that a bounds-clamped variable is marked as sanitized for size-related sink categories.
3. Achieve a measurable false positive reduction on OpenSSL 3.5.5 (from ~95% to a target of <80% on the conditional-assignment false positive class specifically). This target applies only when **all** source-to-sink taint paths for a given sink are conditionally sanitized. When a sink has both sanitized and unsanitized paths, deduplication correctly preserves the unsanitized finding (see Deduplication Interaction).
4. Preserve detection of genuinely vulnerable patterns where bounds checking does NOT occur.

## Non-Goals

- **Interprocedural analysis.** This plan does not add cross-function bounds-check tracking. If a bounds check happens in a different function, it is not modeled.
- **General control-flow-sensitive taint analysis.** We do not build a full CFG or track branch conditions generically. We specifically model the "conditional clamp" idiom.
- **Sanitizer for non-size sinks.** Conditional bounds checks sanitize size-related CWEs (CWE-119, CWE-120, CWE-190) only. A bounds check on a string variable used in a `system()` call (CWE-78) does NOT sanitize command injection -- length clamping is irrelevant to injection content.
- **Python/Go conditional sanitizers.** These languages rarely use this pattern for the same CWE classes. Python/Go changes are deferred.
- **Registry YAML changes.** The conditional assignment sanitizer is a taint-tracker concept (code-level pattern matching), not a registry-level sanitizer entry. Existing registry sanitizers (e.g., `strncpy`, `snprintf`) are unchanged.
- **Complex dataflow patterns.** We do not model: (a) bounds checks via function calls (e.g., `clamp(n, 0, max)`), (b) assertions (`assert(n <= max)`), (c) early returns (`if (n > max) return -1;`). These are deferred to a future increment.

## Assumptions

1. The taint tracker already performs a single forward pass through AST nodes in `_propagate_taint` (line 349-373 of `taint_tracker.py`). The current `visit()` function only processes assignment nodes and skips all other node types, including `if_statement`.
2. The `TaintState` dataclass (line 53-88) tracks tainted variables as a flat set with no concept of "partially sanitized" or "sanitized for specific CWE categories." This plan must extend `TaintState` to support per-variable, per-category sanitization.
3. The `_check_sink_reachability` method (line 565-622) returns a `sanitizer_name` string, which is currently only populated by the registry-based sanitizer lookup in `_check_args_for_taint`. This plan adds a second sanitization pathway via the taint state. The method has **two** reachability paths: a primary path via `_check_args_for_taint` (lines 593-605) and a fallback substring-match path (lines 607-620). Both paths must be patched to check conditional sanitization.
4. Tree-sitter C AST uses `if_statement` for `if (cond) body` and `conditional_expression` for the ternary operator `cond ? a : b`. Both have been verified via AST dumps (see Background).
5. The `TaintPath.sanitized` and `TaintPath.sanitizer` fields (in `models.py`) already flow through the confidence scoring pipeline. When `sanitized=True`, the auditor's `sanitizer_score()` returns 0 (vs 100 for unsanitized), which reduces the confidence score by 25 points (0.25 weight). This existing mechanism is sufficient -- no changes to the auditor are needed.
6. OpenSSL 3.5.5 scan produced 2092 findings across 1652 C files. Deep analysis of ~40 findings revealed ~95% false positive rate, with "conditional assignment clamp not modeled" as the #1 false positive pattern.
7. The `_compute_raw_confidence` method in `orchestrator.py` returns `0.3` for sanitized findings and `0.6`-`0.8` for unsanitized findings. The `_deduplicate_findings` function keeps the highest-confidence finding per `(file, sink_line, cwe)` key. This means sanitized findings are discarded when competing with unsanitized findings at the same sink -- this is correct and intentional (see Deduplication Interaction).
8. The existing `_node_to_var_name` method only handles `identifier`, `qualified_type`, `type_identifier`, `pointer_declarator`, `subscript_expression`, and `parenthesized_expression` node types. It does NOT handle `number_literal` nodes. This plan extends the comparison extractor to accept numeric literals as valid bound operands.

## Proposed Design

### Overview

The design introduces a **conditional sanitization** concept at the taint tracker level. When the forward AST walk encounters an `if_statement` or `conditional_expression` (ternary) that matches a "bounds clamp" pattern, the target variable is marked as sanitized for size-related CWE categories in the `TaintState`. Later, when `_check_sink_reachability` evaluates whether a tainted variable reaches a sink, it checks whether the variable has been conditionally sanitized for the sink's CWE category. If so, the finding is marked `sanitized=True` with `sanitizer="conditional_bounds_check"`.

Sanitization state is cleared when a variable is re-tainted from a new source, preventing stale sanitization from persisting across reassignments.

### Pattern Recognition

The following C idioms are recognized as conditional bounds checks:

**Pattern 1: If-statement clamp**
```c
if (n > max) n = max;         // clamp-above
if (n > max) { n = max; }     // same, with braces
if (n >= max) n = max - 1;    // clamp-above variant
if (n > 4096) n = 4096;       // numeric literal bound
```

AST structure:
```
if_statement
  parenthesized_expression
    binary_expression [> or >= or < or <=]
      identifier (clamped_var)
      identifier | number_literal (bound)
  expression_statement | compound_statement
    assignment_expression
      identifier (clamped_var)  -- MUST match the condition variable
      =
      identifier | number_literal | ... (bound or expression involving bound)
```

Recognition rule: An `if_statement` whose condition is a `binary_expression` with a comparison operator (`>`, `>=`, `<`, `<=`), where one operand is a tainted variable `V` and the other is a bound (identifier or numeric literal), and whose body contains an `assignment_expression` that reassigns `V` to a non-tainted value, constitutes a conditional sanitizer for `V`.

**Pattern 2: Ternary clamp**
```c
n = (n > max) ? max : n;       // clamp-above
int m = (n < max) ? n : max;   // min() idiom
i = (i > num) ? num : i;       // OpenSSL pem_lib.c pattern
n = (n > 4096) ? 4096 : n;     // numeric literal bound
```

AST structure:
```
assignment_expression | init_declarator
  identifier (target_var)
  =
  conditional_expression
    binary_expression [comparison]
      identifier (clamped_var)
      identifier | number_literal (bound)
    ?
    identifier | number_literal (true_branch)
    :
    identifier | number_literal (false_branch)
```

Recognition rule: An assignment whose RHS is a `conditional_expression` with a comparison condition involving a tainted variable, where the branch ordering is semantically consistent with a clamp (see Branch Ordering Verification), constitutes a conditional sanitizer for the LHS variable.

**Branch Ordering Verification (F-2 fix):** The ternary recognizer must verify that the "then" branch contains the non-tainted bound (not the tainted variable) when the operator is `>` or `>=`. Without this check, `n = (n > limit) ? n : limit` (a MAX operation that preserves the tainted unbounded value) would be incorrectly marked as sanitized. The rule is:

| Operator | Required "then" branch | Required "else" branch | Semantic |
|---|---|---|---|
| `>` or `>=` | bound (non-tainted) | tainted variable | clamp to upper bound |
| `<` or `<=` | tainted variable | bound (non-tainted) | clamp to upper bound (inverted) |

The key invariant is: for the expression to be a clamp, the result in the "overflow" branch (when the comparison is true for `>` / `>=`) must be the bound, not the tainted variable.

**Pattern 3: Guard-branch (sink inside conditional)**
```c
if (src_len <= dst_len) {
    memcpy(dst, src, src_len);  // only reached when bounded
}
```

This pattern is architecturally harder because it requires the taint tracker to understand that the sink is only reachable when the guard condition holds. The current single-pass forward walk does not track control flow. **This pattern is deferred** to a future increment that adds basic block awareness. However, Patterns 1 and 2 (which reassign the variable before the sink) will catch most of the OpenSSL false positives, because the dominant idiom is to clamp first, then use the clamped value.

### CWE Categories Sanitized

Conditional bounds checks sanitize the following sink categories:

| Sink Category | CWE | Rationale |
|---|---|---|
| `buffer_overflow` | CWE-120 | Size argument bounds-checked prevents buffer overread/overwrite |
| `memory_corruption` | CWE-119 | Size argument bounds-checked prevents out-of-bounds memory operation |
| `integer_overflow` | CWE-190 | Value clamped to known range prevents overflow in allocation size |

Conditional bounds checks do NOT sanitize:

| Sink Category | CWE | Rationale |
|---|---|---|
| `command_injection` | CWE-78 | Length clamping does not prevent injection content |
| `format_string` | CWE-134 | Length clamping does not prevent format string abuse |
| `path_traversal` | CWE-22 | Length clamping does not prevent directory traversal |
| `dangerous_function` | CWE-676 | Function is dangerous regardless of input bounds |

### Deduplication Interaction

The `_deduplicate_findings` function in `orchestrator.py` groups findings by `(file, sink_line, cwe)` and keeps the finding with the **highest** `raw_confidence`. Since `_compute_raw_confidence` returns `0.3` for sanitized findings and `0.6`-`0.8` for unsanitized findings, when a sink has both sanitized and unsanitized taint paths, the unsanitized finding wins deduplication. This is **correct and intentional**: the sink IS reachable via an unbounded path, so the finding should remain unsanitized.

The false positive reduction from this plan applies only to sinks where **all** taint paths are conditionally sanitized. In this case, there is no competing unsanitized finding, and the sanitized finding (with its lower confidence) survives deduplication.

Analysis of the OpenSSL false positive examples (passphrase.c `src_len`, pem_lib.c `i`, params.c size variables) confirms that each has a single source flowing to the sink, with the clamp in between. These cases have no competing unsanitized paths and will benefit from this plan.

No changes to `_deduplicate_findings` are needed. The deduplication behavior is correct for both the single-path and multi-path cases.

### Data Model Changes

#### `TaintState` Extension

Add a `sanitized_vars` dictionary to `TaintState` that tracks per-variable sanitization keyed by sink category. Modify `add_taint` to clear stale sanitization when a variable is re-tainted:

```python
@dataclass
class TaintState:
    tainted_vars: set[str] = field(default_factory=set)
    taint_steps: dict[str, TaintStep] = field(default_factory=dict)
    # NEW: variables that have been conditionally sanitized
    # Maps variable name -> set of sink categories that are neutralized
    sanitized_vars: dict[str, set[str]] = field(default_factory=dict)

    def add_taint(self, var_name: str, step: TaintStep) -> None:
        """Mark a variable as tainted.

        Clears any prior conditional sanitization for the variable,
        because re-assignment from a tainted source invalidates the
        previous bounds check.
        """
        self.tainted_vars.add(var_name)
        self.taint_steps[var_name] = step
        # Clear stale sanitization: re-taint invalidates prior bounds check
        self.sanitized_vars.pop(var_name, None)

    def add_sanitization(self, var_name: str, categories: set[str]) -> None:
        """Mark a tainted variable as conditionally sanitized for specific categories."""
        if var_name in self.tainted_vars:
            existing = self.sanitized_vars.get(var_name, set())
            self.sanitized_vars[var_name] = existing | categories

    def is_sanitized_for(self, var_name: str, category: str) -> bool:
        """Check if a variable is sanitized for a specific sink category."""
        return category in self.sanitized_vars.get(var_name, set())

    def copy(self) -> TaintState:
        new_state = TaintState()
        new_state.tainted_vars = self.tainted_vars.copy()
        new_state.taint_steps = self.taint_steps.copy()
        new_state.sanitized_vars = {
            k: v.copy() for k, v in self.sanitized_vars.items()
        }
        return new_state
```

The variable remains in `tainted_vars` (it IS still tainted -- an attacker controlled its original value). The `sanitized_vars` annotation records that a bounds check has been applied, which is relevant only for size-related sinks.

The `add_taint` modification (clearing `sanitized_vars`) ensures that re-assignment from a tainted source after sanitization correctly invalidates the prior bounds check:

```c
int n = atoi(argv[1]);
if (n > 64) n = 64;        // sanitized
n = atoi(argv[2]);          // re-tainted: sanitization cleared
memcpy(dst, src, n);        // correctly flagged as unsanitized
```

#### No Changes to Pydantic Models

`TaintPath.sanitized` and `TaintPath.sanitizer` are already sufficient. The sanitizer name for this pattern will be `"conditional_bounds_check"`. No new Pydantic fields are needed.

### Taint Tracker Changes

#### `_propagate_taint` Enhancement

The `visit()` function inside `_propagate_taint` currently processes only assignment nodes. It must be extended to also process `if_statement` nodes and to detect conditional sanitization in `conditional_expression` RHS values during assignment handling.

```python
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
```

For ternary expressions, the detection happens inside `_handle_assignment` when the RHS is a `conditional_expression`.

#### New Method: `_handle_if_sanitizer`

```python
# Categories that conditional bounds checks can sanitize
_SIZE_SANITIZABLE_CATEGORIES: frozenset[str] = frozenset({
    "buffer_overflow",   # CWE-120
    "memory_corruption", # CWE-119
    "integer_overflow",  # CWE-190
})

def _handle_if_sanitizer(
    self,
    if_node: Any,
    state: TaintState,
) -> None:
    """Check if an if-statement represents a conditional bounds check.

    Pattern: if (tainted_var > bound) tainted_var = bound;

    If matched, marks tainted_var as sanitized for size-related CWEs.
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
```

#### New Method: `_extract_comparison`

This method accepts both identifier and numeric literal operands. The bound operand may be a `number_literal` node, which is common in real-world C code (`if (n > 4096) n = 4096;`).

```python
def _extract_comparison(
    self, paren_node: Any
) -> tuple[str, str, str] | None:
    """Extract (variable, operator, bound) from a parenthesized comparison.

    Handles: (n > max), (n >= max), (n < max), (n <= max)
    Also handles numeric literal bounds: (n > 4096), (n >= sizeof(buf))
    Also handles the reverse: (max < n) -> (n, ">", max)

    Returns:
        Tuple of (variable_name, operator, bound_name_or_literal) or None.
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
```

#### New Method: `_node_to_comparison_operand`

This is a superset of `_node_to_var_name` that also accepts `number_literal` nodes. It is used exclusively by the comparison extractor to handle numeric bounds. It does NOT modify `_node_to_var_name`, which continues to return `None` for literals (taint tracking should never treat a literal as a variable name).

```python
def _node_to_comparison_operand(self, node: Any) -> str | None:
    """Extract a comparison operand name from a node.

    Like _node_to_var_name but also accepts number_literal nodes,
    returning the literal text (e.g., "4096"). This is used only
    for comparison extraction in conditional sanitizer recognition.

    A number_literal operand is never tainted (it is a constant),
    so it serves as a valid bound in a comparison like (n > 4096).
    """
    # Try identifier extraction first
    var_name = self._node_to_var_name(node)
    if var_name is not None:
        return var_name
    # Accept number_literal as a bound operand
    if node.type == "number_literal":
        return node.text.decode("utf-8", errors="replace")
    return None
```

#### New Method: `_find_nontainted_reassignment_in_body`

This method verifies both that the target variable is reassigned AND that the RHS is not tainted. This prevents false negatives from patterns like `if (n > other_tainted) n = other_tainted;` where the reassignment value is itself attacker-controlled.

```python
def _find_nontainted_reassignment_in_body(
    self, body_node: Any, var_name: str, state: TaintState
) -> bool:
    """Check if the body of an if-statement reassigns the given variable
    to a non-tainted value.

    Handles both:
      - expression_statement { assignment_expression { identifier = ... } }
      - compound_statement { expression_statement { assignment_expression ... } }

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
```

#### Ternary Handling in `_handle_assignment`

When the RHS of an assignment is a `conditional_expression`, check if it represents a min/max clamp:

```python
# Inside _handle_assignment, after determining rhs_tainted is True:
if rhs_node is not None and rhs_node.type == "conditional_expression":
    if self.language == Language.C:
        clamped = self._check_ternary_clamp(rhs_node, state)
        if clamped:
            for lhs_name in lhs_names:
                state.add_sanitization(
                    lhs_name, _SIZE_SANITIZABLE_CATEGORIES
                )
```

Note on sanitization target asymmetry: Pattern 1 (if-statement) sanitizes the condition variable `cmp_var` because it is reassigned in-place in the body. Pattern 2 (ternary) sanitizes the assignment target `lhs_name` because the ternary expression produces a new bounded value assigned to the LHS. Both are correct: the sanitized variable is always the one that holds the clamped result.

#### New Method: `_check_ternary_clamp`

This method verifies branch ordering relative to the comparison operator to distinguish clamps from MAX operations.

```python
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

    Returns:
        True if this is a bounds clamp involving a tainted variable.
    """
    children = list(cond_expr.children)
    # conditional_expression children:
    # [condition, "?", true_branch, ":", false_branch]
    # condition may be parenthesized_expression or binary_expression
    condition = None
    true_branch = None
    false_branch = None

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

    return False


def _extract_comparison_from_node(
    self, node: Any
) -> tuple[str, str, str] | None:
    """Extract comparison info, handling both parenthesized and bare binary_expression."""
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
```

#### `_check_sink_reachability` Enhancement

Add a check for conditional sanitization from the taint state in **both** reachability paths -- the primary `_check_args_for_taint` path AND the fallback substring-match path. The original plan only patched the primary path, leaving the fallback path (lines 607-620 of `taint_tracker.py`) to unconditionally return `sanitizer=None`, silently bypassing the conditional sanitization feature.

```python
def _check_sink_reachability(
    self,
    func_node: Any,
    sink: Sink,
    state: TaintState,
    file_path: str,
) -> tuple[bool, list[TaintStep], str | None]:
    # ... existing preamble ...

    # Primary path: structured argument analysis
    tainted_arg, sanitizer = self._check_args_for_taint(
        sink_node, state, sink.category
    )

    if tainted_arg is not None:
        # Check for conditional sanitization from taint state
        if sanitizer is None and state.is_sanitized_for(tainted_arg, sink.category):
            sanitizer = "conditional_bounds_check"

        sink_step = TaintStep(...)
        return True, [sink_step], sanitizer

    # Fallback path: substring match for direct source patterns in args.
    # This path MUST also check conditional sanitization (F-1 fix).
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
```

This integrates with the existing sanitizer flow. The finding is still emitted (it IS a real taint path), but it is marked as `sanitized=True` with `sanitizer="conditional_bounds_check"`, which reduces its confidence score through the existing scoring pipeline. Both reachability paths now consistently apply conditional sanitization.

### Confidence Score Impact

With `sanitized=True`, the existing `sanitizer_score()` in `confidence.py` returns 0 instead of 100, reducing the base score by 25 points (0.25 * 100 = 25). For a typical finding:

| Component | Unsanitized | Sanitized |
|---|---|---|
| Taint (45%) | 45 (3+ steps -> 100 * 0.45) | 45 |
| Sanitizer (25%) | 25 (100 * 0.25) | 0 (0 * 0.25) |
| CWE baseline (20%) | 15 (severity "high" fallback -> 75 * 0.20) | 15 |
| **Base total** | **85** | **60** |
| Status | confirmed | likely |

This means conditionally-sanitized findings drop from "confirmed" to "likely" status, accurately reflecting reduced exploitability. They are not suppressed entirely -- the bounds check may be incorrect, insufficient, or bypassable.

## Interfaces/Schema Changes

### TaintState (dataclass, not Pydantic)

New field: `sanitized_vars: dict[str, set[str]]`
New methods: `add_sanitization()`, `is_sanitized_for()`
Modified methods: `add_taint()` (clears stale sanitization), `copy()` (must deep-copy `sanitized_vars`)

### TaintEngine (class)

New methods:
- `_handle_if_sanitizer(if_node, state)` -- Pattern 1 recognition
- `_extract_comparison(paren_node)` -- Extract comparison from parenthesized condition
- `_extract_comparison_from_node(node)` -- Handle both parenthesized and bare binary_expression
- `_node_to_comparison_operand(node)` -- Like `_node_to_var_name` but also accepts `number_literal`
- `_find_nontainted_reassignment_in_body(body_node, var_name, state)` -- Find non-tainted reassignment in if body
- `_extract_assignment_rhs(assign_node)` -- Extract RHS node from assignment expression
- `_check_ternary_clamp(cond_expr, state)` -- Pattern 2 recognition with branch ordering verification

Modified methods:
- `_propagate_taint()` -- Process `if_statement` nodes
- `_handle_assignment()` -- Detect ternary clamp in RHS
- `_check_sink_reachability()` -- Check conditional sanitization in **both** the primary and fallback reachability paths

### No Pydantic Model Changes

`TaintPath.sanitized` and `TaintPath.sanitizer` are used as-is.

### No Registry Changes

The conditional assignment sanitizer is a code-level pattern in the taint tracker, not a registry entry.

### No CLI/MCP Changes

The pipeline is unchanged. Findings with `sanitized=True` and `sanitizer="conditional_bounds_check"` flow through existing output formatters unchanged.

## Data Migration

None. No persistent data formats change.

## Rollout Plan

1. **Phase 1: TaintState extension** -- Add `sanitized_vars`, `add_sanitization()`, `is_sanitized_for()`, modify `add_taint()` to clear stale sanitization, and update `copy()`. This is a backward-compatible additive change (the `add_taint` modification only adds a `.pop()` call for a field that does not yet exist in production, so it is safe to apply first).

2. **Phase 2: Pattern recognition** -- Implement `_handle_if_sanitizer`, `_extract_comparison`, `_node_to_comparison_operand`, `_find_nontainted_reassignment_in_body`, `_extract_assignment_rhs`, `_check_ternary_clamp` (with branch ordering verification), and `_extract_comparison_from_node`. Wire into `_propagate_taint` and `_handle_assignment`.

3. **Phase 3: Sink reachability integration** -- Modify `_check_sink_reachability` to check conditional sanitization from taint state in **both** the primary path (after `_check_args_for_taint`) and the fallback substring-match path. This connects the pattern recognition to the finding output.

4. **Phase 4: Test fixtures and tests** -- Create safe-sample fixture files, write unit tests for pattern recognition, and write end-to-end tests demonstrating false positive reduction.

5. **Phase 5: CLAUDE.md update** -- Document the conditional assignment sanitizer in Known Limitations and update the c.yaml registry comments.

All phases merge as a single commit.

## Risks

### 1. False Negatives from Over-Sanitization (Medium)

**Risk:** The pattern matcher may incorrectly mark a variable as sanitized when the bounds check is insufficient. For example:
```c
if (n > INT_MAX) n = INT_MAX;  // "bounds check" but INT_MAX is too large
memcpy(dst, src, n);           // still vulnerable if dst is small
```

**Mitigation:** The design deliberately marks the finding as `sanitized=True` rather than suppressing it. Sanitized findings still appear in output with reduced confidence ("likely" instead of "confirmed"). Users and the auditor can evaluate them. The approach is conservative: we reduce noise without hiding findings.

### 2. Pattern Coverage Gaps (Medium)

**Risk:** The recognized patterns (if-assign and ternary clamp) may not cover all idioms used in real C codebases. For example:
- `n = MIN(n, max);` (macro call -- not recognized)
- `if (n > max) return -1;` (early return -- not recognized)
- `n &= 0xFF;` (bitwise mask -- not recognized)

**Mitigation:** This plan targets the #1 false positive pattern from the OpenSSL analysis. The two patterns (if-assign clamp and ternary clamp) cover the specific examples cited in passphrase.c, pem_lib.c, and params.c. Numeric literal bounds (e.g., `if (n > 4096) n = 4096;`) are now supported via `_node_to_comparison_operand`. Additional patterns can be added incrementally in future plans. The architecture (per-variable, per-category sanitization in TaintState) supports extension without redesign.

### 3. AST Structure Variations (Low)

**Risk:** The tree-sitter C grammar may have edge cases where the AST structure differs from what the pattern matcher expects (e.g., nested parentheses, macro-expanded conditions, comma operators in conditions).

**Mitigation:** The pattern matcher uses defensive coding: it returns early (no sanitization applied) if the AST structure does not exactly match the expected pattern. This means unrecognized variants produce false positives (the existing behavior) rather than false negatives. The risk is limited to missed sanitization opportunities, not incorrect sanitization.

### 4. Performance Impact on Large Codebases (Low)

**Risk:** Processing `if_statement` nodes in `_propagate_taint` adds work to the forward pass. OpenSSL has many if statements.

**Mitigation:** The added work is O(1) per if-statement: extract condition, check if any operand is tainted (set lookup), optionally check body for reassignment. The existing forward pass already visits every AST node. The incremental cost is negligible compared to tree-sitter query execution (the actual bottleneck).

### 5. C-Only Implementation (Low)

**Risk:** Python and Go codebases do not benefit from this change.

**Mitigation:** The conditional bounds-check false positive pattern is specific to C's manual memory management (memcpy, malloc with explicit sizes). Python and Go have runtime bounds checking and do not produce CWE-119/CWE-120/CWE-190 findings. The C-only guard (`if self.language == Language.C`) is appropriate.

### 6. Sanitization State Invalidation (Low)

**Risk:** A variable sanitized by a conditional bounds check is subsequently re-assigned from a tainted source. If the stale sanitization is not cleared, the variable would be incorrectly treated as sanitized at a downstream sink.

**Mitigation:** The `add_taint()` method clears `sanitized_vars` entries when a variable is re-tainted (`self.sanitized_vars.pop(var_name, None)`). This ensures that re-assignment from a new tainted source invalidates prior sanitization. A dedicated test case (`test_retaint_after_sanitize_clears_sanitization`) verifies this behavior.

## Test Plan

### Test Command

```bash
make test-hunter
```

For a focused run of just the new and modified tests:

```bash
uv run pytest tests/test_hunter/test_taint_c_paths.py tests/test_hunter/test_taint_tracker.py -v
```

For the full suite (must remain at 90%+ coverage):

```bash
make test
```

### New Test Class: `TestConditionalSanitizer` (in `tests/test_hunter/test_taint_c_paths.py`)

1. **`test_if_clamp_sanitizes_memcpy`** -- Parse the OpenSSL passphrase.c pattern:
   ```c
   void copy(char *dst, int dst_size, char *src) {
       int src_len = strlen(src);
       if (src_len > dst_size) src_len = dst_size;
       memcpy(dst, src, src_len);
   }
   ```
   With `src_len` seeded as tainted: assert `state.is_sanitized_for("src_len", "memory_corruption")` is True.

2. **`test_ternary_clamp_sanitizes`** -- Parse the pem_lib.c pattern:
   ```c
   void copy_data(char *buf, int num, char *userdata) {
       int i = strlen(userdata);
       i = (i > num) ? num : i;
       memcpy(buf, userdata, i);
   }
   ```
   With `i` seeded as tainted: assert sanitized for `memory_corruption`.

3. **`test_ternary_max_not_sanitized`** -- Verify that a MAX pattern (F-2 anti-pattern) is NOT recognized as a clamp:
   ```c
   void bad_max(char *buf, int num, char *userdata) {
       int i = strlen(userdata);
       i = (i > num) ? i : num;
       memcpy(buf, userdata, i);
   }
   ```
   The ternary `(i > num) ? i : num` is a MAX operation (preserves the larger/tainted value in the overflow branch). Assert that the finding is NOT sanitized.

4. **`test_if_clamp_no_sanitize_for_command_injection`** -- Verify that bounds-checking does NOT sanitize command injection:
   ```c
   void run(int argc, char *argv[]) {
       char *cmd = argv[1];
       int len = strlen(cmd);
       if (len > 255) len = 255;
       system(cmd);
   }
   ```
   Assert that the `system(cmd)` finding is NOT sanitized (len is sanitized, but cmd is not -- and even if cmd were bounds-checked, CWE-78 is not in the sanitizable category set).

5. **`test_same_var_bounds_check_no_sanitize_for_injection`** -- Verify that CWE-category filtering works even when the bounds-checked variable is the same one used at the sink:
   ```c
   void run2(int argc, char *argv[]) {
       int val = atoi(argv[1]);
       if (val > 255) val = 255;
       char cmd[512];
       snprintf(cmd, sizeof(cmd), "%d", val);
       system(cmd);
   }
   ```
   Assert that `val` IS sanitized for `memory_corruption` / `buffer_overflow` but NOT for `command_injection`. This exercises the category filtering logic directly.

6. **`test_genuine_vuln_not_sanitized`** -- Verify that memcpy without bounds check is still flagged:
   ```c
   void copy_bad(int argc, char *argv[]) {
       int size = atoi(argv[1]);
       char dst[64];
       memcpy(dst, "hello", size);
   }
   ```
   No bounds check on `size` -> finding is NOT sanitized.

7. **`test_if_clamp_with_braces`** -- Same as test 1 but with braced body:
   ```c
   if (src_len > dst_size) { src_len = dst_size; }
   ```
   Assert sanitized.

8. **`test_if_clamp_numeric_literal_bound`** -- Verify numeric literal bounds are recognized:
   ```c
   void copy_bounded(char *dst, char *src) {
       int n = strlen(src);
       if (n > 4096) n = 4096;
       memcpy(dst, src, n);
   }
   ```
   Assert `n` is sanitized for `memory_corruption`.

9. **`test_taint_state_sanitization_methods`** -- Unit test `add_sanitization`, `is_sanitized_for`, and `copy` on `TaintState` directly.

10. **`test_taint_state_copy_isolates_sanitization`** -- Verify that `copy()` produces an independent sanitization state.

11. **`test_if_clamp_untainted_var_no_effect`** -- An if-clamp on a non-tainted variable does NOT add sanitization.

12. **`test_retaint_after_sanitize_clears_sanitization`** -- Verify that re-assignment from a tainted source clears prior sanitization:
    ```c
    void retaint(int argc, char *argv[]) {
        int n = atoi(argv[1]);
        if (n > 64) n = 64;        // sanitized
        n = atoi(argv[2]);          // re-tainted: sanitization must be cleared
        memcpy(dst, src, n);        // should be unsanitized
    }
    ```
    Assert `state.is_sanitized_for("n", "memory_corruption")` is False after re-taint. Assert the finding is NOT sanitized.

13. **`test_multi_var_only_clamped_var_sanitized`** -- Verify that sanitization is per-variable, not per-function:
    ```c
    void multi_var(int argc, char *argv[]) {
        int size_a = atoi(argv[1]);
        int size_b = atoi(argv[2]);
        if (size_a > 64) size_a = 64;  // only size_a is clamped
        memcpy(dst, src, size_b);       // uses unsanitized size_b
    }
    ```
    Assert that `size_a` is sanitized but `size_b` is NOT. Assert the finding for `size_b` is unsanitized.

14. **`test_if_clamp_tainted_rhs_not_sanitized`** -- Verify that reassignment to another tainted variable is not recognized as a sanitizer:
    ```c
    void tainted_rhs(int argc, char *argv[]) {
        int n = atoi(argv[1]);
        int m = atoi(argv[2]);
        if (n > m) n = m;  // RHS is tainted -- not a valid bound
        memcpy(dst, src, n);
    }
    ```
    Assert that `n` is NOT sanitized (the RHS `m` is tainted).

### New End-to-End Test Fixture

**`tests/fixtures/safe_samples/c/conditional_bounds.c`** -- Contains multiple functions exercising the conditional-clamp pattern with various sinks (memcpy, malloc), including numeric literal bounds. All paths should be sanitized.

**`tests/fixtures/vulnerable_samples/c/unbounded_memcpy.c`** -- Verifies that the existing `memory_functions.c` fixture (or a new focused variant) with no bounds check is still correctly flagged as unsanitized.

### Updated Existing Test

**`test_safe_bounded_copy_no_findings`** in `TestCEndToEnd` -- This test already checks that sanitized paths have `tp.sanitized=True`. No changes needed, but verify it still passes.

### Regression Check

Run `make test` to verify all existing Python, Go, and C tests pass unchanged. The conditional sanitizer only activates for C and only for specific AST patterns, so Python/Go tests should be unaffected.

## Acceptance Criteria

1. `TaintState` supports per-variable, per-category conditional sanitization via `add_sanitization()` and `is_sanitized_for()`.
2. `TaintState.add_taint()` clears stale entries from `sanitized_vars` when a variable is re-tainted.
3. The taint tracker recognizes `if (n > max) n = max;` patterns (including numeric literal bounds like `if (n > 4096) n = 4096;`) and marks the clamped variable as sanitized for CWE-119, CWE-120, CWE-190.
4. The taint tracker recognizes `n = (n > max) ? max : n;` ternary patterns with correct branch ordering verification and marks the assigned variable as sanitized.
5. The ternary recognizer correctly rejects MAX patterns like `n = (n > max) ? n : max;` (tainted value in the overflow branch).
6. `_check_sink_reachability` checks conditional sanitization in **both** the primary path and the fallback substring-match path.
7. Sanitized findings have `taint_path.sanitized=True` and `taint_path.sanitizer="conditional_bounds_check"`.
8. Findings with non-size-related CWEs (CWE-78, CWE-134, etc.) are NOT affected by conditional bounds checks.
9. Findings without bounds checks are NOT affected (no false negatives introduced).
10. Reassignment to a tainted RHS in an if-body is NOT recognized as a sanitizer.
11. All new tests pass: `uv run pytest tests/test_hunter/test_taint_c_paths.py -v`.
12. All existing tests pass: `make test`.
13. Coverage remains at 90%+.
14. CLAUDE.md Known Limitations updated to document conditional assignment sanitizer.

## Task Breakdown

### Files to Modify

| # | File | Changes |
|---|---|---|
| 1 | `src/deep_code_security/hunter/taint_tracker.py` | Add `sanitized_vars` to `TaintState`, modify `add_taint` to clear stale sanitization, add `add_sanitization`, `is_sanitized_for`, update `copy`. Add `_handle_if_sanitizer`, `_extract_comparison`, `_node_to_comparison_operand`, `_extract_comparison_from_node`, `_find_nontainted_reassignment_in_body`, `_extract_assignment_rhs`, `_check_ternary_clamp` (with branch ordering) to `TaintEngine`. Modify `_propagate_taint`, `_handle_assignment`, `_check_sink_reachability` (both primary and fallback paths). |
| 2 | `tests/test_hunter/test_taint_c_paths.py` | Add `TestConditionalSanitizer` class with 14 new tests |
| 3 | `tests/fixtures/safe_samples/c/conditional_bounds.c` | New fixture: functions with conditional bounds checks before memcpy/malloc |
| 4 | `CLAUDE.md` | Update Known Limitations to document conditional assignment sanitizer |

### Files to Create

| # | File | Description |
|---|---|---|
| 1 | `tests/fixtures/safe_samples/c/conditional_bounds.c` | Safe-sample fixture with conditional bounds checks (including numeric literal bounds) |

## Work Groups

### Shared Dependencies

- `src/deep_code_security/hunter/taint_tracker.py` (implement first -- test groups depend on it)

### Work Group 1: Test Fixtures

- `tests/fixtures/safe_samples/c/conditional_bounds.c`

### Work Group 2: Tests

- `tests/test_hunter/test_taint_c_paths.py`

### Work Group 3: Documentation

- `CLAUDE.md`

## Context Alignment

### CLAUDE.md Patterns Followed

- **Pydantic v2 for data-crossing models**: No new Pydantic models introduced; `TaintState` is a dataclass (internal to the taint tracker, not a data-crossing boundary). The existing Pydantic models (`TaintPath`, `RawFinding`) are used unchanged.
- **Type hints on all public functions**: All new methods have full type annotations.
- **Registries in YAML files, never hardcoded in Python**: The conditional sanitizer is NOT a registry entry. It is a code-level pattern in the taint tracker. The set of sanitizable categories (`_SIZE_SANITIZABLE_CATEGORIES`) is a constant in the taint tracker module, which is appropriate because it is tightly coupled to the pattern-matching logic (unlike registry sanitizers which are user-extensible).
- **Test fixtures in `tests/fixtures/`**: New fixtures follow existing directory structure and naming.
- **File conventions**: No new `models.py` or `orchestrator.py` needed. Changes are localized to the taint tracker.
- **Never `eval()`, `exec()`, `os.system()`, `subprocess.run(shell=True)`**: No subprocess or eval calls added.
- **Never `yaml.load()`**: No YAML loading added.

### Prior Plans Referenced

- **`c-language-support.md`**: This plan directly extends the C taint tracker work introduced in that plan. The `_LANGUAGE_NODE_TYPES["c"]` mapping, `_node_to_var_name` C-specific branches, `_extract_lhs_name` C-specific branches, and `_is_rhs_tainted` field_expression handling were all added by that plan. This plan builds on that foundation by adding conditional-flow awareness to the same taint tracker.
- **`suppressions-file.md`**: The suppression mechanism is an alternative to this plan for dealing with false positives. This plan addresses the root cause (taint tracker not modeling bounds checks) rather than the symptom (suppressing individual findings). Both mechanisms are complementary.
- **`deep-code-security.md`**: The confidence scoring model (sanitizer_score as 25% weight) was established in the base plan. This plan relies on that existing mechanism.

### Deviations from Established Patterns

- **`_SIZE_SANITIZABLE_CATEGORIES` as a module constant instead of a registry entry**: The conditional sanitizer concept does not fit the existing registry sanitizer schema (which maps function names to sink categories). A conditional bounds check is a structural code pattern, not a function call. Making it a module constant is appropriate. If future plans want to make this user-configurable, the constant could be loaded from a config file.
- **C-only implementation guarded by `if self.language == Language.C`**: This deviates from the language-agnostic taint engine design. However, the conditional bounds-check pattern is specific to C's manual memory management. Python and Go do not produce CWE-119/CWE-120/CWE-190 findings, so there is no value in extending this to other languages. The guard is justified.
- **`_node_to_comparison_operand` as a new method rather than extending `_node_to_var_name`**: The `_node_to_var_name` method is used throughout the taint tracker for variable identity resolution. Extending it to return strings for `number_literal` nodes would risk treating numeric literals as variable names in taint propagation. The separate `_node_to_comparison_operand` method is used exclusively by the conditional sanitizer pattern matching, keeping the two concerns cleanly separated.

<!-- Context Metadata
discovered_at: 2026-03-19T02:30:00Z
claude_md_exists: true
recent_plans_consulted: c-language-support.md, suppressions-file.md, sast-to-fuzz-pipeline.md
archived_plans_consulted: none
-->

## Status: APPROVED
