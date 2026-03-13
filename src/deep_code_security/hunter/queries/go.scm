; Go tree-sitter query fragments for source/sink detection
; These are shared fragments referenced by the YAML registry
; Note: Individual queries are in registries/go.yaml

; --- Source patterns ---

; http.Request URL query
(selector_expression
  operand: (identifier) @obj
  field: (field_identifier) @attr
  (#match? @obj "^r$|^req$|^request$")
  (#eq? @attr "URL")) @source.web_input

; http.Request form value
(call_expression
  function: (selector_expression
    operand: (selector_expression
      operand: (identifier) @obj
      field: (field_identifier) @field1
      (#match? @obj "^r$|^req$|^request$")
      (#eq? @field1 "Form"))
    field: (field_identifier) @attr
    (#eq? @attr "Get"))) @source.web_input

; http.Request FormValue
(call_expression
  function: (selector_expression
    operand: (identifier) @obj
    field: (field_identifier) @attr
    (#match? @obj "^r$|^req$|^request$")
    (#eq? @attr "FormValue"))) @source.web_input

; os.Args access
(selector_expression
  operand: (identifier) @obj
  field: (field_identifier) @attr
  (#eq? @obj "os")
  (#eq? @attr "Args")) @source.cli_input

; os.Getenv
(call_expression
  function: (selector_expression
    operand: (identifier) @obj
    field: (field_identifier) @attr
    (#eq? @obj "os")
    (#eq? @attr "Getenv"))) @source.env_input

; bufio.Scanner.Text (stdin reading)
(call_expression
  function: (selector_expression
    field: (field_identifier) @attr
    (#eq? @attr "Text"))) @source.stdin_input

; --- Sink patterns ---

; exec.Command
(call_expression
  function: (selector_expression
    operand: (identifier) @obj
    field: (field_identifier) @attr
    (#eq? @obj "exec")
    (#eq? @attr "Command"))) @sink.command_injection

; exec.CommandContext
(call_expression
  function: (selector_expression
    operand: (identifier) @obj
    field: (field_identifier) @attr
    (#eq? @obj "exec")
    (#eq? @attr "CommandContext"))) @sink.command_injection

; syscall.Exec
(call_expression
  function: (selector_expression
    operand: (identifier) @obj
    field: (field_identifier) @attr
    (#eq? @obj "syscall")
    (#eq? @attr "Exec"))) @sink.command_injection

; db.Query with string concat
(call_expression
  function: (selector_expression
    field: (field_identifier) @attr
    (#match? @attr "^(Query|QueryRow|Exec)$"))
  arguments: (argument_list
    (binary_expression
      operator: "+"))) @sink.sql_injection

; fmt.Sprintf (potential format string issues)
(call_expression
  function: (selector_expression
    operand: (identifier) @obj
    field: (field_identifier) @attr
    (#eq? @obj "fmt")
    (#eq? @attr "Sprintf"))) @sink.format_string

; os.Create / os.Open with user-controlled path
(call_expression
  function: (selector_expression
    operand: (identifier) @obj
    field: (field_identifier) @attr
    (#eq? @obj "os")
    (#match? @attr "^(Create|Open|OpenFile)$"))) @sink.path_traversal
