; Python tree-sitter query fragments for source/sink detection
; These are shared fragments referenced by the YAML registry
; Note: Individual queries are in registries/python.yaml

; --- Source patterns ---

; Flask/Django request.form access
(attribute
  object: (identifier) @obj
  attribute: (identifier) @attr
  (#eq? @obj "request")
  (#eq? @attr "form")) @source.web_input

; Flask/Django request.args access
(attribute
  object: (identifier) @obj
  attribute: (identifier) @attr
  (#eq? @obj "request")
  (#eq? @attr "args")) @source.web_input

; Flask request.json access
(attribute
  object: (identifier) @obj
  attribute: (identifier) @attr
  (#eq? @obj "request")
  (#eq? @attr "json")) @source.web_input

; Flask request.data access
(attribute
  object: (identifier) @obj
  attribute: (identifier) @attr
  (#eq? @obj "request")
  (#eq? @attr "data")) @source.web_input

; sys.argv access
(attribute
  object: (identifier) @obj
  attribute: (identifier) @attr
  (#eq? @obj "sys")
  (#eq? @attr "argv")) @source.cli_input

; input() builtin
(call
  function: (identifier) @fn
  (#eq? @fn "input")) @source.cli_input

; os.environ access
(attribute
  object: (identifier) @obj
  attribute: (identifier) @attr
  (#eq? @obj "os")
  (#eq? @attr "environ")) @source.env_input

; open() call for file read
(call
  function: (identifier) @fn
  (#eq? @fn "open")) @source.file_read

; --- Sink patterns ---

; os.system call
(call
  function: (attribute
    object: (identifier) @obj
    attribute: (identifier) @attr
    (#eq? @obj "os")
    (#eq? @attr "system"))) @sink.command_injection

; subprocess.call / run / Popen / check_output / check_call
(call
  function: (attribute
    object: (identifier) @obj
    attribute: (identifier) @attr
    (#eq? @obj "subprocess")
    (#match? @attr "^(call|run|Popen|check_output|check_call)$"))) @sink.command_injection

; eval() builtin
(call
  function: (identifier) @fn
  (#eq? @fn "eval")) @sink.code_execution

; exec() builtin
(call
  function: (identifier) @fn
  (#eq? @fn "exec")) @sink.code_execution

; cursor.execute() with binary_operator (string concatenation) in args
(call
  function: (attribute
    attribute: (identifier) @attr
    (#eq? @attr "execute"))
  arguments: (argument_list
    (binary_operator))) @sink.sql_injection

; open() with user-controlled path (path traversal)
(call
  function: (identifier) @fn
  (#eq? @fn "open")
  arguments: (argument_list)) @sink.path_traversal
