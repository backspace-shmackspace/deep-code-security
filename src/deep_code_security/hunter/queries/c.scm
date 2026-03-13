; C tree-sitter query fragments for source/sink detection (stretch goal)
; Note: Individual queries are in registries/c.yaml

; --- Source patterns ---

; argv access (main function parameters)
(declaration
  declarator: (array_declarator
    declarator: (identifier) @id
    (#eq? @id "argv"))) @source.cli_input

; scanf family
(call_expression
  function: (identifier) @fn
  (#match? @fn "^(scanf|fscanf|sscanf|vscanf|vfscanf)$")) @source.stdin_input

; gets (deprecated, always unsafe)
(call_expression
  function: (identifier) @fn
  (#eq? @fn "gets")) @source.stdin_input

; fgets from stdin
(call_expression
  function: (identifier) @fn
  (#eq? @fn "fgets")) @source.stdin_input

; getenv
(call_expression
  function: (identifier) @fn
  (#eq? @fn "getenv")) @source.env_input

; --- Sink patterns ---

; system() call
(call_expression
  function: (identifier) @fn
  (#eq? @fn "system")) @sink.command_injection

; popen() call
(call_expression
  function: (identifier) @fn
  (#eq? @fn "popen")) @sink.command_injection

; execv/execl family
(call_expression
  function: (identifier) @fn
  (#match? @fn "^(execv|execl|execvp|execlp|execve|execle|execvpe)$")) @sink.command_injection

; sprintf / vsprintf (buffer overflow risk)
(call_expression
  function: (identifier) @fn
  (#match? @fn "^(sprintf|vsprintf)$")) @sink.buffer_overflow

; strcpy / strcat (buffer overflow risk)
(call_expression
  function: (identifier) @fn
  (#match? @fn "^(strcpy|strcat|wcscpy|wcscat)$")) @sink.buffer_overflow

; printf with user-controlled format string
(call_expression
  function: (identifier) @fn
  (#eq? @fn "printf")) @sink.format_string

; fopen with user-controlled path
(call_expression
  function: (identifier) @fn
  (#eq? @fn "fopen")) @sink.path_traversal
