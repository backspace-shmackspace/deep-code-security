/* Vulnerable C code with command injection -- for testing purposes ONLY.
 * This file intentionally contains security vulnerabilities for testing the Hunter.
 * Do NOT use this pattern in production code.
 *
 * CWE-78: OS Command Injection
 * Pattern: argv -> sprintf -> system()
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* CWE-78: Command injection via system() with user-controlled argv */
void run_user_command(int argc, char *argv[]) {
    char cmd[512];
    if (argc > 1) {
        /* VULNERABLE: User input directly interpolated into command string */
        sprintf(cmd, "ls -la %s", argv[1]);
        system(cmd);  /* VULNERABLE: tainted cmd passed to system() */
    }
}

int main(int argc, char *argv[]) {
    run_user_command(argc, argv);
    return 0;
}
