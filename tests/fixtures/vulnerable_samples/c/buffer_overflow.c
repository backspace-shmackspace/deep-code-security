/* Vulnerable C code with buffer overflow — for testing purposes ONLY.
 * This file intentionally contains security vulnerabilities for testing the Hunter.
 * Do NOT use this pattern in production code.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* CWE-120: Buffer overflow via strcpy with argv input */
void process_name_vulnerable(int argc, char *argv[]) {
    char buf[64];
    /* VULNERABLE: No bounds check — buffer overflow if argv[1] > 63 chars */
    if (argc > 1) {
        strcpy(buf, argv[1]);  /* VULNERABLE */
        printf("Hello, %s!\n", buf);
    }
}

/* CWE-78: Command injection via system() with argv */
void run_command_vulnerable(int argc, char *argv[]) {
    char cmd[256];
    if (argc > 1) {
        /* VULNERABLE: sprintf + system with user input */
        sprintf(cmd, "echo %s", argv[1]);
        system(cmd);  /* VULNERABLE */
    }
}

/* CWE-134: Format string vulnerability */
void log_message_vulnerable(char *user_input) {
    /* VULNERABLE: Format string attack — user controls format */
    printf(user_input);  /* VULNERABLE */
}

int main(int argc, char *argv[]) {
    process_name_vulnerable(argc, argv);
    run_command_vulnerable(argc, argv);
    if (argc > 2) {
        log_message_vulnerable(argv[2]);
    }
    return 0;
}
