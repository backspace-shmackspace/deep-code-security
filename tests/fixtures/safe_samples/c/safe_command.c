/* Safe C code with hardcoded command arguments -- for testing purposes ONLY.
 * This file demonstrates safe command execution with no user input.
 * Should produce zero findings (no taint source present).
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Safe: no user input in command -- hardcoded arguments */
void run_safe_command(void) {
    /* Hardcoded command with no user-controlled data */
    system("ls -la /tmp");

    /* execv with hardcoded args */
    char *args[] = {"/bin/echo", "hello", NULL};
    execv("/bin/echo", args);
}

int main(void) {
    run_safe_command();
    return 0;
}
