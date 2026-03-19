/* Vulnerable C code with format string bug -- for testing purposes ONLY.
 * This file intentionally contains security vulnerabilities for testing the Hunter.
 * Do NOT use this pattern in production code.
 *
 * CWE-134: Uncontrolled Format String
 * Pattern: fgets (return-value source) -> printf(user_data)
 *
 * NOTE: Uses the return-value pattern for fgets. The LHS-seeding taint
 * engine taints the return value variable, not the buffer argument.
 * Pattern: char *input = fgets(buf, n, fp); printf(input);
 */

#include <stdio.h>
#include <string.h>

/* CWE-134: Format string vulnerability via fgets return value */
void log_user_input(void) {
    char buf[256];
    /* fgets returns buf on success -- LHS 'input' is tainted */
    char *input = fgets(buf, sizeof(buf), stdin);
    if (input != NULL) {
        /* VULNERABLE: user-controlled format string */
        printf(input);  /* VULNERABLE */
    }
}

int main(void) {
    log_user_input();
    return 0;
}
