/* Vulnerable C code with network-like input via fgets -- for testing purposes ONLY.
 * This file intentionally contains security vulnerabilities for testing the Hunter.
 * Do NOT use this pattern in production code.
 *
 * CWE-120: Buffer Copy without Checking Size
 * Pattern: fgets (return-value source) -> strcpy (unbounded copy)
 *
 * NOTE: Uses fgets (a return-value source that works with LHS-seeding)
 * rather than recv (an output-parameter source that does not).
 * Pattern: char *input = fgets(buf, n, fp); strcpy(dst, input);
 */

#include <stdio.h>
#include <string.h>

/* CWE-120: Buffer overflow via strcpy with fgets input */
void process_network_data(FILE *fp) {
    char buf[1024];
    char small_buf[32];
    /* fgets returns buf on success -- LHS 'data' is tainted */
    char *data = fgets(buf, sizeof(buf), fp);
    if (data != NULL) {
        /* VULNERABLE: strcpy with no bounds check */
        strcpy(small_buf, data);  /* VULNERABLE */
        printf("Received: %s\n", small_buf);
    }
}

int main(void) {
    process_network_data(stdin);
    return 0;
}
