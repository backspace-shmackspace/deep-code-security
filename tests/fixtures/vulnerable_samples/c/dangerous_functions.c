/* Vulnerable C code with dangerous function usage -- for testing purposes ONLY.
 * This file intentionally contains security vulnerabilities for testing the Hunter.
 * Do NOT use this pattern in production code.
 *
 * CWE-676: Use of Potentially Dangerous Function
 * Pattern: gets() is both a source and a sink. Two gets() calls in the same
 * function exercise the dual source+sink registration: the first gets() is the
 * taint source, and the second gets() is the CWE-676 sink (at a later line).
 */

#include <stdio.h>
#include <string.h>

/* CWE-676: gets() is always dangerous -- buffer overflow with no bounds */
void read_two_inputs(void) {
    char first[64];
    char second[64];
    /* First gets() -- acts as taint source */
    gets(first);  /* SOURCE: cli_input */
    /* Second gets() -- acts as CWE-676 sink (at later line than source) */
    gets(second);  /* VULNERABLE: CWE-676 dangerous function */
}

int main(void) {
    read_two_inputs();
    return 0;
}
