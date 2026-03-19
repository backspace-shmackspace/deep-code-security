/* Vulnerable C code with integer overflow -- for testing purposes ONLY.
 * This file intentionally contains security vulnerabilities for testing the Hunter.
 * Do NOT use this pattern in production code.
 *
 * CWE-190: Integer Overflow or Wraparound
 * Pattern: argv -> atoi -> arithmetic -> malloc(tainted_size)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* CWE-190: Integer overflow in malloc size calculation */
void allocate_user_buffer(int argc, char *argv[]) {
    if (argc > 1) {
        /* User-controlled size from command line */
        int count = atoi(argv[1]);
        /* VULNERABLE: integer overflow -- count * sizeof(int) can wrap around */
        int *buf = malloc(count * sizeof(int));
        if (buf != NULL) {
            memset(buf, 0, count * sizeof(int));
            free(buf);
        }
    }
}

int main(int argc, char *argv[]) {
    allocate_user_buffer(argc, argv);
    return 0;
}
