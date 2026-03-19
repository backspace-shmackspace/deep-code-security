/* Vulnerable C code with unbounded memory copy -- for testing purposes ONLY.
 * This file intentionally contains security vulnerabilities for testing the Hunter.
 * Do NOT use this pattern in production code.
 *
 * CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer
 * Pattern: argv -> atoi -> memcpy size argument (unbounded)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* CWE-119: Unbounded memcpy with user-controlled size */
void copy_user_data(int argc, char *argv[]) {
    char src[1024] = "source data";
    char dst[64];
    if (argc > 1) {
        /* User controls the copy size via argv[1] */
        int size = atoi(argv[1]);
        /* VULNERABLE: memcpy with user-controlled size, no bounds check */
        memcpy(dst, src, size);  /* VULNERABLE */
        printf("Copied %d bytes\n", size);
    }
}

int main(int argc, char *argv[]) {
    copy_user_data(argc, argv);
    return 0;
}
