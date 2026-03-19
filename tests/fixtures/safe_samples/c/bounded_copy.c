/* Safe C code using bounded copy functions -- for testing purposes ONLY.
 * This file demonstrates proper bounded string operations.
 * Should produce zero or low-confidence (sanitized) findings.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Safe: uses strncpy (bounded) instead of strcpy */
void safe_strncpy(int argc, char *argv[]) {
    char buf[64];
    if (argc > 1) {
        strncpy(buf, argv[1], sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        printf("Hello, %s!\n", buf);
    }
}

/* Safe: uses snprintf (bounded) instead of sprintf */
void safe_snprintf(int argc, char *argv[]) {
    char cmd[256];
    if (argc > 1) {
        snprintf(cmd, sizeof(cmd), "echo %s", argv[1]);
        printf("Would run: %s\n", cmd);
    }
}

int main(int argc, char *argv[]) {
    safe_strncpy(argc, argv);
    safe_snprintf(argc, argv);
    return 0;
}
