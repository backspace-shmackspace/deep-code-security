/* Safe C code using conditional assignment (clamp) patterns -- for testing purposes ONLY.
 * This file demonstrates tainted size variables that are bounds-checked via
 * conditional assignment before reaching a sink (memcpy, malloc).
 * All paths are sanitized by a bounds clamp; should produce zero unsanitized findings.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_BUF 256

/* Safe: if (n > max) n = max; before memcpy -- plain if, no braces */
void clamp_if_no_braces(int argc, char *argv[]) {
    char dst[MAX_BUF];
    char src[MAX_BUF];
    size_t n = (size_t)atoi(argv[1]);
    size_t max = sizeof(dst);

    if (n > max)
        n = max;

    memcpy(dst, src, n);
}

/* Safe: if (n > max) { n = max; } before memcpy -- braces variant */
void clamp_if_braces(int argc, char *argv[]) {
    char dst[MAX_BUF];
    char src[MAX_BUF];
    size_t n = (size_t)atoi(argv[1]);
    size_t max = sizeof(dst);

    if (n > max) {
        n = max;
    }

    memcpy(dst, src, n);
}

/* Safe: ternary clamp n = (n > max) ? max : n; before memcpy */
void clamp_ternary(int argc, char *argv[]) {
    char dst[MAX_BUF];
    char src[MAX_BUF];
    size_t n = (size_t)atoi(argv[1]);
    size_t max = sizeof(dst);

    n = (n > max) ? max : n;

    memcpy(dst, src, n);
}

/* Safe: numeric literal bound -- if (n > 4096) n = 4096; before memcpy */
void clamp_numeric_literal(int argc, char *argv[]) {
    char dst[4096];
    char src[4096];
    size_t n = (size_t)atoi(argv[1]);

    if (n > 4096)
        n = 4096;

    memcpy(dst, src, n);
}

/* Safe: >= operator variant -- if (n >= max) n = max - 1; before memcpy */
void clamp_gte_operator(int argc, char *argv[]) {
    char dst[MAX_BUF];
    char src[MAX_BUF];
    size_t n = (size_t)atoi(argv[1]);
    size_t max = sizeof(dst);

    if (n >= max)
        n = max - 1;

    memcpy(dst, src, n);
}

/* Safe: ternary clamp with numeric literal bound before memcpy */
void clamp_ternary_numeric(int argc, char *argv[]) {
    char dst[512];
    char src[512];
    size_t n = (size_t)atoi(argv[1]);

    n = (n > 512) ? 512 : n;

    memcpy(dst, src, n);
}

/* Safe: if clamp before malloc -- size is bounded before allocation */
void clamp_before_malloc(int argc, char *argv[]) {
    size_t n = (size_t)atoi(argv[1]);
    size_t max = 1024;

    if (n > max)
        n = max;

    void *buf = malloc(n);
    if (buf == NULL)
        return;
    free(buf);
}

/* Safe: if clamp with braces before malloc -- braces variant with malloc sink */
void clamp_braces_before_malloc(int argc, char *argv[]) {
    size_t n = (size_t)atoi(argv[1]);
    size_t max = 4096;

    if (n > max) {
        n = max;
    }

    void *buf = malloc(n);
    if (buf == NULL)
        return;
    free(buf);
}

/* Safe: min() idiom via ternary -- (n < max) ? n : max before memcpy */
void clamp_min_idiom(int argc, char *argv[]) {
    char dst[MAX_BUF];
    char src[MAX_BUF];
    size_t n = (size_t)atoi(argv[1]);
    size_t max = sizeof(dst);

    size_t m = (n < max) ? n : max;

    memcpy(dst, src, m);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <n>\n", argv[0]);
        return 1;
    }
    clamp_if_no_braces(argc, argv);
    clamp_if_braces(argc, argv);
    clamp_ternary(argc, argv);
    clamp_numeric_literal(argc, argv);
    clamp_gte_operator(argc, argv);
    clamp_ternary_numeric(argc, argv);
    clamp_before_malloc(argc, argv);
    clamp_braces_before_malloc(argc, argv);
    clamp_min_idiom(argc, argv);
    return 0;
}
