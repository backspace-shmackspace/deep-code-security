/* Fuzz target: buffer overflow vulnerabilities — for testing purposes ONLY.
 * This file intentionally contains security vulnerabilities for use by the
 * C fuzzer plugin test suite.  Do NOT use these patterns in production code.
 *
 * Design intent:
 *   - All functions are non-static, non-main, and have parameters so that
 *     c_signature_extractor discovers them as fuzz targets.
 *   - Vulnerabilities are clear and reachable in a single call with
 *     adversarial inputs, making them suitable for AI-generated harnesses.
 *   - No argv/argc dependency -- callers pass data directly so harnesses
 *     need only supply buffer contents and a length.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/*
 * CWE-120: Buffer Copy Without Checking Size of Input
 *
 * Copies `data` into a fixed 64-byte stack buffer using strcpy.
 * If `data` is longer than 63 bytes the stack is overwritten.
 *
 * Fuzz vector: pass a NUL-terminated string longer than 63 bytes.
 */
int copy_to_fixed_buffer(const char *data) {
    char buf[64];
    /* VULNERABLE: no length check before strcpy */
    strcpy(buf, data);  /* VULNERABLE */
    return (int)strlen(buf);
}

/*
 * CWE-120: Off-by-one buffer overflow via memcpy
 *
 * Copies `len` bytes from `data` into a 256-byte heap buffer.
 * If `len` equals or exceeds 256 the copy overflows the allocation.
 *
 * Fuzz vector: pass len >= 256 with a non-NULL data pointer.
 */
int copy_with_length(const char *data, size_t len) {
    char *buf = malloc(256);
    if (buf == NULL) {
        return -1;
    }
    /* VULNERABLE: len is not validated against the allocation size */
    memcpy(buf, data, len);  /* VULNERABLE */
    buf[255] = '\0';
    int result = (int)strlen(buf);
    free(buf);
    return result;
}

/*
 * CWE-121: Stack-based buffer overflow via sprintf
 *
 * Formats `value` into a 32-byte stack buffer with a decimal prefix.
 * Very large or negative values produce output exceeding 32 bytes.
 *
 * Fuzz vector: pass INT64_MIN or very large positive values.
 */
int format_value(int64_t value) {
    char buf[32];
    /* VULNERABLE: no bounds check; snprintf would be safe */
    sprintf(buf, "value=%lld", (long long)value);  /* VULNERABLE */
    return (int)strlen(buf);
}

/*
 * CWE-122: Heap-based buffer overflow via strcat
 *
 * Appends `suffix` to a heap buffer that was allocated for exactly
 * `base_len + 1` bytes.  If `suffix` is non-empty the heap is overflowed.
 *
 * Fuzz vector: pass any non-empty suffix string.
 */
char *append_suffix(const char *base, size_t base_len, const char *suffix) {
    /* VULNERABLE: allocation is too small when suffix is non-empty */
    char *buf = malloc(base_len + 1);
    if (buf == NULL) {
        return NULL;
    }
    memcpy(buf, base, base_len);
    buf[base_len] = '\0';
    /* VULNERABLE: strcat writes past the allocated region */
    strcat(buf, suffix);  /* VULNERABLE */
    return buf;
}
