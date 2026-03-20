/* Fuzz target: format string vulnerabilities — for testing purposes ONLY.
 * This file intentionally contains security vulnerabilities for use by the
 * C fuzzer plugin test suite.  Do NOT use these patterns in production code.
 *
 * Design intent:
 *   - All functions are non-static, non-main, and have parameters so that
 *     c_signature_extractor discovers them as fuzz targets.
 *   - The format string vulnerability is reachable in a single call with
 *     a crafted format string, making it suitable for AI-generated harnesses.
 *   - Functions write to a stack/heap buffer or stdout so the vulnerability
 *     is observable via ASan or abnormal exit.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

/*
 * CWE-134: Uncontrolled Format String via printf
 *
 * Passes the caller-supplied string directly as the format argument to
 * printf.  A string containing format specifiers (e.g. "%s%s%s%s%n")
 * reads from and writes to the stack, causing undefined behaviour.
 *
 * Fuzz vector: pass a string containing "%n", "%s", or "%p" specifiers.
 */
void log_message(const char *message) {
    /* VULNERABLE: user-controlled format string */
    printf(message);  /* VULNERABLE */
}

/*
 * CWE-134: Uncontrolled Format String via fprintf
 *
 * Same vulnerability as log_message but targets the stderr stream.
 * Useful for testing harnesses that capture stderr for ASan output.
 *
 * Fuzz vector: pass a string containing format specifiers.
 */
void log_error(const char *message) {
    /* VULNERABLE: user-controlled format string */
    fprintf(stderr, message);  /* VULNERABLE */
}

/*
 * CWE-134: Uncontrolled Format String via snprintf into caller buffer
 *
 * Formats `fmt` into the caller-supplied buffer `out` of `out_size` bytes.
 * Even though snprintf bounds the write to `out`, format specifiers still
 * read from the stack (%s, %p) and the %n specifier writes through a pointer.
 *
 * Fuzz vector: pass a format string containing "%n" or large "%*d" widths.
 */
int format_to_buffer(char *out, size_t out_size, const char *fmt) {
    if (out == NULL || out_size == 0) {
        return -1;
    }
    /* VULNERABLE: fmt is caller-supplied; %n writes can corrupt memory */
    return snprintf(out, out_size, fmt);  /* VULNERABLE */
}

/*
 * CWE-134: Format string via sprintf with runtime-computed prefix
 *
 * Builds a log line from a severity level and a caller-supplied message,
 * then passes the concatenated string as the format to printf.
 *
 * Fuzz vector: embed format specifiers in `message`.
 */
void log_with_level(int level, const char *message) {
    char buf[512];
    const char *severity = (level >= 2) ? "ERROR" : (level == 1 ? "WARN" : "INFO");
    /* Build the prefix safely... */
    snprintf(buf, sizeof(buf), "[%s] %s", severity, message);
    /* ...but then pass the assembled string as the format: VULNERABLE */
    printf(buf);  /* VULNERABLE */
    printf("\n");
}
