/* Fuzz target: integer overflow vulnerabilities — for testing purposes ONLY.
 * This file intentionally contains security vulnerabilities for use by the
 * C fuzzer plugin test suite.  Do NOT use these patterns in production code.
 *
 * Design intent:
 *   - All functions are non-static, non-main, and have parameters so that
 *     c_signature_extractor discovers them as fuzz targets.
 *   - Integer overflows are reachable in a single call with adversarial
 *     inputs (e.g. INT_MAX, very large counts, negative sizes).
 *   - Downstream effects (heap allocation, array indexing) make the
 *     overflow detectable by ASan or abnormal exit codes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

/*
 * CWE-190: Integer Overflow in malloc size calculation
 *
 * Allocates `count * element_size` bytes on the heap.  When either operand
 * is large the multiplication wraps around, producing a tiny allocation that
 * is immediately overwritten by the subsequent memset call.
 *
 * Fuzz vector: pass count=INT_MAX and element_size=2 (product wraps to 0 or
 * a small value on 32-bit size_t; still small on 64-bit when count is UINT_MAX).
 */
int allocate_elements(size_t count, size_t element_size) {
    /* VULNERABLE: no overflow check before multiplication */
    size_t total = count * element_size;  /* VULNERABLE */
    char *buf = malloc(total);
    if (buf == NULL) {
        return -1;
    }
    /* Write `total` bytes -- overflows if the multiplication wrapped */
    memset(buf, 0, total);
    free(buf);
    return 0;
}

/*
 * CWE-190: Signed integer overflow in array index computation
 *
 * Adds two caller-supplied signed integers and uses the result as an array
 * index.  Signed overflow is undefined behaviour in C; with optimisation
 * the compiler may assume it cannot happen, breaking bounds checks.
 *
 * Fuzz vector: pass a=INT_MAX, b=1 (signed overflow to INT_MIN).
 */
int read_array_element(const int *array, int array_len, int a, int b) {
    if (array == NULL || array_len <= 0) {
        return -1;
    }
    /* VULNERABLE: a + b can overflow; index may be negative or out of bounds */
    int idx = a + b;  /* VULNERABLE */
    if (idx < 0 || idx >= array_len) {
        return -2;
    }
    return array[idx];
}

/*
 * CWE-191: Integer Underflow (wrap-around subtraction)
 *
 * Subtracts `delta` from an unsigned counter.  If `delta` is greater than
 * `counter` the result wraps around to a huge positive value, which is then
 * used to compute an allocation size.
 *
 * Fuzz vector: pass counter=0 and delta=1 (wraps to SIZE_MAX).
 */
int shrink_buffer(size_t counter, size_t delta) {
    /* VULNERABLE: unsigned subtraction can wrap to SIZE_MAX */
    size_t new_size = counter - delta;  /* VULNERABLE */
    char *buf = malloc(new_size);
    if (buf == NULL) {
        return -1;
    }
    memset(buf, 'X', new_size);
    free(buf);
    return 0;
}

/*
 * CWE-190: Integer truncation when converting size_t to int
 *
 * Accepts a size_t length and truncates it to int before using it in a loop
 * bound.  When length > INT_MAX the truncated value is negative (or a small
 * positive), causing the loop to iterate a wrong number of times.
 *
 * Fuzz vector: pass length = (size_t)INT_MAX + 1.
 */
int process_buffer(const char *data, size_t length) {
    if (data == NULL) {
        return -1;
    }
    /* VULNERABLE: truncation from size_t to int */
    int n = (int)length;  /* VULNERABLE */
    int sum = 0;
    for (int i = 0; i < n; i++) {
        sum += (unsigned char)data[i];
    }
    return sum;
}
