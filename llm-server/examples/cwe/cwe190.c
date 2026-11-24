#include <limits.h>
#include <stdlib.h>
#include <stddef.h>

int *alloc_items(int count) {
    return malloc(count * sizeof(int) * 1024); // expect: TRUE_POSITIVE
}

char *alloc_pair(unsigned int a, unsigned int b) {
    unsigned int total = a + b;
    return malloc(total); // expect: TRUE_POSITIVE
}

char *checked_sum(unsigned int a, unsigned int b) {
    if (a > UINT_MAX - b) {
        return NULL;
    }
    unsigned int total = a + b;
    return malloc(total); // expect: LIKELY_FALSE_POSITIVE
}

char *fixed_size(void) {
    int size = 16 * 4;
    return malloc(size); // expect: LIKELY_FALSE_POSITIVE
}
