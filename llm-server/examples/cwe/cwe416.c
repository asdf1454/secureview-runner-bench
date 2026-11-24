#include <stdio.h>
#include <stdlib.h>

void use_after(void) {
    char *p = malloc(16);
    free(p);
    p[0] = 'a'; // expect: TRUE_POSITIVE
}

void on_error(int failed) {
    char *p = malloc(16);
    if (failed) {
        free(p);
    }
    puts(p); // expect: TRUE_POSITIVE
}

void reassigned(void) {
    char *p = malloc(16);
    free(p);
    p = malloc(32);
    p[0] = 'a'; // expect: LIKELY_FALSE_POSITIVE
    free(p);
}

void only_free(void) {
    char *p = malloc(16);
    p[0] = 'a';
    free(p); // expect: LIKELY_FALSE_POSITIVE
}
