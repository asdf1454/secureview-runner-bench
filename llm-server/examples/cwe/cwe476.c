#include <stdio.h>
#include <stdlib.h>

void no_check(void) {
    int *p = malloc(sizeof(int));
    *p = 1; // expect: TRUE_POSITIVE
    free(p);
}

int first_char(const char *path) {
    FILE *f = fopen(path, "r");
    return fgetc(f); // expect: TRUE_POSITIVE
}

void with_check(void) {
    int *p = malloc(sizeof(int));
    if (p == NULL) {
        return;
    }
    *p = 1; // expect: LIKELY_FALSE_POSITIVE
    free(p);
}

int local_address(void) {
    int value = 3;
    int *p = &value;
    return *p; // expect: LIKELY_FALSE_POSITIVE
}
