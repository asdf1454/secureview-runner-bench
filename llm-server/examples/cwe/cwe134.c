#include <stdio.h>

void log_message(const char *msg) {
    printf(msg); // expect: TRUE_POSITIVE
}

void to_buffer(char *out, const char *user) {
    sprintf(out, user); // expect: TRUE_POSITIVE
}

void safe_format(const char *msg) {
    printf("%s", msg); // expect: LIKELY_FALSE_POSITIVE
}

void constant_format(void) {
    printf("ready\n"); // expect: LIKELY_FALSE_POSITIVE
}
