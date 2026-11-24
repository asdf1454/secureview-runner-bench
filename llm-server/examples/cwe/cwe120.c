#include <stdio.h>
#include <string.h>

void copy_arg(const char *input) {
    char buf[16];
    strcpy(buf, input); // expect: TRUE_POSITIVE
    puts(buf);
}

void read_name(void) {
    char name[8];
    gets(name); // expect: TRUE_POSITIVE
    puts(name);
}

void bounded(const char *input) {
    char buf[16];
    strncpy(buf, input, sizeof(buf) - 1); // expect: LIKELY_FALSE_POSITIVE
    buf[sizeof(buf) - 1] = '\0';
    puts(buf);
}

void checked(const char *input) {
    char buf[16];
    if (strlen(input) >= sizeof(buf)) {
        return;
    }
    strcpy(buf, input); // expect: LIKELY_FALSE_POSITIVE
    puts(buf);
}
