/* Synthetic build-setting fixture; run only through the isolated worker. */
#include <stdio.h>
#include <string.h>

#ifndef AUDIT_GUARD
#define AUDIT_GUARD 0
#endif
#ifdef __OPTIMIZE__
#define OPTIMIZATION "enabled"
#else
#define OPTIMIZATION "disabled"
#endif

static void serve_request(const char *role) {
    puts("ENTRY request-handler");
#if AUDIT_GUARD
    if (strcmp(role, "admin") != 0) {
        puts("DENIED");
        return;
    }
#endif
    puts("DATA private-record");
}

int main(int argc, char **argv) {
    printf("CONFIG optimization=%s guard=%d\n", OPTIMIZATION, AUDIT_GUARD);
    if (argc != 2) return 2;
    serve_request(argv[1]);
    return 0;
}
