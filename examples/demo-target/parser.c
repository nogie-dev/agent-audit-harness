#include <stddef.h>
#include <string.h>

int copy_payload(const char *data, size_t length) {
    char buf[16];
    memcpy(buf, data, length);
    return buf[0];
}
