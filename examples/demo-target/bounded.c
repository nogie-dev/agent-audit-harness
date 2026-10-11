#include <stddef.h>
#include <string.h>

int copy_bounded(const char *data, size_t length) {
    char buf[16];
    if (length == 0 || length > sizeof(buf))
        return -1;
    memcpy(buf, data, length);
    return buf[0];
}
