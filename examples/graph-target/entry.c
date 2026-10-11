#include "api.h"

static int helper(int value) { return value + 1; }

int entry(int value) { return parse(helper(value)); }

int callback_entry(int value, int (*callback)(int)) { return callback(value); }
