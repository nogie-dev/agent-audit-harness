#include "api.h"

static int helper(int value) { return value * 2; }

int parse(int value) { return helper(value); }

int recurse(int value) { return value > 0 ? recurse(value - 1) : 0; }
