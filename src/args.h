#pragma once
#include <stdbool.h>

struct flag
{
    const char *name;   // Flag name, such as "-o"
    char **value;
    bool takes_value;   // Does this flag take a value?
    bool present;       // For boolean flags
};

extern int parse_args(int argc, char *argv[], struct flag flags[], int flag_count);