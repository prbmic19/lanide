#pragma once
#include <stdbool.h>

typedef struct flag
{
    char *name;         // Flag name, such as "-o"
    char **value;
    bool takes_value;   // Does this flag take a value?
    bool present;       // For boolean flags
} flag_td;

extern int parse_args(int argc, char **argv, flag_td *flags, int flag_count);