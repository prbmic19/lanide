/** Declarations for argument parsing. */

#pragma once
#include <stdbool.h>

// Struct to store information about the flag, such as its name, its value,
// if it takes a value, if it is present as a boolean flag.
struct flag
{
    const char *name;
    char **value;
    bool takes_value;
    bool present;
};

extern int parse_args(int argc, char *argv[], struct flag flags[], int flag_count);