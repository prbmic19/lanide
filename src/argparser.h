/** Declarations for argument parsing. */

#pragma once
#include <stdbool.h>

/**
 * Macros to indicate a particular error that would occur,
 * using `apstat` as the bit field.
 */
#define APEN_VALEXPECT  0x1
#define APEN_NOSUCHFLAG 0x2
#define APEN_NODEFAULT  0x4

// Struct to store information about the option, such as its name, its value,
// if it takes a value, if it is present as a boolean flag.
struct option
{
    const char *name;
    char **value;
    bool takes_value;
    bool present;
};

extern unsigned int apstat;
extern unsigned int apindex;
extern int parse_args(int argc, char *argv[], struct option options[], unsigned int flag_count);