/** Implementation of the argument parser. */

#include "args.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Generic malformity error
#define ERR_MALFORMED 0x80

// Macro to print formatted errors
#define ERROR_FMT(format, ...)  fprintf(stderr, "\x1b[31merror:\x1b[0m " format "\n", __VA_ARGS__)

// Parses arguments passed in argv.
// Returns the index of the default argument, i.e., an argument/value not tied to any flag.
int parse_args(int argc, char *argv[], struct flag flags[], int flag_count)
{
    int positional_index = -1;

    // Loop through each argument
    for (int i = 1; i < argc; i++)
    {
        // Indicates whether a flag was found.
        bool found = false;

        for (int f = 0; f < flag_count; f++)
        {
            // Check if the current argument is a flag
            if (strcmp(argv[i], flags[f].name) == 0)
            {
                found = true;

                // Does it take a value?
                if (flags[f].takes_value)
                {
                    if (i + 1 < argc)
                    {
                        *(flags[f].value) = argv[++i];
                        found = true;
                        break;
                    }
                    // We're expecting a value next to the flag, but found none.
                    else
                    {
                        ERROR_FMT("Flag \"%s\" requires a value.", argv[i]);
                        exit(ERR_MALFORMED);
                    }
                }
                // If not, it's a boolean flag.
                else
                {
                    flags[f].present = true;
                }

                break;
            }
        }

        // If no flags were found but the current argument does not start with a dash,
        // then it is the "default" argument.
        if (!found && argv[i][0] != '-')
        {
            positional_index = i;
        }
        // If it does start with a dash, then that flag doesn't exist.
        else if (!found && argv[i][0] == '-')
        {
            ERROR_FMT("Unknown flag \"%s\"", argv[i]);
            exit(ERR_MALFORMED);
        }
    }

    return positional_index;
}