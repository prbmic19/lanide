/** Implementation of the argument parser. */

#include "argparser.h"
#include "diag.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Bit field to indicate any error that might occur.
unsigned int apstat = 0;

/**
 * Parses arguments passed in argv, modifying the contents of `options[]`.
 * Returns the index of the default argument, i.e., an argument not tied to any option.
 */
int parse_args(int argc, char *argv[], struct option options[], unsigned int flag_count)
{
    int positional_index = -1;

    // Loop through each argument
    for (int i = 1; i < argc; i++)
    {
        // Indicates whether an option was found.
        bool found = false;

        for (unsigned int f = 0; f < flag_count; f++)
        {
            // Check if the current argument is an option
            if (strcmp(argv[i], options[f].name) == 0)
            {
                found = true;

                // Does it take a value?
                if (options[f].takes_value)
                {
                    if (i + 1 < argc)
                    {
                        if (*(options[f].value) != NULL)
                        {
                            emit_warning("option '%s' specified multiple times, last occurrence takes precedence", argv[i], argv[i + 1]);
                        }
                        *(options[f].value) = argv[++i];
                        found = true;
                        break;
                    }
                    // We're expecting a value next to the option, but found none.
                    else
                    {
                        emit_error("missing value after '%s'", argv[i]);
                        apstat |= APEN_VALEXPECT;
                    }
                }
                // If not, it's a boolean flag.
                else
                {
                    options[f].present = true;
                }

                break;
            }
        }

        // If no options were found but the current argument does not start with a dash,
        // then it is the "default" argument.
        if (!found && argv[i][0] != '-')
        {
            positional_index = i;
        }
        // If it does start with a dash, then that option doesn't exist.
        else if (!found && argv[i][0] == '-')
        {
            emit_error("unrecognized flag: '%s'", argv[i]);
            apstat |= APEN_NOSUCHFLAG;
        }
    }

    if (positional_index == -1)
    {
        apstat |= APEN_NODEFAULT;
    }

    return positional_index;
}