#include "args.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ERR_MALFORMED 0x80
#define TXT_ERROR "\x1b[31merror:\x1b[0m "

int parse_args(int argc, char *argv[], struct flag flags[], int flag_count)
{
    int positional_index = -1;

    for (int i = 1; i < argc; i++)
    {
        bool found = false;

        for (int f = 0; f < flag_count; f++)
        {
            if (strcmp(argv[i], flags[f].name) == 0)
            {
                found = true;

                if (flags[f].takes_value)
                {
                    if (i + 1 < argc)
                    {
                        *(flags[f].value) = argv[++i];
                        found = true;
                        break;
                    }
                    else
                    {
                        fprintf(stderr, TXT_ERROR "\"%s\" requires a value.\n", argv[i]);
                        exit(ERR_MALFORMED);
                    }
                }
                else
                {
                    flags[f].present = true;
                }

                break;
            }
        }

        if (!found && argv[i][0] != '-')
        {
            positional_index = i;
        }
        else if (!found && argv[i][0] == '-')
        {
            fprintf(stderr, TXT_ERROR "Unknown flag \"%s\"\n", argv[i]);
            exit(ERR_MALFORMED);
        }
    }

    return positional_index;
}