#include "args.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int parse_args(int argc, char **argv, flag_td *flags, int flag_count)
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
                        fprintf(stderr, "Error: \"%s\" requires a value.\n", argv[i]);
                        exit(0x80);
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
            fprintf(stderr, "Error: Unknown flag \"%s\"\n", argv[i]);
            exit(0x80);
        }
    }

    return positional_index;
}