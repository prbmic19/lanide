/** Implements the assembler, outputting Lanide Extended machine code. */

#include "definitions.h"
#include "encoders.h"
#include "args.h"
#include <ctype.h>

// Internal function for trimming a line of source code.
static char *trim(char *string)
{
    char *end = NULL;

    while (isspace((uint8_t)*string))
    {
        string++;
    }

    if (*string == '\0')
    {
        return string;
    }

    // Trim trailing space
    end = string + strlen(string) - 1;
    while (end > string && isspace((uint8_t)*end))
    {
        end--;
    }

    end[1] = '\0';

    return string;
}

int main(int argc, char *argv[])
{
    char *input_file = NULL;
    char *output_file = NULL;
    struct flag flags[] = {
        { .name = "--help" },
        { .name = "-h" }, // Alias of --help
        { .name = "-o", .value = &output_file, .takes_value = true },
    };

    // Parse arguments passed.
    // An argument not tied to a flag is expected to be the input file.
    int position = parse_args(argc, argv, flags, sizeof(flags) / sizeof(flags[0]));

    // -h, --help
    if (flags[1].present || flags[2].present)
    {
        puts("Usage: rasm [options] <input.asm>\n");
        puts("Options:\n");
        puts("    -h, --help          Display this help message");
        puts("    -o <output.lx>      Write the assembled machine code to output file");
        return 0;
    }

    if (position < 0)
    {
        ERROR("Missing input file.");
        return 1;
    }
    input_file = argv[position];

    if (!output_file)
    {
        ERROR("Missing output file.");
        return 1;
    }

    // Validate their extensions.
    if (!ends_with(input_file, ".asm"))
    {
        ERROR("Input file must have have .asm extension.");
        return 1;
    }
    if (!ends_with(output_file, ".lx"))
    {
        ERROR("Output file must have .lx extension.");
        return 1;
    }

    FILE *fin = fopen(input_file, "r");
    FILE *fout = fopen(output_file, "wb");
    if (!fin || !fout)
    {
        perror("fopen");
        return 1;
    }

    // Allocate space for the .text and .data sections
    uint8_t *text_buf = (uint8_t *)calloc(MEM_SIZE / 2, 1);
    uint8_t *data_buf = (uint8_t *)calloc(MEM_SIZE / 2, 1);
    if (!text_buf || !data_buf)
    {
        perror("calloc");
        return 1;
    }
    size_t text_size = 0;
    size_t data_size = 0;

    // ID of the current section.
    uint16_t current_section = 0xffff;

    char line[256] = {0};
    while (fgets(line, sizeof(line), fin))
    {
        // Skip comments and newlines.
        if (*trim(line) == ';' || *trim(line) == '\n')
        {
            continue;
        }

        char mnemonic[32] = {0};
        char destination[32] = {0};
        char source[32] = {0};
        struct instruction ei = {0};
        bool found = false;

        // Parse the line
        int n = sscanf(line, "%31s %31[^,], %31s", mnemonic, destination, source);
        if (n <= 0)
        {
            continue;
        }

        // Change the section
        if (STR_EQUAL_LEN(mnemonic, ".section", 8))
        {
            if (STR_EQUAL_LEN(destination, ".text", 5))
            {
                current_section = SECT_TEXT;
            }
            else if (STR_EQUAL_LEN(destination, ".data", 5))
            {
                current_section = SECT_DATA;
            }
            else
            {
                ERROR_FMT("Unknown section: %s", destination);
                return ERR_MALFORMED;
            }
            continue;
        }

        // Uh oh! Illegal instruction! These cannot be accessed as an operand.
        if (
            STR_EQUAL_LEN(destination, "dip", 3)
            || STR_EQUAL_LEN(destination, "dstat", 4)
            || STR_EQUAL_LEN(source, "dip", 3)
            || STR_EQUAL_LEN(source, "dstat", 4)
        )
        {
            ERROR("Illegal instruction: accessing DIP/DSTAT");
            return ERR_ILLINT;
        }

        // Fine for now, but this will get inefficient pretty quickly as the instruction set grows.
        // TODO: optimize this
        for (uint16_t i = 0; i < instruction_count; i++)
        {
            if (strcmp(mnemonic, instruction_table[i].mnemonic) == 0)
            {
                ei = instruction_table[i].encode(destination, source);
                found = true;
                break;
            }
        }

        // Emit a byte
        if (STR_EQUAL_LEN(mnemonic, ".byte", 5))
        {
            ei.length = 1;
            ei.bytes[0] = strtoul(destination, NULL, 0) & 0xff;
            found = true;
        }

        // Emit a word (2 bytes)
        if (STR_EQUAL_LEN(mnemonic, ".word", 5))
        {
            unsigned long value = strtoul(destination, NULL, 0);
            ei.length = 2;
            ei.bytes[0] = value & 0xff;
            ei.bytes[1] = (value >> 8) & 0xff;
            found = true;
        }

        // Emit a dword (4 bytes)
        if (STR_EQUAL_LEN(mnemonic, ".dword", 6))
        {
            unsigned long value = strtoul(destination, NULL, 0);
            ei.length = 4;
            ei.bytes[0] = value & 0xff;
            ei.bytes[1] = (value >> 8) & 0xff;
            ei.bytes[2] = (value >> 16) & 0xff;
            ei.bytes[3] = (value >> 24) & 0xff;
            found = true;
        }

        if (!found)
        {
            ERROR_FMT("Unknown mnemonic: %s", mnemonic);
            return ERR_ILLINT;
        }

        // Write the buffers to their respective sections
        switch (current_section)
        {
            case SECT_TEXT:
                memcpy(text_buf + text_size, ei.bytes, ei.length);
                text_size += ei.length;
                break;
            case SECT_DATA:
                memcpy(data_buf + data_size, ei.bytes, ei.length);
                data_size += ei.length;
                break;
            default:
                ERROR_FMT("Unknown section ID: %d", current_section);
                return ERR_MALFORMED;
        }
    }

    // Write the magic bytes
    fwrite(magic_bytes, 1, MAGIC_BYTES_SIZE, fout);

    // Write the offset of .data
    uint32_t data_offset = (uint32_t)text_size;
    fwrite(&data_offset, sizeof(uint32_t), 1, fout);

    // Write the contents of .text
    fwrite(text_buf, 1, text_size, fout);

    // Write the contents of .data
    fwrite(data_buf, 1, data_size, fout);

    fclose(fin);
    fclose(fout);
    free(text_buf);
    free(data_buf);
    return 0;
}