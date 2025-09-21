#include "helpers.h"
#include "encoders.h"
#include "args.h"
#include <ctype.h>

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
        {"-o", &output_file, true, false},
        { .name = "--help" },
        { .name = "-h" },
    };

    // Default = input
    int position = parse_args(argc, argv, flags, sizeof(flags) / sizeof(flags[0]));

    // -h, --help
    if (flags[1].present || flags[2].present)
    {
        puts("Usage: rasm [options...] <input.asm>\n");
        puts("Options:\n");
        puts("    -h, --help          Display this help message.");
        puts("    -o <output.lx>      Write the output to <output.lx>.");
        return 0;
    }

    if (position < 0)
    {
        fputs(TXT_ERROR "Missing input file.\n", stderr);
        return 1;
    }
    input_file = argv[position];

    if (!output_file)
    {
        fputs(TXT_ERROR "Missing output file.\n", stderr);
        return 1;
    }

    if (!has_ext(input_file, ".asm"))
    {
        fputs(TXT_ERROR "Input file must have .asm extension.\n", stderr);
        return 1;
    }
    if (!has_ext(output_file, ".lx"))
    {
        fputs(TXT_ERROR "Output file must have .lx extension.\n", stderr);
        return 1;
    }

    FILE *fin = fopen(input_file, "r");
    FILE *fout = fopen(output_file, "wb");
    if (!fin || !fout)
    {
        perror("fopen");
        return 1;
    }

    // Allocate just half a MEM_SIZE for both.
    uint8_t *text_buf = (uint8_t *)calloc(MEM_SIZE / 2, 1);
    uint8_t *data_buf = (uint8_t *)calloc(MEM_SIZE / 2, 1);
    if (!text_buf || !data_buf)
    {
        perror("calloc");
        return 1;
    }
    size_t text_size = 0;
    size_t data_size = 0;

    uint16_t current_section = 0xffff;

    char line[256] = {0};
    while (fgets(line, sizeof(line), fin))
    {
        if (*trim(line) == ';' || *trim(line) == '\n')
        {
            continue;
        }

        char mnemonic[32] = {0};
        char operand1[32] = {0};
        char operand2[32] = {0};
        struct instruction ei = {0};
        bool found = false;
        int n = sscanf(line, "%31s %31[^,], %31s", mnemonic, operand1, operand2);

        if (n <= 0)
        {
            continue;
        }

        if (strcmp(mnemonic, ".section") == 0)
        {
            if (strncmp(operand1, ".text", 5) == 0)
            {
                current_section = SECT_TEXT;
            }
            else if (strncmp(operand1, ".data", 5) == 0)
            {
                current_section = SECT_DATA;
            }
            else
            {
                fprintf(stderr, TXT_ERROR "Unknown section: %s\n", operand1);
                return ERR_MALFORMED;
            }
            continue;
        }

        if (strncmp(operand1, "dip", 3) == 0 || strncmp(operand2, "dip", 3) == 0 || strncmp(operand1, "dstat", 4) == 0 || strncmp(operand2, "dstat", 4) == 0)
        {
            fputs(TXT_ERROR "Illegal instruction: accessing DIP/DSTAT\n", stderr);
            return ERR_ILLINT;
        }

        // Fine for now, but this will get inefficient pretty quickly as the instruction set grows.
        for (uint8_t i = 0; i < instruction_count; i++)
        {
            if (strcmp(mnemonic, instruction_table[i].mnemonic) == 0)
            {
                ei = instruction_table[i].encode(operand1, operand2);
                found = true;
                break;
            }
        }

        if (strcmp(mnemonic, ".byte") == 0)
        {
            ei.length = 1;
            ei.bytes[0] = strtoul(operand1, NULL, 0) & 0xff;
            found = true;
        }

        if (strcmp(mnemonic, ".word") == 0)
        {
            unsigned long value = strtoul(operand1, NULL, 0);
            ei.length = 2;
            ei.bytes[0] = value & 0xff;
            ei.bytes[1] = (value >> 8) & 0xff;
            found = true;
        }

        if (strcmp(mnemonic, ".dword") == 0)
        {
            unsigned long value = strtoul(operand1, NULL, 0);
            ei.length = 4;
            ei.bytes[0] = value & 0xff;
            ei.bytes[1] = (value >> 8) & 0xff;
            ei.bytes[2] = (value >> 16) & 0xff;
            ei.bytes[3] = (value >> 24) & 0xff;
            found = true;
        }

        if (!found)
        {
            fprintf(stderr, TXT_ERROR "Unknown instruction: %s\n", mnemonic);
            return ERR_ILLINT;
        }

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
                fprintf(stderr, TXT_ERROR "Unknown section ID: %d\n", current_section);
                return ERR_MALFORMED;
        }
    }

    // Writes [magic][data_offset][text][data]
    fwrite(magic_bytes, 1, MAGIC_BYTES_SIZE, fout);
    uint32_t data_offset = (uint32_t)text_size;
    fwrite(&data_offset, sizeof(uint32_t), 1, fout);
    fwrite(text_buf, 1, text_size, fout);
    fwrite(data_buf, 1, data_size, fout);

    fclose(fin);
    fclose(fout);
    free(text_buf);
    free(data_buf);
    return 0;
}