#include "helpers.h"
#include "encoders.h"

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: rasm <input.asm> <output.lx>\n");
        return 1;
    }
    if (!has_ext(argv[1], ".asm"))
    {
        fprintf(stderr, "Input file must have .asm extension\n");
        return 1;
    }
    if (!has_ext(argv[2], ".lx"))
    {
        fprintf(stderr, "Output file must have .lx extension\n");
        return 1;
    }

    FILE *fin = fopen(argv[1], "r");
    FILE *fout = fopen(argv[2], "wb");
    if (!fin || !fout)
    {
        perror("fopen");
        return 1;
    }

    fwrite(magic_bytes, MAGIC_BYTES_SIZE, 1, fout);

    char line[256] = {0};
    while (fgets(line, sizeof(line), fin))
    {
        if (line[0] == ';' || line[0] == '\n')
        {
            continue;
        }

        char mnemonic[32] = {0};
        char operand1[32] = {0};
        char operand2[32] = {0};
        struct encoded_instruction ei = {0};
        bool found = false;
        int n = sscanf(line, "%31s %31[^,], %31s", mnemonic, operand1, operand2);

        if (n <= 0)
        {
            continue;
        }

        if (strcmp(operand1, "dip") == 0 || strcmp(operand2, "dip") == 0 || strcmp(operand1, "dstat") == 0 || strcmp(operand2, "dstat") == 0)
        {
            fprintf(stderr, "Illegal instruction: accessing DIP/DSTAT\n");
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
            ei.length = 2;
            ei.bytes[0] = strtoul(operand1, NULL, 0) & 0xff;
            ei.bytes[1] = (strtoul(operand1, NULL, 0) >> 8) & 0xff;
            found = true;
        }

        if (strcmp(mnemonic, ".dword") == 0)
        {
            ei.length = 4;
            ei.bytes[0] = strtoul(operand1, NULL, 0) & 0xff;
            ei.bytes[1] = (strtoul(operand1, NULL, 0) >> 8) & 0xff;
            ei.bytes[2] = (strtoul(operand1, NULL, 0) >> 16) & 0xff;
            ei.bytes[3] = (strtoul(operand1, NULL, 0) >> 24) & 0xff;
            found = true;
        }

        if (!found)
        {
            fprintf(stderr, "Unknown instruction: %s\n", mnemonic);
            return ERR_ILLINT;
        }

        fwrite(ei.bytes, ei.length, 1, fout);
    }

    fclose(fin);
    fclose(fout);
    return 0;
}
