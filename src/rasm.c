#include "helpers.h"
#include "encoders.h"

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        fprintf(stderr, "Usage: rasm <input.asm> <output.lx>\n");
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

    char line[256];
    while (fgets(line, sizeof(line), fin))
    {
        if (line[0] == ';' || line[0] == '\n')
        {
            continue;
        }

        char mnemonic[32];
        char operand1[32];
        char operand2[32];
        EncodedInstruction ei = { 0 };
        _Bool found = 0;
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

        for (uint8_t i = 0; i < instruction_count; i++)
        {
            if (strcmp(mnemonic, instruction_table[i].mnemonic) == 0)
            {
                ei = instruction_table[i].encode(operand1, operand2);
                found = 1;
                break;
            }
        }

        if (strcmp(mnemonic, "here") == 0)
        {
            ei.length = 1;
            ei.bytes[0] = (uint8_t)strtol(operand1, NULL, 0);
            found = 1;
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