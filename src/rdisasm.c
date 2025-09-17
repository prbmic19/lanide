#include "helpers.h"

#define BAD_INSTRUCTION() printf("(bad)")
#define REG_COUNT 18

static const char *reg_names[REG_COUNT] = {
    "dxa", "dxt", "dxc",
    "dd0", "dd1", "dd2", "dd3", "dd4", "dd5",
    "dbp", "dsp",
    "ds0", "ds1", "ds2", "ds3", "ds4",
    "dip", "dstat"
};

static void print_hex_bytes(uint8_t *mem, uint32_t addr, int length)
{
    int max_length = 6;
    for (int i = 0; i < length && i < max_length; i++)
    {
        printf("%02x ", mem[addr + i]);
    }
    for (int i = length; i < max_length; i++)
    {
        printf("   ");
    }
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: rdisasm <program.lx>\n");
        return 1;
    }
    if (!has_ext(argv[1], ".lx"))
    {
        fprintf(stderr, "Input file must have .lx extension");
        return 1;
    }

    FILE *fin = fopen(argv[1], "rb");
    if (!fin)
    {
        perror("fopen");
        return 1;
    }

    uint8_t header[MAGIC_BYTES_SIZE];
    size_t header_read = fread(header, 1, MAGIC_BYTES_SIZE, fin);
    if (header_read < MAGIC_BYTES_SIZE || memcmp(header, magic_bytes, MAGIC_BYTES_SIZE) != 0)
    {
        fprintf(stderr, "Invalid or missing magic bytes.\n");
        fclose(fin);
        return ERR_MALFORMED;
    }

    uint8_t *memory = (uint8_t *)malloc(MEM_SIZE);
    if (!memory)
    {
        perror("calloc");
        fclose(fin);
        return 1;
    }

    size_t loaded = fread(memory + TEXT_BASE, 1, MEM_SIZE - TEXT_BASE, fin);
    if (!feof(fin) && loaded == (MEM_SIZE - TEXT_BASE))
    {
        fprintf(stderr, "Warning: program may have been truncated.\n");
    }
    fclose(fin);

    printf("Disassembly of %s:\n\n", argv[1]);

    uint32_t ip = TEXT_BASE;
    uint32_t end = TEXT_BASE + (uint32_t)loaded;

    while (ip < end)
    {
        uint8_t opcode = memory[ip];
        int length = get_length(opcode, memory[ip + 1]);
        if (ip + length > end)
        {
            break;
        }

        printf("%8x:   ", ip);
        print_hex_bytes(memory, ip, length);
        printf("   ");

        uint8_t class = opcode >> 4;
        uint8_t op = opcode & 0xf;

        switch (class)
        {
            case IC_REGREG:
            {
                uint8_t b1 = memory[ip + 1];
                uint8_t rd32 = (b1 >> 4) & 0xf;
                uint8_t rs32 = b1 & 0xf;
                const char *mnemonics[] = {"add", "sub", "mul", "div", "and", "or", "xor", "not", "mov", "xchg", "push", "pop"};
                if (op < sizeof(mnemonics) / sizeof(mnemonics[0]))
                {
                    if (op == OC_REGREG_NOT || op == OC_REGREG_PUSH || op == OC_REGREG_POP)
                    {
                        printf("%-7s %s", mnemonics[op], reg_names[rd32]);
                    }
                    else
                    {
                        printf("%-7s %s,%s", mnemonics[op], reg_names[rd32], reg_names[rs32]);
                    }
                }
                else
                {
                    BAD_INSTRUCTION();
                }
                break;
            }
            case IC_REGIMM:
            {
                uint8_t rinfo = memory[ip + 1];
                uint8_t r32 = (rinfo >> 4) & 0xf;
                uint8_t immsize = rinfo & 0xf;
                uint32_t raw32 = memory[ip + 2] | (memory[ip + 3] << 8) | (memory[ip + 4] << 16) | (memory[ip + 5] << 24);
                uint32_t imm = (immsize == 0)
                    ? raw32 & 0xff
                    : (immsize == 1)
                    ? raw32 & 0xffff
                    : raw32;

                // Values 4..15 are reserved
                if (immsize > 3)
                {
                    BAD_INSTRUCTION();
                    break;
                }

                const char *mnemonics[] = {"add", "sub", "mul", "div", "and", "or", "xor", "mov"};
                if (op < sizeof(mnemonics) / sizeof(mnemonics[0]))
                {
                    printf("%-7s %s,0x%x", mnemonics[op], reg_names[r32], imm);
                }
                else
                {
                    BAD_INSTRUCTION();
                }
                break;
            }
            case IC_MEM:
            {
                uint8_t b1 = memory[ip + 1];
                uint8_t r32 = (b1 >> 4) & 0xf;
                uint32_t imm20 = (b1 & 0xf) | (memory[ip+2] << 4) | (memory[ip+3] << 12);
                const char *mnemonics[] = {"ldb", "stb", "ldw", "stw", "ldd", "std"};
                if (op < sizeof(mnemonics) / sizeof(mnemonics[0]))
                {
                    if (mnemonics[op][0] == 's')
                    {
                        printf("%-7s 0x%x,%s", mnemonics[op], imm20, reg_names[r32]);
                    }
                    else
                    {
                        printf("%-7s %s,0x%x", mnemonics[op], reg_names[r32], imm20);
                    }
                }
                else
                {
                    BAD_INSTRUCTION();
                }
                break;
            }
            case IC_BRANCH:
            {
                uint8_t b1 = memory[ip + 1];
                uint32_t imm20 = (b1 & 0xf) | (memory[ip + 2] << 4) | (memory[ip + 3] << 12);
                const char *mnemonics[] = {"jmp", "jc", "jnc", "jz", "jnz", "jo", "jno", "js", "jns", "call", "ret"};
                if (op < sizeof(mnemonics) / sizeof(mnemonics[0]))
                {
                    if (op == OC_BRANCH_RET)
                    {
                        printf("ret");
                    }
                    else
                    {
                        printf("%-7s 0x%x", mnemonics[op], imm20);
                    }
                }
                else
                {
                    BAD_INSTRUCTION();
                }
                break;
            }
            case IC_MISC:
                switch (op)
                {
                    case OC_MISC_HLT:
                        printf("hlt");
                        break;
                    case OC_MISC_NOP:
                        printf("nop");
                        break;
                    default:
                        BAD_INSTRUCTION();
                }
                break;
            default:
                BAD_INSTRUCTION();
        }

        putchar('\n');
        ip += length;
    }
    
    free(memory);
    return 0;
}