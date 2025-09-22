#include "definitions.h"
#include "args.h"

// Option to toggle colored display
static bool colored_display = false;

static const char *reg_names[REG_COUNT] = {
    "dxa", "dxt", "dxc",
    "dd0", "dd1", "dd2", "dd3", "dd4", "dd5",
    "dbp", "dsp",
    "ds0", "ds1", "ds2", "ds3", "ds4",
    "dip", "dstat"
};

/* These functions add color to a string or a number using ANSI color codes, only if `colored_display` is set. */

const char *color(const char *string, const char *color)
{
    if (!colored_display)
    {
        return string;
    }

    static char buffer[128] = {0};
    snprintf(buffer, sizeof(buffer), "%s%s\x1b[0m", color, string);
    return buffer;
}

const char *color_mnemonic(const char *mnemonic)
{
    static char buffer[32];
    char padded[16];
    const char *format = colored_display ? "\x1b[33m%s\x1b[0m" : "%s";

    snprintf(padded, sizeof(padded), "%-7s", mnemonic);
    snprintf(buffer, sizeof(buffer), format, padded);
    return buffer;
}

const char *color_num(size_t number, const char *format, const char *color)
{
    static char buffer[128];
    buffer[0] = '\0';
    if (colored_display)
    {
        snprintf(buffer, sizeof(buffer), "%s", color);
    }

    size_t offset = strlen(buffer);
    snprintf(buffer + offset, sizeof(buffer) - offset, format, number);

    if (colored_display)
    {
        strncat(buffer, "\x1b[0m", sizeof(buffer) - strlen(buffer) - 1);
    }

    return buffer;
}

// Mnemonics as yellow
#define MNEMONIC(mnemonic)  color_mnemonic(mnemonic)
// Registers as blue
#define REG(reg)            color(reg, "\x1b[34m")
// Immediates and addresses as high intensity green
#define IMM(imm)            color_num(imm, "%#x", "\x1b[92m")

// Macro to print "(bad)" in case a bad instruction was detected
#define BAD_INSTRUCTION() fputs(MNEMONIC("(bad)"), stdout)

// Prints the raw encoded hex of the instruction at address `addr`.
static void print_hex_bytes(uint8_t memory[], uint32_t addr, int length)
{
    for (int i = 0; i < length && i < MAX_INSTRUCTION_LENGTH; i++)
    {
        printf("%02x ", memory[addr + i]);
    }
    for (int i = length; i < MAX_INSTRUCTION_LENGTH; i++)
    {
        fputs("   ", stdout);
    }
}

// Disassembles a range of memory and prints. Start from `ip` and ending at `end`.
static void disassemble(uint8_t memory[], uint32_t ip, uint32_t end)
{
    while (ip < end)
    {
        uint8_t opcode = memory[ip];
        int length = get_length(opcode, memory[ip + 1]);
        if (ip + length > end)
        {
            break;
        }

        printf("   %s:\t", color_num(ip, "%#5x", "\x1b[92m"));
        print_hex_bytes(memory, ip, length);
        putchar('\t');

        enum instruction_class class = opcode >> 4;
        enum instruction_type op = opcode & 0xf;

        switch (class)
        {
            case IC_REGREG:
            {
                uint8_t b1 = memory[ip + 1];
                uint8_t rd32 = (b1 >> 4) & 0xf;
                uint8_t rs32 = b1 & 0xf;
                const char *mnemonics[] = {"add", "sub", "mul", "div", "and", "or", "xor", "not", "neg", "mov", "cmp", "test", "push", "pushfd", "pop", "popfd"};
                if (op < sizeof(mnemonics) / sizeof(mnemonics[0]))
                {
                    if (op == IT_REGREG_NOT || op == IT_REGREG_NEG || op == IT_REGREG_PUSH || op == IT_REGREG_POP)
                    {
                        printf("%-7s %s", MNEMONIC(mnemonics[op]), REG(reg_names[rd32]));
                    }
                    else if (op == IT_REGREG_PUSHFD || op == IT_REGREG_POPFD)
                    {
                        fputs(MNEMONIC(mnemonics[op]), stdout);
                    }
                    else
                    {
                        printf("%-7s %s,%s", MNEMONIC(mnemonics[op]), REG(reg_names[rd32]), REG(reg_names[rs32]));
                    }
                }
                else
                {
                    BAD_INSTRUCTION();
                }
                break;
            }
            case IC_XREGREG:
            {
                uint8_t b1 = memory[ip + 1];
                uint8_t rd32 = (b1 >> 4) & 0xf;
                uint8_t rs32 = b1 & 0xf;
                const char *mnemonics[] = {"xchg", "ldip", "jmp", "call"};
                if (op < sizeof(mnemonics) / sizeof(mnemonics[0]))
                {
                    if (op == IT_XREGREG_XCHG)
                    {
                        printf("%-7s %s,%s", MNEMONIC(mnemonics[op]), REG(reg_names[rd32]), REG(reg_names[rs32]));
                    }
                    else
                    {
                        printf("%-7s %s", MNEMONIC(mnemonics[op]), REG(reg_names[rd32]));
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

                // Values 4..15 are reserved.
                if (immsize > 3)
                {
                    BAD_INSTRUCTION();
                    break;
                }

                const char *mnemonics[] = {"add", "sub", "mul", "div", "and", "or", "xor", "mov", "cmp", "test"};
                if (op < sizeof(mnemonics) / sizeof(mnemonics[0]))
                {
                    printf("%-7s %s,%s", MNEMONIC(mnemonics[op]), REG(reg_names[r32]), IMM(imm));
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
                const char *mnemonics[] = {"ldb", "ldw", "ldd", "stb", "stw", "std"};
                if (op < sizeof(mnemonics) / sizeof(mnemonics[0]))
                {
                    if (mnemonics[op][0] == 's')
                    {
                        printf("%-7s %s,%s", MNEMONIC(mnemonics[op]), IMM(imm20), REG(reg_names[r32]));
                    }
                    else
                    {
                        printf("%-7s %s,%s", MNEMONIC(mnemonics[op]), REG(reg_names[r32]), IMM(imm20));
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
                uint32_t imm20 = (memory[ip + 1] & 0xf) | (memory[ip + 2] << 4) | (memory[ip + 3] << 12);
                const char *mnemonics[] = {"jmp", "call", "ret"};
                if (op < sizeof(mnemonics) / sizeof(mnemonics[0]))
                {
                    if (op == IT_BRANCH_RET)
                    {
                        fputs("ret", stdout);
                    }
                    else
                    {
                        printf("%-7s %s", MNEMONIC(mnemonics[op]), IMM(imm20));
                    }
                }
                else
                {
                    BAD_INSTRUCTION();
                }
                break;
            }
            case IC_XBRANCH:
            {
                uint32_t imm20 = (memory[ip + 1] & 0xf) | (memory[ip + 2] << 4) | (memory[ip + 3] << 12);
                const char *mnemonics[] = {"jc", "jz", "jo", "js", "jnc", "jnz", "jno", "jns", "jg", "jge", "jl", "jle", "ja", "jbe"};
                if (op < sizeof(mnemonics) / sizeof(mnemonics[0]))
                {
                    printf("%-7s %s", MNEMONIC(mnemonics[op]), IMM(imm20));
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
                    case IT_MISC_HLT:
                        fputs(MNEMONIC("hlt"), stdout);
                        break;
                    case IT_MISC_NOP:
                        fputs(MNEMONIC("nop"), stdout);
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
}

int main(int argc, char *argv[])
{
    char *input_file = NULL;
    struct flag flags[] = {
        { .name = "--help" },
        { .name = "-h" },   // Alias of --help
        { .name = "--all-sections" },
        { .name = "--color" },
        { .name = "-c" },   // Alias of --color
    };

    // Default = input
    int position = parse_args(argc, argv, flags, sizeof(flags) / sizeof(flags[0]));

    // -h, --help
    if (flags[0].present || flags[1].present)
    {
        puts("Usage: rdisasm [options] <program.lx>\n");
        puts("Options:\n");
        puts("    -h, --help            Display this help message");
        puts("    --all-sections        Disassemble all sections");
        puts("    -c, --color           Display disassembly output with color");
        return 0;
    }

    if (position < 0)
    {
        ERROR("Missing input file.");
        return 1;
    }
    input_file = argv[position];

    if (!ends_with(input_file, ".lx"))
    {
        ERROR("Input file must have .lx extension.");
        return 1;
    }

    FILE *fin = fopen(input_file, "rb");
    if (!fin)
    {
        perror("fopen");
        return 1;
    }

    // Parse magic bytes
    uint8_t header[MAGIC_BYTES_SIZE];
    size_t header_read = fread(header, 1, MAGIC_BYTES_SIZE, fin);
    if (header_read < MAGIC_BYTES_SIZE || memcmp(header, magic_bytes, MAGIC_BYTES_SIZE) != 0)
    {
        ERROR("Invalid or missing magic bytes.");
        fclose(fin);
        return ERR_MALFORMED;
    }

    // Parse data offset
    uint32_t data_offset = 0;
    if (fread(&data_offset, sizeof(uint32_t), 1, fin) != 1)
    {
        ERROR("Failed to read data offset.");
        fclose(fin);
        return ERR_MALFORMED;
    }

    uint8_t *memory = (uint8_t *)calloc(MEM_SIZE, 1);
    if (!memory)
    {
        perror("calloc");
        fclose(fin);
        return 1;
    }

    // Parse .text section and load at TEXT_BASE
    size_t text_to_read = (size_t)data_offset;
    if (text_to_read > (MEM_SIZE - TEXT_BASE))
    {
        ERROR("Text section too large to fit in memory.");
        fclose(fin);
        free(memory);
        return ERR_MALFORMED;
    }

    size_t text_read = fread(memory + TEXT_BASE, 1, text_to_read, fin);
    if (text_read != text_to_read)
    {
        if (feof(fin))
        {
            WARN_FMT("Text section truncated (expected %zu, got %zu)", text_to_read, text_read);
        }
        else
        {
            perror("fread");
            fclose(fin);
            free(memory);
            return 1;
        }
    }

    // Parse .data section and load at DATA_BASE
    size_t data_capacity = MEM_SIZE - DATA_BASE;
    size_t data_read = fread(memory + DATA_BASE, 1, data_capacity, fin);
    if (!feof(fin) && data_read == data_capacity)
    {
        WARN("Data section may have been truncated.");
    }

    fclose(fin);

    // -c, --color
    colored_display = flags[3].present || flags[4].present;

    printf("Target: %s\n\n", input_file);

    puts("Disassembly of section .text:\n");
    disassemble(memory, TEXT_BASE, TEXT_BASE + (uint32_t)text_read);

    // --all-sections
    if (flags[2].present)
    {
        puts("\nDisassembly of section .data:\n");
        disassemble(memory, DATA_BASE, DATA_BASE + (uint32_t)data_read);
    }
    
    free(memory);
    return 0;
}