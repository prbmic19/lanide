#include "argparser.h"
#include "definitions.h"
#include "diag.h"
#include <errno.h>

#define COLOR_RING_SLOTS 8
#define COLOR_BUFFER_SIZE 128
#define MNEMONIC_BUFFER_SIZE 64

static FILE *fin = NULL;
static uint8_t *memory = NULL;

// Option to toggle colored display.
static bool colored_display = false;

static const char *reg_names[REG_COUNT][4] = {
    {"rxa", "dxa", "xa", "al"},
    {"rxb", "dxb", "xb", "bl"},
    {"rxc", "dxc", "xc", "cl"},
    {"rxd", "dxd", "xd", "dl"},
    {"rxe", "dxe", "xe", "el"},
    {"rxi", "dxi", "xi", "il"},
    {"rbp", "dbp", "bp", "bpl"},
    {"rsp", "dsp", "sp", "spl"},
    {"r8", "r8d", "r8w", "r8b"},
    {"r9", "r9d", "r9w", "r9b"},
    {"r10", "r10d", "r10w", "r10b"},
    {"r11", "r11d", "r11w", "r11b"},
    {"r12", "r12d", "r12w", "r12b"},
    {"r13", "r13d", "r13w", "r13b"},
    {"r14", "r14d", "r14w", "r14b"},
    {"r15", "r15d", "r15w", "r15b"},
    {"rip", "dip", "ip", ""},
    {"rflags", "dflags", "flags", ""}
};

/**
 * These functions add color to a string or a number using ANSI color codes, only if `colored_display` is set.
 * `colored_display` can be toggled with the `--color` flag.
 * Buffer rings are used so static strings won't cause problems
 */

static const char *color(const char *restrict string, const char *restrict color)
{
    if (!colored_display)
    {
        return string;
    }

    static char buffer_ring[COLOR_RING_SLOTS][COLOR_BUFFER_SIZE] = {0};
    static uint32_t index = 0;
    uint32_t current = (index++) % COLOR_RING_SLOTS;

    snprintf(buffer_ring[current], COLOR_BUFFER_SIZE, "%s%s\x1b[0m", color, string);
    return buffer_ring[current];
}

static const char *color_mnemonic(const char *mnemonic)
{
    static char buffer_ring[COLOR_RING_SLOTS][MNEMONIC_BUFFER_SIZE] = {0};
    static uint32_t index = 0;
    uint32_t current = (index++) % COLOR_RING_SLOTS;

    const char *format = colored_display ? "\x1b[33m%-7s\x1b[0m" : "%-7s";
    snprintf(buffer_ring[current], MNEMONIC_BUFFER_SIZE, format, mnemonic);
    return buffer_ring[current];
}

static const char *color_u64(u64_it number, const char *restrict format, const char *restrict color)
{
    static char buffer_ring[COLOR_RING_SLOTS][COLOR_BUFFER_SIZE] = {0};
    static uint32_t index = 0;
    uint32_t current = (index++) % COLOR_RING_SLOTS;

    char temp[64] = {0};
    snprintf(temp, sizeof(temp), format, number);

    if (colored_display)
    {
        snprintf(buffer_ring[current], COLOR_BUFFER_SIZE, "%s%s\x1b[0m", color, temp);
    }
    else
    {
        snprintf(buffer_ring[current], COLOR_BUFFER_SIZE, "%s", temp);
    }

    return buffer_ring[current];
}

// Mnemonics as yellow
#define MNEMONIC(mnemonic) color_mnemonic(mnemonic)
// Registers as blue
#define REG(reg) color(reg, "\x1b[34m")
// Immediates and addresses as high intensity green
#define IMM(imm) color_u64(imm, "0x%llx", "\x1b[92m")

// Macro to print "(bad)" in case a bad instruction was parsed
#define BAD_INSTRUCTION() fputs(MNEMONIC("(bad)"), stdout)

// Prints the raw encoded hex of the instruction at address `addr`.
static void print_hex_bytes(uint8_t memory[], u64_it address, int length)
{
    for (int i = 0; i < length && i < MAX_INSTRUCTION_LENGTH; i++)
    {
        printf("%02x ", memory[address + i]);
    }
    for (int i = length; i < MAX_INSTRUCTION_LENGTH; i++)
    {
        fputs("   ", stdout);
    }
}

// Returns the number of bytes an immediate occupies based on the operand size.
static inline uint8_t get_ibc_for_size(uint16_t operand_size)
{
    switch (operand_size)
    {
        case 8:
            return 1;
        case 16:
            return 2;
        case 32:
            return 4;
        case 64:
            return 8;
        default:
            return 0;
    }
}

// Returns the second index used for accessing the 2D array `reg_names` based on the operand size given.
static inline int get_regindex_for_size(uint16_t operand_size)
{
    switch (operand_size)
    {
        case 8:
            return 3;
        case 16:
            return 2;
        case 32:
            return 1;
        default: // Fallback to 64-bit
        case 64:
            return 0;
    }
}

// Disassembles a range of memory and prints it, starting from `ip` and ending at `end`.
static void dump_disassembly(uint8_t memory[], u64_it ip, u64_it end)
{
    while (ip < end)
    {
        uint8_t initial_opcode = memory[ip];
        uint8_t opcode = initial_opcode;
        bool prefix_present = false;
        // Default operand size.
        uint16_t operand_size = 64;

        // Check for prefix
        if ((initial_opcode >> 4) == IC_PREFIX)
        {
            prefix_present = true;
            switch (initial_opcode & 0xf)
            {
                case IT_PREFIX_OS32:
                    operand_size = 32;
                    break;
                case IT_PREFIX_OS16:
                    operand_size = 16;
                    break;
                case IT_PREFIX_OS8:
                    operand_size = 8;
                    break;
                default:
                    emit_fatal("at address 0x%llx: unrecognized prefix type", ip);
            }
            // The real opcode is the next byte
            opcode = memory[ip + 1];
        }

        enum instruction_class class = opcode >> 4;
        enum instruction_type op = opcode & 0xf;
        int length = get_length(opcode, operand_size, prefix_present);
        uint8_t byte1 = memory[ip + 1 + prefix_present];

        // If we have not enough bytes for a full instruction, dump what's left and mark it bad.
        if (ip + length > end)
        {
            printf("   %s:\t", color_u64(ip, "0x%5x", "\x1b[92m"));
            print_hex_bytes(memory, ip, end - ip);
            putchar('\t');
            BAD_INSTRUCTION();
            putchar('\n');
            break;
        }

        printf("   %s: \t", color_u64(ip, "0x%-4x", "\x1b[92m"));
        print_hex_bytes(memory, ip, length);
        putchar('\t');

        switch (class)
        {
            case IC_REGREG:
            {
                uint8_t rd = byte1 >> 4;
                uint8_t rs = byte1 & 0xf;
                int reg_index = get_regindex_for_size(operand_size);
                const char *mnemonics[] = {
                    "add", "and", "cmp", "div",
                    "mov", "mul", "neg", "not",
                    "or", "pop", "popfd", "push",
                    "pushfd", "sub", "test", "xor"
                };

                if (op < sizeof(mnemonics) / sizeof(mnemonics[0]))
                {
                    switch (op)
                    {
                        case IT_REGREG_NOT:
                        case IT_REGREG_NEG:
                        case IT_REGREG_PUSH:
                        case IT_REGREG_POP:
                            printf("%-7s %s", MNEMONIC(mnemonics[op]), REG(reg_names[rd][reg_index]));
                            break;
                        case IT_REGREG_PUSHFQ:
                        case IT_REGREG_POPFQ:
                            fputs(MNEMONIC(mnemonics[op]), stdout);
                            break;
                        default:
                            printf("%-7s %s,%s", MNEMONIC(mnemonics[op]), REG(reg_names[rd][reg_index]), REG(reg_names[rs][reg_index]));
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
                uint8_t rd = byte1 >> 4;
                uint8_t rs = byte1 & 0xf;
                int reg_index = get_regindex_for_size(operand_size);
                const char *mnemonics[] = {"call", "jmp", "ldip", "mulh", "sdiv", "smulh", "xchg"};

                if (op < sizeof(mnemonics) / sizeof(mnemonics[0]))
                {
                    switch (op)
                    {
                        case IT_XREGREG_CALL:
                        case IT_XREGREG_JMP:
                        case IT_XREGREG_LDIP:
                            printf("%-7s %s", MNEMONIC(mnemonics[op]), REG(reg_names[rd][reg_index]));
                            break;
                        default:
                            printf("%-7s %s,%s", MNEMONIC(mnemonics[op]), REG(reg_names[rd][reg_index]), REG(reg_names[rs][reg_index]));
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
                uint8_t r = byte1 >> 4;
                uint8_t immbytes_count = get_ibc_for_size(operand_size);
                int reg_index = get_regindex_for_size(operand_size);
                u64_it imm = 0;
                const char *mnemonics[] = {"add", "and", "cmp", "div", "mov", "mul", "mulh", "or", "sdiv", "smulh", "sub", "test"};

                for (uint8_t i = 0; i < immbytes_count; i++)
                {
                    imm |= ((u64_it)memory[ip + prefix_present + 2 + i]) << (i * 8);
                }

                if (op < sizeof(mnemonics) / sizeof(mnemonics[0]))
                {
                    printf("%-7s %s,%s", MNEMONIC(mnemonics[op]), REG(reg_names[r][reg_index]), IMM(imm));
                }
                else
                {
                    BAD_INSTRUCTION();
                }

                break;
            }
            case IC_MEM:
            {
                uint8_t r = byte1 >> 4;
                u64_it addr24 = memory[ip + prefix_present + 2]
                    | (memory[ip + prefix_present + 3] << 8)
                    | (memory[ip + prefix_present + 4] << 16);
                int reg_index = get_regindex_for_size(operand_size);
                const char *mnemonics[] = {"ldb", "ldd", "ldq", "ldw", "stb", "std", "stq", "stw"};

                VALIDATE_ADDR(addr24, ip);

                if (op < sizeof(mnemonics) / sizeof(mnemonics[0]))
                {
                    // ST* instructions (store)
                    if (mnemonics[op][0] == 's')
                    {
                        printf("%-7s %s,%s", MNEMONIC(mnemonics[op]), IMM(addr24), REG(reg_names[r][reg_index]));
                    }
                    // LD* instructions
                    else
                    {
                        printf("%-7s %s,%s", MNEMONIC(mnemonics[op]), REG(reg_names[r][reg_index]), IMM(addr24));
                    }
                }

                break;
            }
            case IC_BRANCH:
            {
                u64_it addr24 = memory[ip + prefix_present + 2]
                    | (memory[ip + prefix_present + 3] << 8)
                    | (memory[ip + prefix_present + 4] << 16);
                const char *mnemonics[] = {"call", "jmp", "ret"};

                VALIDATE_ADDR(addr24, ip);

                if (op < sizeof(mnemonics) / sizeof(mnemonics[0]))
                {
                    if (op == IT_BRANCH_RET)
                    {
                        fputs(MNEMONIC("ret"), stdout);
                    }
                    else
                    {
                        printf("%-7s %s", MNEMONIC(mnemonics[op]), IMM(addr24));
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
                u64_it addr24 = memory[ip + prefix_present + 2]
                    | (memory[ip + prefix_present + 3] << 8)
                    | (memory[ip + prefix_present + 4] << 16);
                const char *mnemonics[] = {"ja", "jae", "jb", "jbe", "je", "jg", "jge", "jl", "jle", "jno", "jne", "jnp", "jns", "jo", "jp", "js"};

                VALIDATE_ADDR(addr24, ip);

                if (op < sizeof(mnemonics) / sizeof(mnemonics[0]))
                {
                    printf("%-7s %s", MNEMONIC(mnemonics[op]), IMM(addr24));
                }
                else
                {
                    BAD_INSTRUCTION();
                }

                break;
            }
            case IC_PREFIX:
            {
                const char *prefixes[] = {"OS32", "OS16", "OS8"};

                if (op < sizeof(prefixes) / sizeof(prefixes[0]))
                {
                    fputs(MNEMONIC(prefixes[op]), stdout);
                }
                else
                {
                    BAD_INSTRUCTION();
                }

                break;
            }
            case IC_MISC:
            {
                const char *mnemonics[] = {"hlt", "nop"};

                if (op < sizeof(mnemonics) / sizeof(mnemonics[0]))
                {
                    fputs(MNEMONIC(mnemonics[op]), stdout);
                }
                else
                {
                    BAD_INSTRUCTION();
                }

                break;
            }
            default:
                BAD_INSTRUCTION();
        }

        putchar('\n');
        ip += length;
    }
}

// Display help message.
static int display_help(void)
{
    puts("Usage: rdisasm [options] <file>");
    puts("Options:");
    puts("    --help                Display this help message");
    puts("    -v, --version         Display version information");
    puts("    --all-sections        Disassemble all sections");
    puts("    --color               Display disassembly output with color");
    return 0;
}

// Display version information.
static int display_version(void)
{
    puts("rdisasm version" RDISASM_VERSION);
    return 0;
}

// Cleanup before exit.
static void cleanup(void)
{
    if (fin)
    {
        fclose(fin);
    }
    free(memory);
}

int main(int argc, char *argv[])
{
    char *input_file = NULL;
    struct option options[] = {
        { .name = "--help" },
        { .name = "--version" },
        { .name = "-v" }, // Alias of --version
        { .name = "--all-sections" },
        { .name = "--color" }
    };

    set_progname(argv[0]);
    optional_enable_vt_mode();
    atexit(cleanup);

    // Default = input
    int position = parse_args(argc, argv, options, sizeof(options) / sizeof(options[0]));

    // --help
    if (options[0].present)
    {
        return display_help();
    }

    // -v, --version
    if (options[1].present || options[2].present)
    {
        return display_version();
    }

    if (apstat & APEN_NODEFAULT)
    {
        emit_fatal("missing input file");
    }

    if (position < 0)
    {
        return 1;
    }

    input_file = argv[position];

    if (!ends_with(input_file, ".lx"))
    {
        emit_error("input file must have '.lx' extension");
    }

    fin = fopen(input_file, "rb");
    if (!fin)
    {
        emit_fatal("failed to open input file: %s", strerror(errno));
    }

    // Parse magic bytes
    uint8_t header[MAGIC_BYTES_SIZE] = {0};
    size_t header_read = fread(header, 1, MAGIC_BYTES_SIZE, fin);
    if (header_read < MAGIC_BYTES_SIZE || memcmp(header, magic_bytes, MAGIC_BYTES_SIZE) != 0)
    {
        emit_fatal("invalid or missing magic bytes");
    }

    // Parse data offset
    uint32_t data_offset = 0;
    if (fread(&data_offset, sizeof(uint32_t), 1, fin) != 1)
    {
        emit_fatal("failed to read data offset");
    }

    memory = calloc(MEM_SIZE, 1);
    if (!memory)
    {
        emit_fatal("failed to allocate memory: %s", strerror(errno));
    }

    // Parse .text section and load at TEXT_BASE
    size_t text_to_read = (size_t)data_offset;
    if (text_to_read > (MEM_SIZE - TEXT_BASE))
    {
        emit_fatal("text section too large to fit in memory");
    }

    size_t text_read = fread(memory + TEXT_BASE, 1, text_to_read, fin);
    if (text_read != text_to_read)
    {
        if (feof(fin))
        {
            emit_warning("text section truncated: expected %zu, got %zu", text_to_read, text_read);
        }
        else
        {
            emit_fatal("failed to read input file: %s", strerror(errno));
        }
    }

    // Parse .data section and load at DATA_BASE
    size_t data_capacity = MEM_SIZE - DATA_BASE;
    size_t data_read = fread(memory + DATA_BASE, 1, data_capacity, fin);
    if (!feof(fin) && data_read == data_capacity)
    {
        emit_warning("data section may have been truncated");
    }

    if (errors_emitted != 0)
    {
        return 1;
    }

    // --color
    colored_display = options[4].present;

    printf("Target: %s\n\n", input_file);

    puts("Disassembly of section .text:\n");
    dump_disassembly(memory, TEXT_BASE, TEXT_BASE + text_read);

    // --all-sections
    if (options[3].present)
    {
        puts("\nDisassembly of section .data:\n");
        dump_disassembly(memory, DATA_BASE, DATA_BASE + data_read);
    }

    return 0;
}