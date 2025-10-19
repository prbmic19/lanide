#include "argparser.h"
#include "diag.h"
#include "mmu.h"
#include <errno.h>

static const char *reg_names[REG_COUNT] = {
    "rxa", "rxb", "rxc", "rxd",
    "rxe", "rxi", "rbp", "rsp",
    "r8", "r9", "r10", "r11",
    "r12", "r13", "r14", "r15",
    "rip", "rflags"
};

// Macro to check if a certain flag in a bit field is set.
#define FLAG_ISSET(bitfield, flag) (((bitfield) & (flag)) != 0)

static FILE *fin = NULL;

// This should NOT be static.
uint8_t *memory = NULL;

// Default operand size.
static uint16_t operand_size = 64;

// Enumeration of ALU operations used in `update_status()` and `alu_execute()`.
enum alu_op
{
    ALU_ADD,
    ALU_SUB,
    ALU_MUL,
    ALU_MULH,
    ALU_SMULH,
    ALU_DIV,
    ALU_SDIV,
    ALU_AND,
    ALU_OR,
    ALU_XOR,
    ALU_NOT,
    ALU_NEG,
    ALU_CMP,
    ALU_TEST
};

// Gets the size of `fin`, a.k.a the opened file.
static size_t get_file_size(void)
{
    long current = ftell(fin);
    fseek(fin, 0, SEEK_END);
    long end = ftell(fin);
    fseek(fin, current, SEEK_SET);
    return (size_t)end;
}

static inline bool compute_parity(u64 number)
{
    number ^= number >> 4;
    number &= 0xf;
    return !(0x6996 >> number & 1);
}

static inline u64 get_mask_for_size(void)
{
    if (operand_size >= 64)
    {
        return ~0ull;
    }
    return ((1ull << operand_size) - 1ull);
}

// Updates flags based on the result and operands given.
static inline void update_flags(u64 registers[], enum alu_op operation, u64 result, u64 lhs, u64 rhs)
{
    if (result == 0)
    {
        rflags |= FLAG_ZF;
    }
    else
    {
        rflags &= ~FLAG_ZF;
    }

    // No cast required :P
    // Semantically better as well. Since SF reflects the sign bit value.
    if ((result >> 63) & 1)
    {
        rflags |= FLAG_SF;
    }
    else
    {
        rflags &= ~FLAG_SF;
    }

    if (compute_parity(result))
    {
        rflags |= FLAG_PF;
    }
    else
    {
        rflags &= ~FLAG_PF;
    }

    if (((lhs ^ rhs ^ result) & 0x10) != 0)
    {
        rflags |= FLAG_AF;
    }
    else
    {
        rflags &= ~FLAG_AF;
    }

    switch (operation)
    {
        case ALU_ADD:
            if (result < lhs)
            {
                rflags |= FLAG_CF;
            }
            else
            {
                rflags &= ~FLAG_CF;
            }

            if (((lhs ^ result) & (rhs ^ result)) >> 63)
            {
                rflags |= FLAG_OF;
            }
            else
            {
                rflags &= ~FLAG_OF;
            }
            break;
        case ALU_CMP:
        case ALU_SUB:
            if (rhs > lhs)
            {
                rflags |= FLAG_CF;
            }
            else
            {
                rflags &= ~FLAG_CF;
            }

            if (((lhs ^ rhs) & (lhs ^ result)) >> 63)
            {
                rflags |= FLAG_OF;
            }
            else
            {
                rflags &= ~FLAG_OF;
            }
            break;
        case ALU_MUL:
            __uint128_t result128 = (__uint128_t)lhs * (__uint128_t)rhs;
            if (result128 >> 64)
            {
                rflags |= FLAG_CF | FLAG_OF;
            }
            else
            {
                rflags &= ~(FLAG_CF | FLAG_OF);
            }
            break;
        case ALU_NEG:
            if (lhs == 0)
            {
                rflags |= FLAG_CF;
            }
            else
            {
                rflags &= ~FLAG_CF;
            }
            break;
        default:
            // DIV, SDIV, MULH, SMULH, and logical operations clear CF/OF
            rflags &= ~(FLAG_CF | FLAG_OF);
    }
}

// Executes ALU operations, subsequently updating flags.
static inline void alu_execute(u64 registers[], enum alu_op operation, uint8_t rd64, u64 rhs)
{
    u64 mask = get_mask_for_size();
    u64 lhs = registers[rd64] & mask;
    rhs &= mask;

    u64 result = lhs;
    u64 throwaway = 0;

    switch (operation)
    {
        case ALU_ADD:
            result = (lhs + rhs) & mask;
            throwaway = result;
            break;
        case ALU_SUB:
            result = (lhs - rhs) & mask;
            throwaway = result;
            break;
        // Lower 64 bits of 128-bit multiplication result
        case ALU_MUL:
            result = (u64)((__uint128_t)lhs * (__uint128_t)rhs) & mask;
            throwaway = result;
            break;
        // Signed and unsigned higher 64 bits of 128-bit multiplication result
        case ALU_MULH:
            result = (u64)(((__uint128_t)lhs * (__uint128_t)rhs) >> 64);
            throwaway = result;
            break;
        case ALU_SMULH:
            result = (u64)(((__int128_t)(i64)lhs * (__int128_t)(i64)rhs) >> 64);
            throwaway = result;
            break;
        case ALU_DIV:
            if (rhs == 0)
            {
                emit_fatal("at address 0x%llx: division by zero", rip);
            }
            result = (lhs / rhs) & mask;
            throwaway = result;
            break;
        case ALU_SDIV:
            if (rhs == 0)
            {
                emit_fatal("at address 0x%llx: division by zero", rip);
            }
            result = (u64)((i64)lhs / (i64)rhs) & mask;
            throwaway = result;
            break;
        case ALU_AND:
            result = (lhs & rhs) & mask;
            throwaway = result;
            break;
        case ALU_OR:
            result = (lhs | rhs) & mask;
            throwaway = result;
            break;
        case ALU_XOR:
            result = (lhs ^ rhs) & mask;
            throwaway = result;
            break;
        case ALU_NOT:
            result = (~lhs) & mask;
            throwaway = result;
            break;
        case ALU_NEG:
            result = (-lhs) & mask;
            throwaway = result;
            break;
        case ALU_CMP:
            throwaway = (lhs - rhs) & mask;
            break;
        case ALU_TEST:
            throwaway = (lhs & rhs) & mask;
            break;
    }

    registers[rd64] = result;
    update_flags(registers, operation, throwaway, lhs, rhs);
}

// Function to display help message.
static int display_help(void)
{
    puts("Usage: remu [options] <file>");
    puts("Options:");
    puts("    --help              Display this help message");
    puts("    -v, --version       Display version information");
    puts("    --dump-regs         Display register values at program end");
    return 0;
}

// Function to display version information.
static int display_version(void)
{
    puts("remu version " REMU_VERSION);
    return 0;
}

// Cleanup before exit.
static void cleanup(void)
{
    // Try to avoid disasters
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
        { .name = "--dump-regs" }
    };

    set_progname(argv[0]);
    maybe_enable_vt_mode();
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
        // TODO: give better reasons
        // Such as if the input "file" was actually a directory
        emit_fatal("failed to open input file: %s", strerror(errno));
    }

    // Parse magic bytes
    char header[MAGIC_BYTES_SIZE] = {0};
    size_t header_read = fread(header, 1, MAGIC_BYTES_SIZE, fin);
    // If it's incomplete or malformed, then...
    if (header_read != MAGIC_BYTES_SIZE || memcmp(header, magic_bytes, MAGIC_BYTES_SIZE) != 0)
    {
        emit_fatal("invalid or missing magic bytes");
    }

    // Parse rodata offset
    uint32_t rodata_offset = 0;
    if (fread(&rodata_offset, sizeof(uint32_t), 1, fin) != 1)
    {
        emit_fatal("failed to read rodata offset");
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

    // Parse .text section and load it at TEXT_BASE
    size_t text_to_read = (size_t)(rodata_offset - TEXT_FILE_OFFSET);
    if (text_to_read > TEXT_SIZE)
    {
        emit_fatal("text section too large to fit in memory");
    }

    fseek(fin, TEXT_FILE_OFFSET, SEEK_SET);
    size_t text_read = fread(memory + TEXT_BASE, 1, text_to_read, fin);
    if (text_read != text_to_read)
    {
        if (feof(fin))
        {
            emit_warning("text section truncated: expected %zu bytes, got %zu bytes", text_to_read, text_read);
        }
        else
        {
            emit_fatal("failed to read input file: %s", strerror(errno));
        }
    }

    // Parse .rodata section and load it at RODATA_BASE
    size_t rodata_to_read = (size_t)(data_offset - rodata_offset);
    if (rodata_to_read > RODATA_SIZE)
    {
        emit_fatal("rodata section too large to fit in memory");
    }

    fseek(fin, rodata_offset, SEEK_SET);
    size_t rodata_read = fread(memory + RODATA_BASE, 1, rodata_to_read, fin);
    if (rodata_read != rodata_to_read)
    {
        if (feof(fin))
        {
            emit_warning("rodata section truncated: expected %zu bytes, got %zu bytes", rodata_to_read, rodata_read);
        }
        else
        {
            emit_fatal("failed to read input file: %s", strerror(errno));
        }
    }

    // Parse .data section and load it at DATA_BASE
    size_t data_to_read = (size_t)(get_file_size() - data_offset);
    if (data_to_read > DATA_SIZE)
    {
        emit_fatal("data section too large to fit in memory");
    }

    fseek(fin, data_offset, SEEK_SET);
    size_t data_read = fread(memory + DATA_BASE, 1, data_to_read, fin);
    if (data_read != data_to_read)
    {
        if (feof(fin))
        {
            emit_warning("data section truncated: expected %zu bytes, got %zu bytes", data_to_read, data_read);
        }
        else
        {
            emit_fatal("failed to read input file: %s", strerror(errno));
        }
    }

    // If any errors accumulated, exit.
    if (errors_emitted != 0)
    {
        return 1;
    }

    setup_initial_mappings();

    // Initialize registers.
    // Set `rsp` to STACK_BASE and `rip` to TEXT_BASE.
    u64 registers[REG_COUNT] = {
        [7] = STACK_BASE,
        [16] = TEXT_BASE
    };

    while (true)
    {
        /* Fetch */

        uint8_t initial_opcode = fetch8(rip);
        uint8_t opcode = initial_opcode;
        bool prefix_present = false;
        operand_size = 64;

        // Check for prefix
        if ((initial_opcode >> 4) == IC_PREFIX)
        {
            prefix_present = true;
            switch (initial_opcode & 0xf)
            {
                case IT_PREFIX_OPSZ32:
                    operand_size = 32;
                    break;
                case IT_PREFIX_OPSZ16:
                    operand_size = 16;
                    break;
                case IT_PREFIX_OPSZ8:
                    operand_size = 8;
                    break;
                default:
                    emit_fatal("at address 0x%llx: unrecognized prefix type", rip);
            }
            // The real opcode is the next byte
            opcode = fetch8(rip + 1);
        }

        enum instruction_class class = opcode >> 4;
        enum instruction_type op = opcode & 0xf;
        int length = get_length(opcode, operand_size, prefix_present);

        if (rip + length > MEM_SIZE)
        {
            emit_fatal("instruction pointer out of bounds: 0x%llx", rip);
        }

        uint8_t buffer[MAX_INSTRUCTION_LENGTH] = {0};
        
        // Fetch the rest of the instruction, and exclude the prefix byte if it exists.
        for (int i = 0; i < length - prefix_present; i++)
        {
            buffer[i] = fetch8(rip + prefix_present + i);
        }

        /* Decode and execute */

        switch (class)
        {
            case IC_REGREG:
            {
                uint8_t rd64 = buffer[1] >> 4;
                uint8_t rs64 = buffer[1] & 0xf;
                u64 mask = get_mask_for_size();

                // I'm pretty sure it's impossible for us to get an illegal instruction here.
                // IC_REGREG already has 16 defined instructions, and a nibble can hold only 16 possible values.
                switch (op)
                {
                    case IT_REGREG_ADD:
                        alu_execute(registers, ALU_ADD, rd64, registers[rs64]);
                        break;
                    case IT_REGREG_AND:
                        alu_execute(registers, ALU_AND, rd64, registers[rs64]);
                        break;
                    case IT_REGREG_CMP:
                        alu_execute(registers, ALU_CMP, rd64, registers[rs64]);
                        break;
                    case IT_REGREG_DIV:
                        alu_execute(registers, ALU_DIV, rd64, registers[rs64]);
                        break;
                    case IT_REGREG_MOV:
                        registers[rd64] = registers[rs64];
                        break;
                    case IT_REGREG_MUL:
                        alu_execute(registers, ALU_MUL, rd64, registers[rs64]);
                        break;
                    case IT_REGREG_NEG:
                        alu_execute(registers, ALU_NEG, rd64, registers[rs64]);
                        break;
                    case IT_REGREG_NOT:
                        alu_execute(registers, ALU_NOT, rd64, registers[rs64]);
                        break;
                    case IT_REGREG_OR:
                        alu_execute(registers, ALU_OR, rd64, registers[rs64]);
                        break;
                    case IT_REGREG_POP:
                        registers[rd64] = load64(rsp) & mask;
                        rsp += operand_size / 8;
                        break;
                    case IT_REGREG_POPFQ:
                        rflags = load64(rsp);
                        rsp += 8;
                        break;
                    case IT_REGREG_PUSH:
                        rsp -= operand_size / 8;
                        store64(rsp, registers[rd64] & mask);
                        break;
                    case IT_REGREG_PUSHFQ:
                        rsp -= 8;
                        store64(rsp, rflags);
                        break;
                    case IT_REGREG_SUB:
                        alu_execute(registers, ALU_SUB, rd64, registers[rs64]);
                        break;
                    case IT_REGREG_TEST:
                        alu_execute(registers, ALU_TEST, rd64, registers[rs64]);
                        break;
                    case IT_REGREG_XOR:
                        alu_execute(registers, ALU_XOR, rd64, registers[rs64]);
                        break;
                    case IT_REGREG_INSTRUCTIONCOUNT:
                    default:
                        // What the hell? This should be impossible.
                }

                registers[rd64] &= mask;
                break;
            }
            case IC_XREGREG:
            {
                uint8_t rd64 = buffer[1] >> 4;
                uint8_t rs64 = buffer[1] & 0xf;
                u64 mask = get_mask_for_size();

                switch (op)
                {
                    case IT_XREGREG_XCHG:
                    {
                        u64 temp = registers[rd64];
                        registers[rd64] = registers[rs64];
                        registers[rs64] = temp;
                        break;
                    }
                    case IT_XREGREG_LDIP:
                        registers[rd64] = rip + length;
                        break;
                    case IT_XREGREG_MULH:
                        alu_execute(registers, ALU_MULH, rd64, registers[rs64]);
                        break;
                    case IT_XREGREG_SMULH:
                        alu_execute(registers, ALU_SMULH, rd64, registers[rs64]);
                        break;
                    case IT_XREGREG_SDIV:
                        alu_execute(registers, ALU_SDIV, rd64, registers[rs64]);
                        break;
                    case IT_XREGREG_JMP:
                        rip = registers[rd64];
                        continue;
                    case IT_XREGREG_CALL:
                        // Push the address of the next instruction on stack, so we can return to it eventually
                        rsp -= 8;
                        store64(rsp, rip + length);
                        rip = registers[rd64];
                        continue;
                    case IT_XREGREG_INSTRUCTIONCOUNT:
                    default:
                        emit_fatal("at address 0x%llx: illegal IC_XREGREG instruction: 0x%x", rip, op);
                }

                registers[rd64] &= mask;
                break;
            }
            case IC_REGIMM:
            {
                if ((buffer[1] & 0xf) != 0)
                {
                    emit_fatal("at address 0x%llx: illegal IC_REGIMM instruction: reserved bits are nonzero", rip);
                }

                uint8_t r64 = buffer[1] >> 4;
                uint8_t immbytes_count = operand_size / 8;
                u64 imm = 0;
                u64 mask = get_mask_for_size();

                for (uint8_t i = 0; i < immbytes_count; i++)
                {
                    imm |= ((u64)buffer[2 + i]) << (i * 8);
                }

                imm &= mask;

                switch (op)
                {
                    case IT_REGIMM_MOV:
                        registers[r64] = imm;
                        break;
                    case IT_REGIMM_ADD:
                        alu_execute(registers, ALU_ADD, r64, imm);
                        break;
                    case IT_REGIMM_SUB:
                        alu_execute(registers, ALU_SUB, r64, imm);
                        break;
                    case IT_REGIMM_MUL:
                        alu_execute(registers, ALU_MUL, r64, imm);
                        break;
                    case IT_REGIMM_MULH:
                        alu_execute(registers, ALU_MULH, r64, imm);
                        break;
                    case IT_REGIMM_SMULH:
                        alu_execute(registers, ALU_SMULH, r64, imm);
                        break;
                    case IT_REGIMM_DIV:
                        alu_execute(registers, ALU_DIV, r64, imm);
                        break;
                    case IT_REGIMM_SDIV:
                        alu_execute(registers, ALU_SDIV, r64, imm);
                        break;
                    case IT_REGIMM_AND:
                        alu_execute(registers, ALU_AND, r64, imm);
                        break;
                    case IT_REGIMM_OR:
                        alu_execute(registers, ALU_OR, r64, imm);
                        break;
                    case IT_REGIMM_XOR:
                        alu_execute(registers, ALU_XOR, r64, imm);
                        break;
                    case IT_REGIMM_CMP:
                        alu_execute(registers, ALU_CMP, r64, imm);
                        break;
                    case IT_REGIMM_TEST:
                        alu_execute(registers, ALU_TEST, r64, imm);
                        break;
                    case IT_REGIMM_INSTRUCTIONCOUNT:
                    default:
                        emit_fatal("at address 0x%llx: illegal IC_REGIMM instruction: 0x%x", rip, op);
                }

                registers[r64] &= mask;
                break;
            }
            case IC_MEM:
            {
                if ((buffer[1] & 0xf) != 0)
                {
                    emit_fatal("at address 0x%llx: illegal IC_REGIMM instruction: reserved bits are nonzero", rip);
                }

                uint8_t r64 = buffer[1] >> 4;
                u64 addr24 = buffer[2] | (buffer[3] << 8) | (buffer[4] << 16);

                switch (op)
                {
                    case IT_MEM_LDB:
                        registers[r64] = load8(addr24);
                        break;
                    case IT_MEM_LDW:
                        registers[r64] = load16(addr24);
                        break;
                    case IT_MEM_LDD:
                        registers[r64] = load32(addr24);
                        break;
                    case IT_MEM_LDQ:
                        registers[r64] = load64(addr24);
                        break;
                    case IT_MEM_STB:
                        store8(addr24, registers[r64] & 0xff);
                        break;
                    case IT_MEM_STW:
                        store16(addr24, registers[r64] & 0xffff);
                        break;
                    case IT_MEM_STD:
                        store32(addr24, registers[r64] & 0xffffffff);
                        break;
                    case IT_MEM_STQ:
                        store64(addr24, registers[r64]);
                        break;
                    case IT_MEM_INSTRUCTIONCOUNT:
                    default:
                        emit_fatal("at address 0x%llx: illegal IC_MEM instruction: 0x%x", rip, op);
                }

                break;
            }
            case IC_BRANCH:
            {
                u64 addr24 = buffer[1] | (buffer[2] << 8) | (buffer[3] << 16);

                // We continue to avoid "dip += length;"
                switch (op)
                {
                    case IT_BRANCH_JMP:
                        rip = addr24;
                        continue;
                    case IT_BRANCH_CALL:
                        rsp -= 8;
                        store64(rsp, rip + length);
                        rip = addr24;
                        continue;
                    case IT_BRANCH_RET:
                        rip = load64(rsp);
                        rsp += 8;
                        continue;
                    case IT_BRANCH_INSTRUCTIONCOUNT:
                    default:
                        emit_fatal("at address 0x%llx: illegal IC_BRANCH instruction: 0x%x", rip, op);
                }

                break;
            }
            case IC_XBRANCH:
            {
                u64 addr24 = buffer[1] | (buffer[2] << 8) | (buffer[3] << 16);

                switch (op)
                {
                    case IT_XBRANCH_JB:
                        JUMP(addr24, FLAG_ISSET(rflags, FLAG_CF));
                        break;
                    case IT_XBRANCH_JE:
                        JUMP(addr24, FLAG_ISSET(rflags, FLAG_ZF));
                        break;
                    case IT_XBRANCH_JO:
                        JUMP(addr24, FLAG_ISSET(rflags, FLAG_OF));
                        break;
                    case IT_XBRANCH_JS:
                        JUMP(addr24, FLAG_ISSET(rflags, FLAG_SF));
                        break;
                    case IT_XBRANCH_JAE:
                        JUMP(addr24, !FLAG_ISSET(rflags, FLAG_CF));
                        break;
                    case IT_XBRANCH_JNE:
                        JUMP(addr24, !FLAG_ISSET(rflags,FLAG_ZF));
                        break;
                    case IT_XBRANCH_JNO:
                        JUMP(addr24, !FLAG_ISSET(rflags, FLAG_OF));
                        break;
                    case IT_XBRANCH_JNS:
                        JUMP(addr24, !FLAG_ISSET(rflags, FLAG_SF));
                        break;
                    case IT_XBRANCH_JG:
                        JUMP(addr24, !FLAG_ISSET(rflags, FLAG_ZF) && (FLAG_ISSET(rflags, FLAG_SF) == FLAG_ISSET(rflags, FLAG_OF)));
                        break;
                    case IT_XBRANCH_JGE:
                        JUMP(addr24, FLAG_ISSET(rflags, FLAG_SF) == FLAG_ISSET(rflags, FLAG_OF));
                        break;
                    case IT_XBRANCH_JL:
                        JUMP(addr24, FLAG_ISSET(rflags, FLAG_SF) != FLAG_ISSET(rflags, FLAG_OF));
                        break;
                    case IT_XBRANCH_JLE:
                        JUMP(addr24, FLAG_ISSET(rflags, FLAG_ZF) && (FLAG_ISSET(rflags, FLAG_SF) != FLAG_ISSET(rflags, FLAG_OF)));
                        break;
                    case IT_XBRANCH_JA:
                        JUMP(addr24, !FLAG_ISSET(rflags, FLAG_CF) && !FLAG_ISSET(rflags, FLAG_ZF));
                        break;
                    case IT_XBRANCH_JBE:
                        JUMP(addr24, FLAG_ISSET(rflags, FLAG_CF) && FLAG_ISSET(rflags, FLAG_ZF));
                        break;
                    case IT_XBRANCH_JP:
                        JUMP(addr24, FLAG_ISSET(rflags, FLAG_PF));
                        break;
                    case IT_XBRANCH_JNP:
                        JUMP(addr24, !FLAG_ISSET(rflags, FLAG_PF));
                        break;
                    case IT_XBRANCH_INSTRUCTIONCOUNT:
                    default:
                        // Shouldn't happen
                }

                break;
            }
            case IC_MISC:
                switch (op)
                {
                    case IT_MISC_HLT:
                        goto halted;
                    case IT_MISC_NOP:
                        break;
                    case IT_MISC_INSTRUCTIONCOUNT:
                    default:
                        emit_fatal("at address 0x%llx: illegal IC_MISC instruction: 0x%x", rip, op);
                }
                break;
            default:
                emit_fatal("at address 0x%llx: illegal reserved class: 0x%x", rip, class);
        }

        rip += length;
        // Always set
        rflags |= FLAG_RB1;
        // Always cleared
        rflags &= ~(FLAG_RB3 | FLAG_RB5 | FLAG_RB15);
        // Clear bits 22..63
        rflags &= ~0xffffffffffc00000ull;
    }

halted:

    // --dump-regs
    // Will remove this in the future.
    if (options[3].present)
    {
        for (int i = 0; i < REG_COUNT; i++)
        {
            printf("%-16s  0x%-16llx  %llu\n", reg_names[i], registers[i], registers[i]);
        }
    }

    return 0;
}