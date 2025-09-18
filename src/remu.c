#include "helpers.h"
#include "args.h"

#define REG_COUNT 18
static const char *reg_names[REG_COUNT] = {
    "dxa", "dxt", "dxc",                        // Accumulator, temporary, counter
    "dd0", "dd1", "dd2", "dd3", "dd4", "dd5",   // Data/arguments
    "dbp", "dsp",                               // Base pointer, stack pointer
    "ds0", "ds1", "ds2", "ds3", "ds4",          // Callee-saved registers
    "dip", "dstat"                              // Instruction pointer, Status/flags
};

typedef enum alu_op
{
    ALU_ADD,
    ALU_SUB,
    ALU_MUL,
    ALU_DIV,
    ALU_AND,
    ALU_OR,
    ALU_XOR,
    ALU_NOT
} alu_op_td;

// Yeah... the ALU instructions implicitly update flags
static inline void update_status(uint32_t *registers, alu_op_td operation, int32_t result, int32_t lhs, int32_t rhs)
{
    if (result == 0)
    {
        dstat |= STAT_ZF;
    }
    else
    {
        dstat &= ~STAT_ZF;
    }

    if (result < 0)
    {
        dstat |= STAT_SF;
    }
    else
    {
        dstat &= ~STAT_SF;
    }

    switch (operation)
    {
        case ALU_ADD:
            if ((uint32_t)result < (uint32_t)lhs)
            {
                dstat |= STAT_CF;
            }
            else
            {
                dstat &= ~STAT_CF;
            }

            if (((lhs ^ result) & (rhs ^ result)) >> 31)
            {
                dstat |= STAT_OF;
            }
            else
            {
                dstat &= ~STAT_OF;
            }
            break;
        case ALU_SUB:
            // Borrow
            if ((uint32_t)rhs > (uint32_t)lhs)
            {
                dstat |= STAT_CF;
            }
            else
            {
                dstat &= ~STAT_CF;
            }
            
            if (((lhs ^ rhs) & (lhs ^ result)) >> 31)
            {
                dstat |= STAT_OF;
            }
            else
            {
                dstat &= ~STAT_OF;
            }
            break;
        case ALU_MUL:
            if ((int64_t)lhs * (int64_t)rhs > INT32_MAX || (int64_t)lhs * (int64_t)rhs < INT32_MIN)
            {
                dstat |= STAT_CF | STAT_OF;
            }
            else
            {
                dstat &= ~(STAT_CF | STAT_OF);
            }
            break;
        default:
            dstat &= ~(STAT_CF | STAT_OF); // Division and logical operations don't generate CF/OF
    }
}

static inline void alu_execute(uint32_t *registers, enum alu_op operation, uint8_t rd32, int32_t rhs)
{
    int32_t lhs = registers[rd32];
    int32_t result;

    switch (operation)
    {
        case ALU_ADD:
            result = lhs + rhs;
            break;
        case ALU_SUB:
            result = lhs - rhs;
            break;
        case ALU_MUL:
            result = lhs * rhs;
            break;
        case ALU_DIV:
            result = lhs / rhs;
            break;
        case ALU_AND:
            result = lhs & rhs;
            break;
        case ALU_OR:
            result = lhs | rhs;
            break;
        case ALU_XOR:
            result = lhs ^ rhs;
            break;
        case ALU_NOT:
            result = ~lhs;
            break;
    }
    registers[rd32] = (uint32_t)result;
    update_status(registers, operation, result, lhs, rhs);
}

int main(int argc, char **argv)
{
    int exit_code = 0;
    char *input_file = NULL;
    flag_td flags[] = {
        { .name = "--help" },
        { .name = "-h" },
        // Prints reg values and 512 bytes when the program stops.
        // This is temporarily. Will remove when we get a nice debugger/dumper
        { .name = "--show-state" }
    };

    // Default = input
    int position = parse_args(argc, argv, flags, sizeof(flags) / sizeof(flags[0]));
    if (position < 0)
    {
        fprintf(stderr, TXT_ERROR "Missing input file.\n");
        return 1;
    }
    input_file = argv[position];

    // -h, --help
    if (flags[0].present || flags[1].present)
    {
        printf("Usage: remu [options...] <program.lx>\n\n");
        printf("Options:\n\n");
        printf("    -h, --help          Display this help message.\n");
        printf("    --show-state        Display register values and 512 bytes of memory at program end.\n");
        return 0;
    }

    if (!has_ext(input_file, ".lx"))
    {
        fprintf(stderr, TXT_ERROR "Input file must have .lx extension.");
        return 1;
    }

    FILE *fin = fopen(input_file, "rb");
    if (!fin)
    {
        perror("fopen");
        return 1;
    }

    char header[MAGIC_BYTES_SIZE];
    size_t header_read = fread(header, 1, MAGIC_BYTES_SIZE, fin);
    if (header_read < MAGIC_BYTES_SIZE || memcmp(header, magic_bytes, MAGIC_BYTES_SIZE) != 0)
    {
        fprintf(stderr, TXT_ERROR "Invalid or missing magic bytes.\n");
        fclose(fin);
        return ERR_MALFORMED;
    }

    uint32_t data_offset = 0;
    if (fread(&data_offset, sizeof(uint32_t), 1, fin) != 1)
    {
        fprintf(stderr, TXT_ERROR "Failed to read data offset.\n");
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

    // Load .text at TEXT_BASE
    size_t text_to_read = (size_t)data_offset;
    if (text_to_read > (MEM_SIZE - TEXT_BASE))
    {   
        fprintf(stderr, TXT_ERROR "Text section too large to fit in memory.\n");
        free(memory);
        fclose(fin);
        return ERR_MALFORMED;
    }

    size_t text_read = fread(memory + TEXT_BASE, 1, text_to_read, fin);
    if (text_read != text_to_read)
    {
        if (feof(fin))
        {
            fprintf(stderr, TXT_WARN "Text section truncated (expected %zu, got %zu)\n", text_to_read, text_read);
        }
        else
        {
            perror("fread");
            fclose(fin);
            free(memory);
            return 1;
        }
    }

    // Load .data at DATA_BASE
    size_t data_capacity = MEM_SIZE - DATA_BASE;
    size_t data_read = fread(memory + DATA_BASE, 1, data_capacity, fin);
    if (!feof(fin) && data_read == data_capacity)
    {
        fprintf(stderr, TXT_WARN "Data section may have been truncated.\n");
    }

    fclose(fin);

    uint32_t registers[18] = {0};
    dip = TEXT_BASE;
    dsp = STACK_BASE;

    while (1)
    {
        if (dip + 3 >= MEM_SIZE)
        {
            fprintf(stderr, TXT_ERROR "Instruction pointer out of bounds: 0x%x\n", dip);
            exit_code = ERR_BOUND;
            break;
        }

        uint8_t opcode = memory[dip];
        int length = get_length(opcode, memory[dip + 1]);
        uint8_t buffer[6] = {0};
        memcpy(buffer, memory + dip, length);

        instruction_class_td class = opcode >> 4;
        instruction_type_td op = opcode & 0xf;

        switch (class)
        {
            case IC_REGREG:
            {
                uint8_t rd32 = buffer[1] >> 4;
                uint8_t rs32 = buffer[1] & 0xf;
                switch (op)
                {
                    case IT_REGREG_ADD:
                        alu_execute(registers, ALU_ADD, rd32, registers[rs32]);
                        break;
                    case IT_REGREG_SUB:
                        alu_execute(registers, ALU_SUB, rd32, registers[rs32]);
                        break;
                    case IT_REGREG_MUL:
                        alu_execute(registers, ALU_MUL, rd32, registers[rs32]);
                        break;
                    case IT_REGREG_DIV:
                        if (registers[rs32] == 0)
                        {
                            fprintf(stderr, TXT_ERROR "Illegal DIV instruction: divide-by-zero at address 0x%x\n", dip);
                            exit_code = ERR_ILLINT;
                            goto halted;
                        }
                        alu_execute(registers, ALU_DIV, rd32, registers[rs32]);
                        break;
                    case IT_REGREG_AND:
                        alu_execute(registers, ALU_AND, rd32, registers[rs32]);
                        break;
                    case IT_REGREG_OR:
                        alu_execute(registers, ALU_OR, rd32, registers[rs32]);
                        break;
                    case IT_REGREG_XOR:
                        alu_execute(registers, ALU_XOR, rd32, registers[rs32]);
                        break;
                    case IT_REGREG_NOT:
                        alu_execute(registers, ALU_NOT, rd32, 0);
                        break;
                    case IT_REGREG_MOV:
                        registers[rd32] = registers[rs32];
                        break;
                    case IT_REGREG_XCHG:
                        uint32_t temp = registers[rd32];
                        registers[rd32] = registers[rs32];
                        registers[rs32] = temp;
                        break;
                    case IT_REGREG_PUSH:
                        dsp -= 4;
                        memory[dsp]     = (uint8_t)(registers[rd32] & 0xff);
                        memory[dsp + 1] = (uint8_t)((registers[rd32] >> 8) & 0xff);
                        memory[dsp + 2] = (uint8_t)((registers[rd32] >> 16) & 0xff);
                        memory[dsp + 3] = (uint8_t)((registers[rd32] >> 24) & 0xff);
                        break;
                    case IT_REGREG_POP:
                        registers[rd32] = (uint32_t)memory[dsp]
                            | ((uint32_t)memory[dsp + 1] << 8)
                            | ((uint32_t)memory[dsp + 2] << 16)
                            | ((uint32_t)memory[dsp + 3] << 24);
                        dsp += 4;
                        break;
                    default:
                        fprintf(stderr, TXT_ERROR "Illegal REGREG opcode 0x%x at address 0x%x\n", op, dip);
                        exit_code = ERR_ILLINT;
                        goto halted;
                }
                break;
            }
            case IC_REGIMM:
            {
                uint8_t r32 = buffer[1] >> 4;
                uint8_t immsize = buffer[1] & 0xf;
                uint32_t raw32 = buffer[2] | (buffer[3] << 8) | (buffer[4] << 16) | (buffer[5] << 24);
                int32_t imm = (int32_t)((immsize == 0)
                    ? raw32 & 0xff
                    : (immsize == 1)
                    ? raw32 & 0xffff
                    : raw32);
                
                // Values 4..15 are reserved
                if (immsize > 3)
                {
                    fprintf(stderr, TXT_ERROR "Illegal REGIMM opcode: Invalid immsize %u at address 0x%x\n", immsize, dip);
                    exit_code = ERR_ILLINT;
                    goto halted;
                }

                switch (op)
                {
                    case IT_REGIMM_ADD:
                        alu_execute(registers, ALU_ADD, r32, imm);
                        break;
                    case IT_REGIMM_SUB:
                        alu_execute(registers, ALU_SUB, r32, imm);
                        break;
                    case IT_REGIMM_MUL:
                        alu_execute(registers, ALU_MUL, r32, imm);
                        break;
                    case IT_REGIMM_DIV:
                        if (imm == 0)
                        {
                            fprintf(stderr, TXT_ERROR "Illegal DIV instruction: Divide-by-zero at address 0x%x\n", dip);
                            exit_code = ERR_ILLINT;
                            goto halted;
                        }
                        alu_execute(registers, ALU_DIV, r32, imm);
                        break;
                    case IT_REGIMM_AND:
                        alu_execute(registers, ALU_AND, r32, imm);
                        break;
                    case IT_REGIMM_OR:
                        alu_execute(registers, ALU_OR, r32, imm);
                        break;
                    case IT_REGIMM_XOR:
                        alu_execute(registers, ALU_XOR, r32, imm);
                        break;
                    case IT_REGIMM_MOV:
                        registers[r32] = imm;
                        break;
                    default:
                        fprintf(stderr, TXT_ERROR "Illegal REGIMM opcode 0x%x at address 0x%x\n", op, dip);
                        exit_code = ERR_ILLINT;
                        goto halted;
                }
                break;
            }
            case IC_MEM:
            {
                uint8_t r32 = buffer[1] >> 4;
                uint32_t imm20 = (buffer[1] & 0xf) | (buffer[2] << 4) | (buffer[3] << 12);
                switch (op)
                {
                    case IT_MEM_LDB:
                        registers[r32] = memory[imm20];
                        break;
                    case IT_MEM_STB:
                        memory[imm20] = (uint8_t)(registers[r32] & 0xff);
                        break;
                    case IT_MEM_LDW:
                        registers[r32] = (uint16_t)memory[imm20] | ((uint16_t)memory[imm20 + 1] << 8);
                        break;
                    case IT_MEM_STW:
                        memory[imm20]       = (uint8_t)(registers[r32] & 0xff);
                        memory[imm20 + 1]   = (uint8_t)((registers[r32] >> 8) & 0xff);
                        break;
                    case IT_MEM_LDD:
                        registers[r32] = (uint32_t)memory[imm20]
                            | ((uint32_t)memory[imm20 + 1] << 8)
                            | ((uint32_t)memory[imm20 + 2] << 16)
                            | ((uint32_t)memory[imm20 + 3] << 24);
                        break;
                    case IT_MEM_STD:
                        memory[imm20]     = (uint8_t)(registers[r32] & 0xff);
                        memory[imm20 + 1] = (uint8_t)((registers[r32] >> 8) & 0xff);
                        memory[imm20 + 2] = (uint8_t)((registers[r32] >> 16) & 0xff);
                        memory[imm20 + 3] = (uint8_t)((registers[r32] >> 24) & 0xff);
                        break;
                    default:
                        fprintf(stderr, TXT_ERROR "Illegal MEM opcode 0x%x at address 0x%x\n", op, dip);
                        exit_code = ERR_ILLINT;
                        goto halted;
                }
                break;
            }
            case IC_BRANCH:
            {
                uint32_t imm20 = (buffer[1] & 0xf) | (buffer[2] << 4) | (buffer[3] << 12);
                // We continue to avoid "dip += length;"
                switch (op)
                {
                    case IT_BRANCH_JMP:
                        dip = imm20;
                        continue;
                    case IT_BRANCH_JC:
                        JUMP(imm20, dstat & STAT_CF);
                        break;
                    case IT_BRANCH_JNC:
                        JUMP(imm20, !(dstat & STAT_CF));
                        break;
                    case IT_BRANCH_JZ:
                        JUMP(imm20, dstat & STAT_ZF);
                        break;
                    case IT_BRANCH_JNZ:
                        JUMP(imm20, !(dstat & STAT_ZF));
                        break;
                    case IT_BRANCH_JO:
                        JUMP(imm20, dstat & STAT_OF);
                        break;
                    case IT_BRANCH_JNO:
                        JUMP(imm20, !(dstat & STAT_OF));
                        break;
                    case IT_BRANCH_JS:
                        JUMP(imm20, dstat & STAT_SF);
                        break;
                    case IT_BRANCH_JNS:
                        JUMP(imm20, !(dstat & STAT_SF));
                        break;
                    case IT_BRANCH_CALL:
                    {
                        // Push the address of the next instruction on stack
                        uint32_t return_address = dip + length;
                        dsp -= 4;
                        memory[dsp]     = (uint8_t)(return_address & 0xff);
                        memory[dsp + 1] = (uint8_t)((return_address >> 8) & 0xff);
                        memory[dsp + 2] = (uint8_t)((return_address >> 16) & 0xff);
                        memory[dsp + 3] = (uint8_t)((return_address >> 24) & 0xff);
                        dip = imm20;
                        continue;
                    }
                    case IT_BRANCH_RET:
                    {
                        uint32_t return_address = (uint32_t)memory[dsp]
                            | ((uint32_t)memory[dsp + 1] << 8)
                            | ((uint32_t)memory[dsp + 2] << 16)
                            | ((uint32_t)memory[dsp + 3] << 24);
                        dsp += 4;
                        dip = return_address;
                        continue;
                    }
                    default:
                        fprintf(stderr, TXT_ERROR "Illegal BRANCH opcode %x at address %x\n", op, dip);
                        exit_code = ERR_ILLINT;
                        goto halted;
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
                    default:
                        fprintf(stderr, TXT_ERROR "Illegal MISC opcode 0x%x at address 0x%x\n", op, dip);
                        exit_code = ERR_ILLINT;
                        goto halted;
                }
                break;
            default:
                fprintf(stderr, TXT_ERROR "Illegal reserved class 0x%x at address 0x%x\n", class, dip);
                exit_code = ERR_ILLINT;
                goto halted;
        }

        dip += length;
    }

halted:

    // Will remove this in the future
    if (flags[2].present)
    {
        for (int i = 0; i < REG_COUNT; i++)
        {
            printf("%-14s  0x%-14x  %u\n", reg_names[i], registers[i], registers[i]);
        }

        printf("\nMemory (non-zero bytes, from 0x00000 to 0x00200):\n");
        for (int addr = 0; addr < 0x200; addr++)
        {
            if (memory[addr] != 0)
            {
                printf("0x%-12.05x  0x%-14.02x  %c\n", addr, memory[addr], (memory[addr] >= 32 && memory[addr] <= 126) ? memory[addr] : '.');
            }
        }
    }

    free(memory);
    return exit_code;
}