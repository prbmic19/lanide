#include "helpers.h"

#define REG_COUNT 18
static const char *reg_names[REG_COUNT] = {
    "dxa", "dxt", "dxc",                        // accumulator, temporary, counter
    "dd0", "dd1", "dd2", "dd3", "dd4", "dd5",   // data/arguments
    "dbp", "dsp",                               // base pointer, stack pointer
    "ds0", "ds1", "ds2", "ds3", "ds4",          // callee-saved registers
    "dip", "dstat"                              // instruction pointer, Status/flags
};

const char *reg_name(int index)
{
    if (index >= 0 && index < REG_COUNT)
    {
        return reg_names[index];
    }
    return "(bad)";
}

typedef enum
{
    ALU_ADD,
    ALU_SUB,
    ALU_MUL,
    ALU_DIV,
    ALU_AND,
    ALU_OR,
    ALU_XOR,
    ALU_NOT
} AluOp;

// Yeah... the ALU instructions implicitly update flags
static inline void update_status(uint32_t *registers, AluOp operation, int32_t result, int32_t lhs, int32_t rhs)
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

static inline void alu_execute(uint32_t *registers, AluOp operation, uint8_t rd32, int32_t rhs)
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

    if (argc != 2)
    {
        fprintf(stderr, "Usage: remu <program.lx>\n");
        return 1;
    }

    FILE *fin = fopen(argv[1], "rb");
    if (!fin)
    {
        perror("fopen");
        return 1;
    }

    char header[MAGIC_BYTES_SIZE];
    size_t header_read = fread(header, 1, MAGIC_BYTES_SIZE, fin);
    if (header_read < MAGIC_BYTES_SIZE || memcmp(header, magic_bytes, MAGIC_BYTES_SIZE) != 0)
    {
        fprintf(stderr, "Invalid or missing magic bytes.\n");
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
    
    // Load the code in the middle
    size_t loaded = fread(memory + TEXT_BASE, 1, MEM_SIZE - TEXT_BASE, fin);
    if (!feof(fin) && loaded == (MEM_SIZE - TEXT_BASE))
    {
        fprintf(stderr, "Warning: program may have been truncated.");
    }
    fclose(fin);

    uint32_t registers[18] = {0};
    dip = TEXT_BASE;
    dsp = STACK_BASE;

    while (1)
    {
        if (dip + 3 >= MEM_SIZE)
        {
            fprintf(stderr, "Instruction pointer out of bounds: 0x%x\n", dip);
            exit_code = ERR_BOUND;
            break;
        }

        uint8_t opcode = memory[dip];
        int length = get_length(opcode);
        uint8_t buffer[8] = {0};
        memcpy(buffer, memory + dip, length);

        uint8_t class = opcode >> 4;
        Opcode op = opcode & 0xf;

        switch (class)
        {
            case CLASS_REGREG:
            {
                uint8_t rd32 = (buffer[1] >> 4) & 0xf;
                uint8_t rs32 = buffer[1] & 0xf;
                switch (op)
                {
                    case REGREG_ADD:
                        alu_execute(registers, ALU_ADD, rd32, registers[rs32]);
                        break;
                    case REGREG_SUB:
                        alu_execute(registers, ALU_SUB, rd32, registers[rs32]);
                        break;
                    case REGREG_MUL:
                        alu_execute(registers, ALU_MUL, rd32, registers[rs32]);
                        break;
                    case REGREG_DIV:
                        if (registers[rs32] == 0)
                        {
                            fprintf(stderr, "Illegal DIV instruction: divide-by-zero at address 0x%x\n", dip);
                            exit_code = ERR_ILLINT;
                            goto halted;
                        }
                        alu_execute(registers, ALU_DIV, rd32, registers[rs32]);
                        break;
                    case REGREG_AND:
                        alu_execute(registers, ALU_AND, rd32, registers[rs32]);
                        break;
                    case REGREG_OR:
                        alu_execute(registers, ALU_OR, rd32, registers[rs32]);
                        break;
                    case REGREG_XOR:
                        alu_execute(registers, ALU_XOR, rd32, registers[rs32]);
                        break;
                    case REGREG_NOT:
                        alu_execute(registers, ALU_NOT, rd32, 0);
                        break;
                    case REGREG_MOV:
                        registers[rd32] = registers[rs32];
                        break;
                    case REGREG_SWP:
                        uint32_t temp = registers[rd32];
                        registers[rd32] = registers[rs32];
                        registers[rs32] = temp;
                        break;
                    default:
                        fprintf(stderr, "Illegal REGREG opcode 0x%x at address 0x%x\n", op, dip);
                        exit_code = ERR_ILLINT;
                        goto halted;
                }
                break;
            }
            case CLASS_REGIMM:
            {
                uint8_t r32 = (buffer[1] >> 4) & 0xf;
                uint32_t imm32 = buffer[2] | (buffer[3] << 8) | (buffer[4] << 16) | (buffer[5] << 24);
                switch (op)
                {
                    case REGIMM_ADD:
                        alu_execute(registers, ALU_ADD, r32, (int32_t)imm32);
                        break;
                    case REGIMM_SUB:
                        alu_execute(registers, ALU_SUB, r32, (int32_t)imm32);
                        break;
                    case REGIMM_MUL:
                        alu_execute(registers, ALU_MUL, r32, (int32_t)imm32);
                        break;
                    case REGIMM_DIV:
                        if (imm32 == 0)
                        {
                            fprintf(stderr, "Illegal DIV instruction: divide-by-zero at address 0x%x\n", dip);
                            exit_code = ERR_ILLINT;
                            goto halted;
                        }
                        alu_execute(registers, ALU_DIV, r32, (int32_t)imm32);
                        break;
                    case REGIMM_AND:
                        alu_execute(registers, ALU_AND, r32, (int32_t)imm32);
                        break;
                    case REGIMM_OR:
                        alu_execute(registers, ALU_OR, r32, (int32_t)imm32);
                        break;
                    case REGIMM_XOR:
                        alu_execute(registers, ALU_XOR, r32, (int32_t)imm32);
                        break;
                    case REGIMM_NOT:
                        alu_execute(registers, ALU_NOT, r32, 0);
                        break;
                    case REGIMM_MOV:
                        registers[r32] = imm32;
                        break;
                    default:
                        fprintf(stderr, "Illegal REGIMM opcode 0x%x at address 0x%x\n", op, dip);
                        exit_code = ERR_ILLINT;
                        goto halted;
                }
                break;
            }
            case CLASS_MEM:
            {
                uint8_t r32 = (buffer[1] >> 4) & 0xf;
                uint32_t imm20 = (buffer[1] & 0xf) | (buffer[2] << 4) | (buffer[3] << 12);
                switch (op)
                {
                    case MEM_LDB:
                        registers[r32] = memory[imm20];
                        break;
                    case MEM_STB:
                        memory[imm20] = (uint8_t)(registers[r32] & 0xff);
                        break;
                    case MEM_LDW:
                        registers[r32] = (uint16_t)memory[imm20] | ((uint16_t)memory[imm20 + 1] << 8);
                        break;
                    case MEM_STW:
                        memory[imm20]       = (uint8_t)(registers[r32] & 0xff);
                        memory[imm20 + 1]   = (uint8_t)((registers[r32] >> 8) & 0xff);
                        break;
                    case MEM_LDD:
                        registers[r32] = (uint32_t)memory[imm20]
                            | ((uint32_t)memory[imm20 + 1] << 8)
                            | ((uint32_t)memory[imm20 + 2] << 16)
                            | ((uint32_t)memory[imm20 + 3] << 24);
                        break;
                    case MEM_STD:
                        memory[imm20]     = (uint8_t)(registers[r32] & 0xff);
                        memory[imm20 + 1] = (uint8_t)((registers[r32] >> 8) & 0xff);
                        memory[imm20 + 2] = (uint8_t)((registers[r32] >> 16) & 0xff);
                        memory[imm20 + 3] = (uint8_t)((registers[r32] >> 24) & 0xff);
                        break;
                    default:
                        fprintf(stderr, "Illegal MEM opcode 0x%x at address 0x%x\n", op, dip);
                        exit_code = ERR_ILLINT;
                        goto halted;
                }
                break;
            }
	        case CLASS_BRANCH:
	        {
                uint32_t imm20 = (buffer[1] & 0xf) | (buffer[2] << 4) | (buffer[3] << 12);
                // We continue to avoid "dip += length;"
                switch (op)
                {
                    case BRANCH_JMP:
                        dip = imm20;
                        continue;
                    case BRANCH_JC:
                        JUMP(imm20, dstat & STAT_CF);
                        break;
                    case BRANCH_JNC:
                        JUMP(imm20, !(dstat & STAT_CF));
                        break;
                    case BRANCH_JZ:
                        JUMP(imm20, dstat & STAT_ZF);
                        break;
                    case BRANCH_JNZ:
                        JUMP(imm20, !(dstat & STAT_ZF));
                        break;
                    case BRANCH_JO:
                        JUMP(imm20, dstat & STAT_OF);
                        break;
                    case BRANCH_JNO:
                        JUMP(imm20, !(dstat & STAT_OF));
                        break;
                    case BRANCH_JS:
                        JUMP(imm20, dstat & STAT_SF);
                        break;
                    case BRANCH_JNS:
                        JUMP(imm20, !(dstat & STAT_SF));
                        break;
                    default:
                        fprintf(stderr, "Illegal BRANCH opcode %x at address %x\n", op, dip);
                        exit_code = ERR_ILLINT;
                        goto halted;
                }
                break;
            }
            case CLASS_MISC:
                switch (op)
                {
                    case MISC_HLT:
                        goto halted;
                    case MISC_NOP:
                        break;
                    default:
                        fprintf(stderr, "Illegal MISC opcode 0x%x at address 0x%x\n", op, dip);
                        exit_code = ERR_ILLINT;
                        goto halted;
                }
                break;
            default:
                fprintf(stderr, "Illegal reserved class 0x%x at address 0x%x\n", class, dip);
                exit_code = ERR_ILLINT;
                goto halted;
        }

        dip += length;
    }

halted:
    // Print the program state at the end for now (I'll remove this in the future)

    for (int i = 0; i < REG_COUNT; i++)
    {
        printf("%-14s  0x%-14x  %u\n", reg_name(i), registers[i], registers[i]);
    }

    printf("\nMemory (non-zero bytes, from 0x00000 to 0x00200):\n");
    for (int addr = 0; addr < 0x200; addr++)
    {
        if (memory[addr] != 0)
        {
            printf("0x%-12.05x  0x%-14.02x  %c\n", addr, memory[addr], (memory[addr] >= 32 && memory[addr] <= 126) ? memory[addr] : '.');
        }
    }

    free(memory);
    return exit_code;
}
