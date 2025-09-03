#include "helpers.h"

static inline uint32_t fetch_le32(const uint8_t *memory, size_t pc)
{
    return (uint32_t)memory[pc]
        | ((uint32_t)memory[pc + 1] << 8)
        | ((uint32_t)memory[pc + 2] << 16)
        | ((uint32_t)memory[pc + 3] << 24);
}

const char *reg_name(int index)
{
    if (index >= 0 && index < NUM_REGS)
    {
        return reg_names[index];
    }
    return "(bad)";
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
    size_t header_read = fread(header, 1, 5, fin);
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
#define dip registers[16]
    dip = TEXT_BASE;

    while (1)
    {
        if (dip + 3 >= MEM_SIZE)
        {
            fprintf(stderr, "instruction pointer out of bounds: 0x%x\n", dip);
            exit_code = ERR_BOUND;
            break;
        }

        uint32_t instruction = fetch_le32(memory, dip);
        InstructionClass iclass = GET_CLASS(instruction);
        uint8_t subop = GET_SUBOP(instruction);

        switch (iclass)
        {
            case CLASS_RR:
            {
                uint8_t rd32 = GET_RR_RD32(instruction);
                uint8_t rs32 = GET_RR_RS32(instruction);
                switch (subop)
                {
                    case RR_MOV:
                        registers[rd32] = registers[rs32];
                        break;
                    case RR_ADD:
                        registers[rd32] += registers[rs32];
                        break;
                    case RR_SUB:
                        registers[rd32] -= registers[rs32];
                        break;
                    default:
                        fprintf(stderr, "Illegal RR subop 0x%x at address 0x%x\n", subop, dip);
                        exit_code = ERR_ILLINT;
                        goto halted;
                }
                break;
            }
            case CLASS_RI:
            {
                uint8_t r32 = GET_RI_R32(instruction);
                uint32_t imm20 = GET_RI_IMM20(instruction);
                switch (subop)
                {
                    case RI_MOV:
                        registers[r32] = imm20;
                        break;
                    case RI_ADD:
                        registers[r32] += imm20;
                        break;
                    case RI_SUB:
                        registers[r32] -= imm20;
                        break;
                    default:
                        fprintf(stderr, "Illegal RI subop 0x%x at address 0x%x\n", subop, dip);
                        exit_code = ERR_ILLINT;
                        goto halted;
                }
                break;
            }
            case CLASS_MEM:
            {
                uint8_t r32 = GET_MEM_R32(instruction);
                uint32_t imm20 = GET_MEM_IMM20(instruction);
                switch (subop)
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
                        fprintf(stderr, "Illegal MEM subop 0x%x at address 0x%x\n", subop, dip);
                        exit_code = ERR_ILLINT;
                        goto halted;
                }
                break;
            }
            case CLASS_SYS:
            {
                switch (subop)
                {
                    case SYS_HLT:
                        goto halted;
                    default:
                        fprintf(stderr, "Illegal SYS subop 0x%x at address 0x%x\n", subop, dip);
                        exit_code = ERR_ILLINT;
                        goto halted;
                }
                break;
            }
            default:
                fprintf(stderr, "Illegal class 0x%x at address 0x%x\n", (int)iclass, dip);
                exit_code = ERR_ILLINT;
                goto halted;
        }

        dip += 4;
#undef dip
    }

halted:
    // Print the program state at the end for now (I'll remove this in the future)

    for (int i = 0; i < NUM_REGS; i++)
    {
        printf("%s\t0x%x\t%u\n", reg_name(i), registers[i], registers[i]);
    }

    printf("\nMemory (nonzero bytes, from 0x00000 to 0x00200):\n");
    for (int addr = 0; addr < 0x200; addr++)
    {
        if (memory[addr] != 0)
        {
            printf("[0x%05x]\t0x%02x\t%u\n", addr, memory[addr], memory[addr]);
        }
    }

    free(memory);
    return exit_code;
}