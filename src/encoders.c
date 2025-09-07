#include <ctype.h>
#include "helpers.h"
#include "encoders.h"

#define REG_COUNT 18
static const char *reg_names[REG_COUNT] = {
    "dxa", "dxt", "dxc",                        // Accumulator, temporary, counter
    "dd0", "dd1", "dd2", "dd3", "dd4", "dd5",   // Data/arguments
    "dbp", "dsp",                               // Base pointer, stack pointer
    "ds0", "ds1", "ds2", "ds3", "ds4",          // Callee-saved registers
    "dip", "dstat"                              // Instruction pointer, Status/flags
};

int reg_index(const char *reg)
{
    for (int i = 0; i < REG_COUNT; i++)
    {
        if (strcmp(reg, reg_names[i]) == 0)
        {
            return i;
        }
    }
    return -1;
}

_Bool is_register(const char *operand, int *reg_idx, uint32_t *imm32)
{
    int index = reg_index(operand);
    if (index != -1)
    {
        *reg_idx = index;
        return 1;
    }

    char *endptr;
    uint32_t imm = (uint32_t)strtoul(operand, &endptr, 0);
    // Fully consumed = valid immediate
    if (*endptr == '\0')
    {
        *imm32 = imm;
        return 0;
    }

    fprintf(stderr, "Invalid operand: %s\n", operand);
    exit(ERR_MALFORMED);
}

static EncodedInstruction make_regreg(Opcode opcode, uint8_t rd32, uint8_t rs32)
{
    EncodedInstruction ei = { .length = 2 };
    ei.bytes[0] = (CLASS_REGREG << 4) | (opcode & 0xf);
    ei.bytes[1] = ((rd32 & 0xf) << 4) | (rs32 & 0xf);
    return ei;
}

static EncodedInstruction make_regimm(Opcode opcode, uint8_t r32, uint32_t imm32)
{
    EncodedInstruction ei = { .length = 6 };
    ei.bytes[0] = (CLASS_REGIMM << 4) | (opcode & 0xf);
    ei.bytes[1] = (r32 & 0xf) << 4; // Lower nibble reserved
    ei.bytes[2] = imm32 & 0xff;
    ei.bytes[3] = (imm32 >> 8) & 0xff;
    ei.bytes[4] = (imm32 >> 16) & 0xff;
    ei.bytes[5] = (imm32 >> 24) & 0xff;
    return ei;
}

static EncodedInstruction make_mem(Opcode opcode, uint8_t r32, uint32_t imm20)
{
    EncodedInstruction ei = { .length = 4 };
    ei.bytes[0] = (CLASS_MEM << 4) | (opcode & 0xf);
    ei.bytes[1] = ((r32 & 0xf) << 4) | (imm20 & 0xf); // Squeeze the two nibbles in one byte
    ei.bytes[2] = (imm20 >> 4) & 0xff;
    ei.bytes[3] = (imm20 >> 12) & 0xff;
    return ei;
}

static EncodedInstruction make_branch(Opcode opcode, uint32_t imm20)
{
    EncodedInstruction ei = { .length = 4 };
    ei.bytes[0] = (CLASS_BRANCH << 4) | (opcode & 0xf);
    ei.bytes[1] = imm20 & 0xf;
    ei.bytes[2] = (imm20 >> 4) & 0xff;
    ei.bytes[3] = (imm20 >> 12) & 0xff;
    return ei;
}

static EncodedInstruction make_misc(Opcode opcode)
{
    EncodedInstruction ei = { .length = 1 };
    ei.bytes[0] = (CLASS_MISC << 4) | (opcode & 0xf);
    return ei;
}

EncodedInstruction enc_add(const char *rd32, const char *src)
{
    int r1 = reg_index(rd32);
    int r2;
    uint32_t imm32;
    
    if (is_register(src, &r2, &imm32))
    {
        return make_regreg(REGREG_ADD, r1, r2);
    }
    else
    {
        return make_regimm(REGIMM_ADD, r1, imm32);
    }
}

EncodedInstruction enc_sub(const char *rd32, const char *src)
{
    int r1 = reg_index(rd32);
    int r2;
    uint32_t imm32;
    
    if (is_register(src, &r2, &imm32))
    {
        return make_regreg(REGREG_SUB, r1, r2);
    }
    else
    {
        return make_regimm(REGIMM_SUB, r1, imm32);
    }
}

EncodedInstruction enc_mul(const char *rd32, const char *src)
{
    int r1 = reg_index(rd32);
    int r2;
    uint32_t imm32;
    
    if (is_register(src, &r2, &imm32))
    {
        return make_regreg(REGREG_MUL, r1, r2);
    }
    else
    {
        return make_regimm(REGIMM_MUL, r1, imm32);
    }
}

EncodedInstruction enc_div(const char *rd32, const char *src)
{
    int r1 = reg_index(rd32);
    int r2;
    uint32_t imm32;
    
    if (is_register(src, &r2, &imm32))
    {
        return make_regreg(REGREG_DIV, r1, r2);
    }
    else
    {
        return make_regimm(REGIMM_DIV, r1, imm32);
    }
}

EncodedInstruction enc_and(const char *rd32, const char *src)
{
    int r1 = reg_index(rd32);
    int r2;
    uint32_t imm32;
    
    if (is_register(src, &r2, &imm32))
    {
        return make_regreg(REGREG_AND, r1, r2);
    }
    else
    {
        return make_regimm(REGIMM_AND, r1, imm32);
    }
}

EncodedInstruction enc_or(const char *rd32, const char *src)
{
    int r1 = reg_index(rd32);
    int r2;
    uint32_t imm32;
    
    if (is_register(src, &r2, &imm32))
    {
        return make_regreg(REGREG_OR, r1, r2);
    }
    else
    {
        return make_regimm(REGIMM_OR, r1, imm32);
    }
}

EncodedInstruction enc_xor(const char *rd32, const char *src)
{
    int r1 = reg_index(rd32);
    int r2;
    uint32_t imm32;
    
    if (is_register(src, &r2, &imm32))
    {
        return make_regreg(REGREG_XOR, r1, r2);
    }
    else
    {
        return make_regimm(REGIMM_XOR, r1, imm32);
    }
}

// Not exactly reg-reg, oh well
EncodedInstruction enc_not(const char *r32, const char *)
{
    int r = reg_index(r32);
    return make_regreg(REGREG_NOT, r, 0);
}

EncodedInstruction enc_mov(const char *rd32, const char *src)
{
    int r1 = reg_index(rd32);
    int r2;
    uint32_t imm32;
    
    if (is_register(src, &r2, &imm32))
    {
        return make_regreg(REGREG_MOV, r1, r2);
    }
    else
    {
        return make_regimm(REGIMM_MOV, r1, imm32);
    }
}

EncodedInstruction enc_swp(const char *rd32, const char *rs32)
{
    int r1 = reg_index(rd32);
    int r2 = reg_index(rs32);
    _VALIDATE_REG_INDEX(r1, rd32);
    _VALIDATE_REG_INDEX(r2, rs32);
    return make_regreg(REGREG_SWP, r1, r2);
}

EncodedInstruction enc_ldb(const char *r32, const char *imm20)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_mem(MEM_LDB, r, (uint32_t)strtoul(imm20, NULL, 0));
}

EncodedInstruction enc_stb(const char *imm20, const char *r32)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_mem(MEM_STB, r, (uint32_t)strtoul(imm20, NULL, 0));
}

EncodedInstruction enc_ldw(const char *r32, const char *imm20)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_mem(MEM_LDW, r, (uint32_t)strtoul(imm20, NULL, 0));
}

EncodedInstruction enc_stw(const char *imm20, const char *r32)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_mem(MEM_STW, r, (uint32_t)strtoul(imm20, NULL, 0));
}

EncodedInstruction enc_ldd(const char *r32, const char *imm20)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_mem(MEM_LDD, r, (uint32_t)strtoul(imm20, NULL, 0));
}

EncodedInstruction enc_std(const char *imm20, const char *r32)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_mem(MEM_STD, r, (uint32_t)strtoul(imm20, NULL, 0));
}

EncodedInstruction enc_jmp(const char *imm20, const char *)
{
    return make_branch(BRANCH_JMP, (uint32_t)strtoul(imm20, NULL, 0));
}

EncodedInstruction enc_jc(const char *imm20, const char *)
{
    return make_branch(BRANCH_JC, (uint32_t)strtoul(imm20, NULL, 0));
}

EncodedInstruction enc_jnc(const char *imm20, const char *)
{
    return make_branch(BRANCH_JNC, (uint32_t)strtoul(imm20, NULL, 0));
}

EncodedInstruction enc_jz(const char *imm20, const char *)
{
    return make_branch(BRANCH_JZ, (uint32_t)strtoul(imm20, NULL, 0));
}

EncodedInstruction enc_jnz(const char *imm20, const char *)
{
    return make_branch(BRANCH_JNZ, (uint32_t)strtoul(imm20, NULL, 0));
}

EncodedInstruction enc_jo(const char *imm20, const char *)
{
    return make_branch(BRANCH_JO, (uint32_t)strtoul(imm20, NULL, 0));
}

EncodedInstruction enc_jno(const char *imm20, const char *)
{
    return make_branch(BRANCH_JNO, (uint32_t)strtoul(imm20, NULL, 0));
}

EncodedInstruction enc_js(const char *imm20, const char *)
{
    return make_branch(BRANCH_JS, (uint32_t)strtoul(imm20, NULL, 0));
}

EncodedInstruction enc_jns(const char *imm20, const char *)
{
    return make_branch(BRANCH_JNS, (uint32_t)strtoul(imm20, NULL, 0));
}

EncodedInstruction enc_hlt(const char *, const char *)
{
    return make_misc(MISC_HLT);
}

EncodedInstruction enc_nop(const char *, const char *)
{
    return make_misc(MISC_NOP);
}

InstructionHandler instruction_table[] = {
    {"add", enc_add},
    {"sub", enc_sub},
    {"mul", enc_mul},
    {"div", enc_div},
    {"and", enc_and},
    {"or", enc_or},
    {"xor", enc_xor},
    {"not", enc_not},
    {"mov", enc_mov},
    {"swp", enc_swp},
    {"ldb", enc_ldb},
    {"stb", enc_stb},
    {"ldw", enc_ldw},
    {"stw", enc_stw},
    {"ldd", enc_ldd},
    {"std", enc_std},
    {"jmp", enc_jmp},
    {"jc", enc_jc},
    {"jnc", enc_jnc},
    {"jz", enc_jz},
    {"jnz", enc_jnz},
    {"jo", enc_jo},
    {"jno", enc_jno},
    {"js", enc_js},
    {"jns", enc_jns},
    {"hlt", enc_hlt},
    {"nop", enc_nop}
};
const uint8_t instruction_count = sizeof(instruction_table) / sizeof(instruction_table[0]);