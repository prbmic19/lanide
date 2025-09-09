#include "helpers.h"
#include "encoders.h"

#define ENCODER_DEFINE(mnemonic, operand1, operand2) EncodedInstruction enc_##mnemonic(const char *operand1, const char *operand2)
#define ENCODER_ADD(mnemonic) {#mnemonic, enc_##mnemonic}

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

ENCODER_DEFINE(add, rd32, src)
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

ENCODER_DEFINE(sub, rd32, src)
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

ENCODER_DEFINE(mul, rd32, src)
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

ENCODER_DEFINE(div, rd32, src)
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

ENCODER_DEFINE(and, rd32, src)
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

ENCODER_DEFINE(or, rd32, src)
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

ENCODER_DEFINE(xor, rd32, src)
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

ENCODER_DEFINE(not, r32, )
{
    int r = reg_index(r32);
    return make_regreg(REGREG_NOT, r, 0);
}

ENCODER_DEFINE(mov, rd32, src)
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

ENCODER_DEFINE(xchg, rd32, rs32)
{
    int r1 = reg_index(rd32);
    int r2 = reg_index(rs32);
    _VALIDATE_REG_INDEX(r1, rd32);
    _VALIDATE_REG_INDEX(r2, rs32);
    return make_regreg(REGREG_XCHG, r1, r2);
}

ENCODER_DEFINE(push, r32, )
{
    int r = reg_index(r32);
    return make_regreg(REGREG_PUSH, r, 0);
}

ENCODER_DEFINE(pop, r32, )
{
    int r = reg_index(r32);
    return make_regreg(REGREG_POP, r, 0);
}

ENCODER_DEFINE(ldb, r32, imm20)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_mem(MEM_LDB, r, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(stb, imm20, r32)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_mem(MEM_STB, r, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(ldw, r32, imm20)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_mem(MEM_LDW, r, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(stw, imm20, r32)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_mem(MEM_STW, r, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(ldd, r32, imm20)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_mem(MEM_LDD, r, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(std, imm20, r32)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_mem(MEM_STD, r, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(jmp, imm20, )
{
    return make_branch(BRANCH_JMP, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(jc, imm20, )
{
    return make_branch(BRANCH_JC, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(jnc, imm20, )
{
    return make_branch(BRANCH_JNC, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(jz, imm20, )
{
    return make_branch(BRANCH_JZ, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(jnz, imm20, )
{
    return make_branch(BRANCH_JNZ, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(jo, imm20, )
{
    return make_branch(BRANCH_JO, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(jno, imm20, )
{
    return make_branch(BRANCH_JNO, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(js, imm20, )
{
    return make_branch(BRANCH_JS, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(jns, imm20, )
{
    return make_branch(BRANCH_JNS, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(call, imm20, )
{
    return make_branch(BRANCH_CALL, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(hlt, , )
{
    return make_misc(MISC_HLT);
}

ENCODER_DEFINE(nop, , )
{
    return make_misc(MISC_NOP);
}

ENCODER_DEFINE(ret, , )
{
    return make_misc(MISC_RET);
}

InstructionHandler instruction_table[] = {
    ENCODER_ADD(add),
    ENCODER_ADD(sub),
    ENCODER_ADD(mul),
    ENCODER_ADD(div),
    ENCODER_ADD(and),
    ENCODER_ADD(or),
    ENCODER_ADD(xor),
    ENCODER_ADD(not),
    ENCODER_ADD(mov),
    ENCODER_ADD(xchg),
    ENCODER_ADD(push),
    ENCODER_ADD(pop),
    ENCODER_ADD(ldb),
    ENCODER_ADD(stb),
    ENCODER_ADD(ldw),
    ENCODER_ADD(stw),
    ENCODER_ADD(ldd),
    ENCODER_ADD(std),
    ENCODER_ADD(jmp),
    ENCODER_ADD(jc),
    ENCODER_ADD(jnc),
    ENCODER_ADD(jz),
    ENCODER_ADD(jnz),
    ENCODER_ADD(jo),
    ENCODER_ADD(jno),
    ENCODER_ADD(js),
    ENCODER_ADD(jns),
    ENCODER_ADD(call),
    ENCODER_ADD(hlt),
    ENCODER_ADD(nop),
    ENCODER_ADD(ret),
};
const uint8_t instruction_count = sizeof(instruction_table) / sizeof(instruction_table[0]);