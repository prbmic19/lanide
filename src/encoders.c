#include "helpers.h"
#include "encoders.h"

#define ENCODER_DEFINE(mnemonic, operand1, operand2) struct instruction enc_##mnemonic(const char *operand1, const char *operand2)
#define ENCODER_ADD(mnemonic) {#mnemonic, enc_##mnemonic}

#define REG_COUNT 18
static const char *reg_names[REG_COUNT] = {
    "dxa", "dxt", "dxc",                        // Accumulator, temporary, counter
    "dd0", "dd1", "dd2", "dd3", "dd4", "dd5",   // Data/arguments
    "dbp", "dsp",                               // Base pointer, stack pointer
    "ds0", "ds1", "ds2", "ds3", "ds4",          // Callee-saved registers
    "dip", "dstat"                              // Instruction pointer, Status/flags
};

static int reg_index(const char *reg)
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

static bool is_register(const char *operand, int *reg_idx, uint32_t *imm32)
{
    int index = reg_index(operand);
    if (index != -1)
    {
        *reg_idx = index;
        return true;
    }

    char *endptr;
    uint32_t imm = (uint32_t)strtoul(operand, &endptr, 0);
    // Fully consumed = valid immediate
    if (*endptr == '\0')
    {
        *imm32 = imm;
        return false;
    }

    fprintf(stderr, "Error! Invalid operand: %s\n", operand);
    exit(ERR_MALFORMED);
}

static struct instruction make_regreg(enum instruction_type it, uint8_t rd32, uint8_t rs32)
{
    struct instruction ei;
    if (it == IT_REGREG_PUSHFD || it == IT_REGREG_POPFD)
    {
        ei.length = 1;
        ei.bytes[0] = (IC_REGREG << 4) | (it & 0xf);
    }
    else
    {
        ei.length = 2;
        ei.bytes[0] = (IC_REGREG << 4) | (it & 0xf);
        ei.bytes[1] = ((rd32 & 0xf) << 4) | (rs32 & 0xf);
    }
    return ei;
}

static struct instruction make_xregreg(enum instruction_type it, uint8_t rd32, uint8_t rs32)
{
    struct instruction ei = { .length = 2 };
    ei.bytes[0] = (IC_XREGREG << 4) | (it & 0xf);
    ei.bytes[1] = ((rd32 & 0xf) << 4) | (rs32 & 0xf);
    return ei;
}

// We TRUST that we pass the correct argument for immsize
static struct instruction make_regimm(enum instruction_type it, uint8_t r32, uint32_t imm, uint8_t immsize)
{
    struct instruction ei;
    ei.bytes[0] = (IC_REGIMM << 4) | (it & 0xf);
    ei.bytes[1] = ((r32 & 0xf) << 4) | (immsize & 0xf);
    switch (immsize)
    {
        case 0:
            ei.length = 3;
            ei.bytes[2] = imm & 0xff;
            break;
        case 1:
            ei.length = 4;
            ei.bytes[2] = imm & 0xff;
            ei.bytes[3] = (imm >> 8) & 0xff;
            break;
        case 2:
            ei.length = 6;
            ei.bytes[2] = imm & 0xff;
            ei.bytes[3] = (imm >> 8) & 0xff;
            ei.bytes[4] = (imm >> 16) & 0xff;
            ei.bytes[5] = (imm >> 24) & 0xff;
            break;
        default:
            fprintf(stderr, TXT_ERROR "Invalid immsize: %u\n", immsize);
            exit(ERR_MALFORMED);
    }
    return ei;
}

static struct instruction make_mem(enum instruction_type it, uint8_t r32, uint32_t imm20)
{
    struct instruction ei = { .length = 4 };
    ei.bytes[0] = (IC_MEM << 4) | (it & 0xf);
    ei.bytes[1] = ((r32 & 0xf) << 4) | (imm20 & 0xf);
    ei.bytes[2] = (imm20 >> 4) & 0xff;
    ei.bytes[3] = (imm20 >> 12) & 0xff;
    return ei;
}

static struct instruction make_branch(enum instruction_type it, uint32_t imm20)
{
    struct instruction ei;
    if (it == IT_BRANCH_RET)
    {
        ei.length = 1;
        ei.bytes[0] = (IC_BRANCH << 4) | (IT_BRANCH_RET & 0xf);
    }
    else
    {
        ei.length = 4;
        ei.bytes[0] = (IC_BRANCH << 4) | (it & 0xf);
        ei.bytes[1] = imm20 & 0xf;
        ei.bytes[2] = (imm20 >> 4) & 0xff;
        ei.bytes[3] = (imm20 >> 12) & 0xff;
    }
    return ei;
}

static struct instruction make_xbranch(enum instruction_type it, uint32_t imm20)
{
    struct instruction ei = { .length = 4 };
    ei.bytes[0] = (IC_XBRANCH << 4) | (it & 0xf);
    ei.bytes[1] = imm20 & 0xf;
    ei.bytes[2] = (imm20 >> 4) & 0xff;
    ei.bytes[3] = (imm20 >> 12) & 0xff;
    return ei;
}

static struct instruction make_misc(enum instruction_type it)
{
    struct instruction ei = { .length = 1 };
    ei.bytes[0] = (IC_MISC << 4) | (it & 0xf);
    return ei;
}

ENCODER_DEFINE(add, rd32, src)
{
    int r1 = reg_index(rd32);
    int r2 = 0;
    uint32_t imm = 0;
    
    if (is_register(src, &r2, &imm))
    {
        return make_regreg(IT_REGREG_ADD, r1, r2);
    }
    else
    {
        uint8_t immsize = (imm < 0x100)
            ? 0
            : (imm < 0x10000)
            ? 1
            : 2;
        return make_regimm(IT_REGIMM_ADD, r1, imm, immsize);
    }
}

ENCODER_DEFINE(sub, rd32, src)
{
    int r1 = reg_index(rd32);
    int r2 = 0;
    uint32_t imm = 0;
    
    if (is_register(src, &r2, &imm))
    {
        return make_regreg(IT_REGREG_SUB, r1, r2);
    }
    else
    {
        uint8_t immsize = (imm < 0x100)
            ? 0
            : (imm < 0x10000)
            ? 1
            : 2;
        return make_regimm(IT_REGIMM_SUB, r1, imm, immsize);
    }
}

ENCODER_DEFINE(mul, rd32, src)
{
    int r1 = reg_index(rd32);
    int r2 = 0;
    uint32_t imm = 0;
    
    if (is_register(src, &r2, &imm))
    {
        return make_regreg(IT_REGREG_MUL, r1, r2);
    }
    else
    {
        uint8_t immsize = (imm < 0x100)
            ? 0
            : (imm < 0x10000)
            ? 1
            : 2;
        return make_regimm(IT_REGIMM_MUL, r1, imm, immsize);
    }
}

ENCODER_DEFINE(div, rd32, src)
{
    int r1 = reg_index(rd32);
    int r2 = 0;
    uint32_t imm = 0;
    
    if (is_register(src, &r2, &imm))
    {
        return make_regreg(IT_REGREG_DIV, r1, r2);
    }
    else
    {
        uint8_t immsize = (imm < 0x100)
            ? 0
            : (imm < 0x10000)
            ? 1
            : 2;
        return make_regimm(IT_REGIMM_DIV, r1, imm, immsize);
    }
}

ENCODER_DEFINE(and, rd32, src)
{
    int r1 = reg_index(rd32);
    int r2 = 0;
    uint32_t imm = 0;
    
    if (is_register(src, &r2, &imm))
    {
        return make_regreg(IT_REGREG_AND, r1, r2);
    }
    else
    {
        uint8_t immsize = (imm < 0x100)
            ? 0
            : (imm < 0x10000)
            ? 1
            : 2;
        return make_regimm(IT_REGIMM_AND, r1, imm, immsize);
    }
}

ENCODER_DEFINE(or, rd32, src)
{
    int r1 = reg_index(rd32);
    int r2 = 0;
    uint32_t imm = 0;
    
    if (is_register(src, &r2, &imm))
    {
        return make_regreg(IT_REGREG_OR, r1, r2);
    }
    else
    {
        uint8_t immsize = (imm < 0x100)
            ? 0
            : (imm < 0x10000)
            ? 1
            : 2;
        return make_regimm(IT_REGIMM_OR, r1, imm, immsize);
    }
}

ENCODER_DEFINE(xor, rd32, src)
{
    int r1 = reg_index(rd32);
    int r2 = 0;
    uint32_t imm = 0;
    
    if (is_register(src, &r2, &imm))
    {
        return make_regreg(IT_REGREG_XOR, r1, r2);
    }
    else
    {
        uint8_t immsize = (imm < 0x100)
            ? 0
            : (imm < 0x10000)
            ? 1
            : 2;
        return make_regimm(IT_REGIMM_XOR, r1, imm, immsize);
    }
}

ENCODER_DEFINE(not, r32, )
{
    int r = reg_index(r32);
    return make_regreg(IT_REGREG_NOT, r, 0);
}

ENCODER_DEFINE(neg, r32, )
{
    int r = reg_index(r32);
    return make_regreg(IT_REGREG_NEG, r, 0);
}

ENCODER_DEFINE(mov, rd32, src)
{
    int r1 = reg_index(rd32);
    int r2 = 0;
    uint32_t imm = 0;
    
    if (is_register(src, &r2, &imm))
    {
        return make_regreg(IT_REGREG_MOV, r1, r2);
    }
    else
    {
        uint8_t immsize = (imm < 0x100)
            ? 0
            : (imm < 0x10000)
            ? 1
            : 2;
        return make_regimm(IT_REGIMM_MOV, r1, imm, immsize);
    }
}

ENCODER_DEFINE(cmp, rd32, src)
{
    int r1 = reg_index(rd32);
    int r2 = 0;
    uint32_t imm = 0;
    
    if (is_register(src, &r2, &imm))
    {
        return make_regreg(IT_REGREG_CMP, r1, r2);
    }
    else
    {
        uint8_t immsize = (imm < 0x100)
            ? 0
            : (imm < 0x10000)
            ? 1
            : 2;
        return make_regimm(IT_REGIMM_CMP, r1, imm, immsize);
    }
}

ENCODER_DEFINE(test, rd32, src)
{
    int r1 = reg_index(rd32);
    int r2 = 0;
    uint32_t imm = 0;
    
    if (is_register(src, &r2, &imm))
    {
        return make_regreg(IT_REGREG_TEST, r1, r2);
    }
    else
    {
        uint8_t immsize = (imm < 0x100)
            ? 0
            : (imm < 0x10000)
            ? 1
            : 2;
        return make_regimm(IT_REGIMM_TEST, r1, imm, immsize);
    }
}

ENCODER_DEFINE(push, r32, __UNUSED_PARAM(a))
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_regreg(IT_REGREG_PUSH, r, 0);
}

ENCODER_DEFINE(pushfd, __UNUSED_PARAM(a), __UNUSED_PARAM(b))
{
    return make_regreg(IT_REGREG_PUSHFD, 0, 0);
}

ENCODER_DEFINE(pop, r32, __UNUSED_PARAM(a))
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_regreg(IT_REGREG_POP, r, 0);
}

ENCODER_DEFINE(popfd, __UNUSED_PARAM(a), __UNUSED_PARAM(b))
{
    return make_regreg(IT_REGREG_POPFD, 0, 0);
}

ENCODER_DEFINE(xchg, rd32, rs32)
{
    int r1 = reg_index(rd32);
    int r2 = reg_index(rs32);
    _VALIDATE_REG_INDEX(r1, rd32);
    _VALIDATE_REG_INDEX(r2, rs32);
    return make_xregreg(IT_XREGREG_XCHG, r1, r2);
}

ENCODER_DEFINE(ldip, r32, __UNUSED_PARAM(a))
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_xregreg(IT_XREGREG_LDIP, r, 0);
}

ENCODER_DEFINE(ldb, r32, imm20)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_mem(IT_MEM_LDB, r, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(ldw, r32, imm20)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_mem(IT_MEM_LDW, r, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(ldd, r32, imm20)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_mem(IT_MEM_LDD, r, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(stb, imm20, r32)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_mem(IT_MEM_STB, r, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(stw, imm20, r32)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_mem(IT_MEM_STW, r, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(std, imm20, r32)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_mem(IT_MEM_STD, r, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(jmp, src, __UNUSED_PARAM(a))
{
    int r = 0;
    uint32_t imm = 0;

    if (is_register(src, &r, &imm))
    {
        return make_xregreg(IT_XREGREG_JMP, r, 0);
    }
    else
    {
        return make_branch(IT_BRANCH_JMP, imm);
    }
}

ENCODER_DEFINE(call, src, __UNUSED_PARAM(a))
{
    int r = 0;
    uint32_t imm = 0;

    if (is_register(src, &r, &imm))
    {
        return make_xregreg(IT_XREGREG_CALL, r, 0);
    }
    else
    {
        return make_branch(IT_BRANCH_CALL, imm);
    }
}

ENCODER_DEFINE(ret, __UNUSED_PARAM(a), __UNUSED_PARAM(b))
{
    return make_branch(IT_BRANCH_RET, 0);
}

ENCODER_DEFINE(jc, imm20, __UNUSED_PARAM(a))
{
    return make_xbranch(IT_XBRANCH_JC, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(jz, imm20, __UNUSED_PARAM(a))
{
    return make_xbranch(IT_XBRANCH_JZ, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(jo, imm20, __UNUSED_PARAM(a))
{
    return make_xbranch(IT_XBRANCH_JO, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(js, imm20, __UNUSED_PARAM(a))
{
    return make_xbranch(IT_XBRANCH_JS, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(jnc, imm20, __UNUSED_PARAM(a))
{
    return make_xbranch(IT_XBRANCH_JNC, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(jnz, imm20, __UNUSED_PARAM(a))
{
    return make_xbranch(IT_XBRANCH_JNZ, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(jno, imm20, __UNUSED_PARAM(a))
{
    return make_xbranch(IT_XBRANCH_JNO, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(jns, imm20, __UNUSED_PARAM(a))
{
    return make_xbranch(IT_XBRANCH_JNS, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(jg, imm20, __UNUSED_PARAM(a))
{
    return make_xbranch(IT_XBRANCH_JG, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(jge, imm20, __UNUSED_PARAM(a))
{
    return make_xbranch(IT_XBRANCH_JGE, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(jl, imm20, __UNUSED_PARAM(a))
{
    return make_xbranch(IT_XBRANCH_JL, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(jle, imm20, __UNUSED_PARAM(a))
{
    return make_xbranch(IT_XBRANCH_JLE, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(ja, imm20, __UNUSED_PARAM(a))
{
    return make_xbranch(IT_XBRANCH_JA, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(jbe, imm20, __UNUSED_PARAM(a))
{
    return make_xbranch(IT_XBRANCH_JBE, (uint32_t)strtoul(imm20, NULL, 0));
}

ENCODER_DEFINE(hlt, __UNUSED_PARAM(a), __UNUSED_PARAM(b))
{
    return make_misc(IT_MISC_HLT);
}

ENCODER_DEFINE(nop, __UNUSED_PARAM(a), __UNUSED_PARAM(b))
{
    return make_misc(IT_MISC_NOP);
}

const struct instruction_handler instruction_table[] = {
    ENCODER_ADD(add),
    ENCODER_ADD(sub),
    ENCODER_ADD(mul),
    ENCODER_ADD(div),
    ENCODER_ADD(and),
    ENCODER_ADD(or),
    ENCODER_ADD(xor),
    ENCODER_ADD(not),
    ENCODER_ADD(mov),
    ENCODER_ADD(cmp),
    ENCODER_ADD(test),
    ENCODER_ADD(push),
    ENCODER_ADD(pushfd),
    ENCODER_ADD(pop),
    ENCODER_ADD(popfd),
    ENCODER_ADD(xchg),
    ENCODER_ADD(ldip),
    ENCODER_ADD(ldb),
    ENCODER_ADD(ldw),
    ENCODER_ADD(ldd),
    ENCODER_ADD(stb),
    ENCODER_ADD(stw),
    ENCODER_ADD(std),
    ENCODER_ADD(jmp),
    ENCODER_ADD(call),
    ENCODER_ADD(ret),
    ENCODER_ADD(jc),
    ENCODER_ADD(jz),
    {"je", enc_jz},
    ENCODER_ADD(jo),
    ENCODER_ADD(js),
    ENCODER_ADD(jnc),
    ENCODER_ADD(jnz),
    {"jne", enc_jnz},
    ENCODER_ADD(jno),
    ENCODER_ADD(jns),
    ENCODER_ADD(jg),
    ENCODER_ADD(jge),
    ENCODER_ADD(jl),
    ENCODER_ADD(jle),
    ENCODER_ADD(ja),
    {"jae", enc_jnc},
    {"jb", enc_jc},
    ENCODER_ADD(jbe),
    ENCODER_ADD(hlt),
    ENCODER_ADD(nop),
};
const uint8_t instruction_count = sizeof(instruction_table) / sizeof(instruction_table[0]);