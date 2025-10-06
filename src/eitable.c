/** Definition of encoders for instructions. */

#include "definitions.h"
#include "eitable.h"
#include "diag.h"

// Macro to define encoders.
#define ENCODER_DEFINE(mnemonic, ei, destination, source) \
    void enc_##mnemonic(struct instruction *ei, const char *restrict destination, const char *restrict source)

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

// Returns the index of a register. Returns -1 if the argument passed is not a valid register.
static int reg_index(const char *reg)
{
    for (int i = 0; i < REG_COUNT; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            if (strcmp(reg, reg_names[i][j]) == 0)
            {
                return i;
            }
        }
    }
    return -1;
}

// Well... the function name explains it.
static inline enum instruction_type get_prefix_for_size(uint16_t operand_size)
{
    switch (operand_size)
    {
        case 8:
            return IT_PREFIX_OS8;
        case 16:
            return IT_PREFIX_OS16;
        case 32:
            return IT_PREFIX_OS32;
        case 64:
            return 0;
        default:
            emit_error("invalid operand size: %u", operand_size);
            return 0;
    }
}

// Prepends a byte to an instruction. Useful for when adding prefixes.
static void prepend_byte(struct instruction *ei, uint8_t byte)
{
    if (ei->length >= MAX_INSTRUCTION_LENGTH)
    {
        emit_fatal("instruction too long to prepend a byte");
        return;
    }

    // Moves each byte left by one
    memmove(ei->bytes + 1, ei->bytes, ei->length);

    ei->bytes[0] = byte;
    ei->length++;
}

// Checks if the operand is a register or not, and sets the appropriate variable.
static bool is_register(const char *operand, int *reg_idx, u64_it *imm64)
{
    // Check if it's a register, if so, set reg_idx and return true.
    int index = reg_index(operand);
    if (index != -1)
    {
        *reg_idx = index;
        return true;
    }

    char *endptr = NULL;
    u64_it imm = strtoull(operand, &endptr, 0);
    // If it was fully consumed, it must be an immediate
    if (*endptr == '\0')
    {
        *imm64 = imm;
        return false;
    }

    // The operand is neither a register or an immediate.
    emit_error("invalid operand: '%s'", operand);
    return false;
}

// Encodes IC_REGREG instructions.
static void make_regreg(struct instruction *ei, enum instruction_type it, uint8_t rd64, uint8_t rs64)
{
    ei->length = 2;
    ei->bytes[0] = (IC_REGREG << 4) | (it & 0xf);
    ei->bytes[1] = ((rd64 & 0xf) << 4) | (rs64 & 0xf);

    if (it == IT_REGREG_PUSHFQ || it == IT_REGREG_POPFQ)
    {
        ei->length = 1;
        ei->bytes[1] = 0;
    }
    else if (ei->operand_size != 64)
    {
        enum instruction_type prefix = get_prefix_for_size(ei->operand_size);
        prepend_byte(ei, (IC_PREFIX << 4) | (prefix & 0xf));
    }
}

// Encodes IC_XREGREG instructions.
static void make_xregreg(struct instruction *ei, enum instruction_type it, uint8_t rd64, uint8_t rs64)
{
    ei->length = 2;
    ei->bytes[0] = (IC_REGREG << 4) | (it & 0xf);
    ei->bytes[1] = ((rd64 & 0xf) << 4) | (rs64 & 0xf);

    if (ei->operand_size != 64)
    {
        enum instruction_type prefix = get_prefix_for_size(ei->operand_size);
        prepend_byte(ei, (IC_PREFIX << 4) | (prefix & 0xf));
    }
}

// Encodes IC_REGIMM instructions.
static void make_regimm(struct instruction *ei, enum instruction_type it, uint8_t r64, u64_it imm)
{
    ei->bytes[0] = (IC_REGIMM << 4) | (it & 0xf),
    ei->bytes[1] = (r64 & 0xf) << 4;

    switch (ei->operand_size)
    {
        case 8:
            if (imm > UINT8_MAX)
            {
                emit_warning("byte operand exceeds bounds");
            }
            ei->length = 3;
            ei->bytes[2] = imm & 0xff;
            prepend_byte(ei, (IC_PREFIX << 4) | IT_PREFIX_OS8);
            break;
        case 16:
            if (imm > UINT16_MAX)
            {
                emit_warning("word operand exceeds bounds");
            }
            ei->length = 4;
            ei->bytes[2] = imm & 0xff;
            ei->bytes[3] = (imm >> 8) & 0xff;
            prepend_byte(ei, (IC_PREFIX << 4) | IT_PREFIX_OS16);
            break;
        case 32:
            if (imm > UINT32_MAX)
            {
                emit_warning("dword operand exceeds bounds");
            }
            ei->length = 6;
            ei->bytes[2] = imm & 0xff;
            ei->bytes[3] = (imm >> 8) & 0xff;
            ei->bytes[4] = (imm >> 16) & 0xff;
            ei->bytes[5] = (imm >> 24) & 0xff;
            prepend_byte(ei, (IC_PREFIX << 4) | IT_PREFIX_OS32);
            break;
        case 64:
            ei->length = 10;
            ei->bytes[2] = imm & 0xff;
            ei->bytes[3] = (imm >> 8) & 0xff;
            ei->bytes[4] = (imm >> 16) & 0xff;
            ei->bytes[5] = (imm >> 24) & 0xff;
            ei->bytes[6] = (imm >> 32) & 0xff;
            ei->bytes[7] = (imm >> 40) & 0xff;
            ei->bytes[8] = (imm >> 48) & 0xff;
            ei->bytes[9] = (imm >> 56) & 0xff;
            break;
        // Shouldn't be possible, but it's better to be safe than sorry
        default:
            emit_error("invalid operand size: %u", ei->operand_size);
    }
}

// Encodes IC_MEM instructions.
static void make_mem(struct instruction *ei, enum instruction_type it, uint8_t r64, u64_it addr24)
{
    ei->length = 5;
    ei->bytes[0] = (IC_MEM << 4) | (it & 0xf);
    ei->bytes[1] = (r64 & 0xf) << 4;
    ei->bytes[2] = addr24 & 0xff;
    ei->bytes[3] = (addr24 >> 8) & 0xff;
    ei->bytes[4] = (addr24 >> 16) & 0xff;
}

// Encodes IC_BRANCH instructions.
static void make_branch(struct instruction *ei, enum instruction_type it, u64_it addr24)
{
    if (it == IT_BRANCH_RET)
    {
        ei->length = 1;
        ei->bytes[0] = (IC_BRANCH << 4) | IT_BRANCH_RET;
        return;
    }

    ei->length = 4;
    ei->bytes[0] = (IC_BRANCH << 4) | (it & 0xf);
    ei->bytes[1] = addr24 & 0xff;
    ei->bytes[2] = (addr24 >> 8) & 0xff;
    ei->bytes[3] = (addr24 >> 16) & 0xff;
}

// Encodes IC_XBRANCH instructions.
static void make_xbranch(struct instruction *ei, enum instruction_type it, u64_it addr24)
{
    ei->length = 4;
    ei->bytes[0] = (IC_XBRANCH << 4) | (it & 0xf);
    ei->bytes[1] = addr24 & 0xff;
    ei->bytes[2] = (addr24 >> 8) & 0xff;
    ei->bytes[3] = (addr24 >> 16) & 0xff;
}

// Encodes IC_MISC instructions.
static void make_misc(struct instruction *ei, enum instruction_type it)
{
    ei->length = 1;
    ei->bytes[0] = (IC_MISC << 4) | (it & 0xf);
}

/**
 * The code below defines the encoder for each mnemonic.
 * Some mnemonics are overloaded, encoding different classes based on the operand.
 */

ENCODER_DEFINE(add, ei, rd64, src)
{
    int r1 = reg_index(rd64);
    int r2 = 0;
    u64_it imm = 0;

    if (is_register(src, &r2, &imm))
    {
        make_regreg(ei, IT_REGREG_ADD, r1, r2);
    }
    else
    {
        make_regimm(ei, IT_REGIMM_ADD, r1, imm);
    }
}

ENCODER_DEFINE(sub, ei, rd64, src)
{
    int r1 = reg_index(rd64);
    int r2 = 0;
    u64_it imm = 0;

    if (is_register(src, &r2, &imm))
    {
        make_regreg(ei, IT_REGREG_SUB, r1, r2);
    }
    else
    {
        make_regimm(ei, IT_REGIMM_SUB, r1, imm);
    }
}

ENCODER_DEFINE(mul, ei, rd64, src)
{
    int r1 = reg_index(rd64);
    int r2 = 0;
    u64_it imm = 0;

    if (is_register(src, &r2, &imm))
    {
        make_regreg(ei, IT_REGREG_MUL, r1, r2);
    }
    else
    {
        make_regimm(ei, IT_REGIMM_MUL, r1, imm);
    }
}

ENCODER_DEFINE(mulh, ei, rd64, src)
{
    int r1 = reg_index(rd64);
    int r2 = 0;
    u64_it imm = 0;

    if (is_register(src, &r2, &imm))
    {
        make_regreg(ei, IT_XREGREG_MULH, r1, r2);
    }
    else
    {
        make_regimm(ei, IT_REGIMM_MULH, r1, imm);
    }
}

ENCODER_DEFINE(smulh, ei, rd64, src)
{
    int r1 = reg_index(rd64);
    int r2 = 0;
    u64_it imm = 0;

    if (is_register(src, &r2, &imm))
    {
        make_regreg(ei, IT_XREGREG_SMULH, r1, r2);
    }
    else
    {
        make_regimm(ei, IT_REGIMM_SMULH, r1, imm);
    }
}

ENCODER_DEFINE(div, ei, rd64, src)
{
    int r1 = reg_index(rd64);
    int r2 = 0;
    u64_it imm = 0;

    if (is_register(src, &r2, &imm))
    {
        make_regreg(ei, IT_REGREG_DIV, r1, r2);
    }
    else
    {
        make_regimm(ei, IT_REGIMM_DIV, r1, imm);
    }
}

ENCODER_DEFINE(sdiv, ei, rd64, src)
{
    int r1 = reg_index(rd64);
    int r2 = 0;
    u64_it imm = 0;

    if (is_register(src, &r2, &imm))
    {
        make_xregreg(ei, IT_XREGREG_SDIV, r1, r2);
    }
    else
    {
        make_regimm(ei, IT_REGIMM_SDIV, r1, imm);
    }
}

ENCODER_DEFINE(and, ei, rd64, src)
{
    int r1 = reg_index(rd64);
    int r2 = 0;
    u64_it imm = 0;

    if (is_register(src, &r2, &imm))
    {
        make_regreg(ei, IT_REGREG_AND, r1, r2);
    }
    else
    {
        make_regimm(ei, IT_REGIMM_AND, r1, imm);
    }
}

ENCODER_DEFINE(or, ei, rd64, src)
{
    int r1 = reg_index(rd64);
    int r2 = 0;
    u64_it imm = 0;

    if (is_register(src, &r2, &imm))
    {
        make_regreg(ei, IT_REGREG_OR, r1, r2);
    }
    else
    {
        make_regimm(ei, IT_REGIMM_OR, r1, imm);
    }
}

ENCODER_DEFINE(xor, ei, rd64, src)
{
    int r1 = reg_index(rd64);
    int r2 = 0;
    u64_it imm = 0;

    if (is_register(src, &r2, &imm))
    {
        make_regreg(ei, IT_REGREG_XOR, r1, r2);
    }
    else
    {
        make_regimm(ei, IT_REGIMM_XOR, r1, imm);
    }
}

ENCODER_DEFINE(not, ei, r64, a)
{
    (void)a;
    int r = reg_index(r64);
    _VALIDATE_REG_INDEX(r, r64);
    make_regreg(ei, IT_REGREG_NOT, r, 0);
}

ENCODER_DEFINE(neg, ei, r64, a)
{
    (void)a;
    int r = reg_index(r64);
    _VALIDATE_REG_INDEX(r, r64);
    make_regreg(ei, IT_REGREG_NEG, r, 0);
}

ENCODER_DEFINE(mov, ei, rd64, src)
{
    int r1 = reg_index(rd64);
    int r2 = 0;
    u64_it imm = 0;

    if (is_register(src, &r2, &imm))
    {
        make_regreg(ei, IT_REGREG_MOV, r1, r2);
    }
    else
    {
        make_regimm(ei, IT_REGIMM_MOV, r1, imm);
    }
}

ENCODER_DEFINE(cmp, ei, rd64, src)
{
    int r1 = reg_index(rd64);
    int r2 = 0;
    u64_it imm = 0;

    if (is_register(src, &r2, &imm))
    {
        make_regreg(ei, IT_REGREG_CMP, r1, r2);
    }
    else
    {
        make_regimm(ei, IT_REGIMM_CMP, r1, imm);
    }
}

ENCODER_DEFINE(test, ei, rd64, src)
{
    int r1 = reg_index(rd64);
    int r2 = 0;
    u64_it imm = 0;

    if (is_register(src, &r2, &imm))
    {
        make_regreg(ei, IT_REGREG_TEST, r1, r2);
    }
    else
    {
        make_regimm(ei, IT_REGIMM_TEST, r1, imm);
    }
}

ENCODER_DEFINE(push, ei, r64, a)
{
    (void)a;
    int r = reg_index(r64);
    _VALIDATE_REG_INDEX(r, r64);
    make_regreg(ei, IT_REGREG_PUSH, r, 0);
}

ENCODER_DEFINE(pushfq, ei, a, b)
{
    (void)a;
    (void)b;
    make_regreg(ei, IT_REGREG_PUSHFQ, 0, 0);
}

ENCODER_DEFINE(pop, ei, r64, a)
{
    (void)a;
    int r = reg_index(r64);
    _VALIDATE_REG_INDEX(r, r64);
    make_regreg(ei, IT_REGREG_POP, r, 0);
}

ENCODER_DEFINE(popfq, ei, a, b)
{
    (void)a;
    (void)b;
    make_regreg(ei, IT_REGREG_POPFQ, 0, 0);
}

ENCODER_DEFINE(xchg, ei, rd64, rs64)
{
    int r1 = reg_index(rd64);
    int r2 = reg_index(rs64);
    _VALIDATE_REG_INDEX(r1, rd64);
    _VALIDATE_REG_INDEX(r2, rs64);
    make_xregreg(ei, IT_XREGREG_XCHG, r1, r2);
}

ENCODER_DEFINE(ldip, ei, r64, a)
{
    (void)a;
    int r = reg_index(r64);
    _VALIDATE_REG_INDEX(r, r64);
    make_xregreg(ei, IT_XREGREG_LDIP, r, 0);
}

ENCODER_DEFINE(ldb, ei, r64, addr24)
{
    int r = reg_index(r64);
    _VALIDATE_REG_INDEX(r, r64);
    make_mem(ei, IT_MEM_LDB, r, strtoull(addr24, NULL, 0));
}

ENCODER_DEFINE(ldw, ei, r64, addr24)
{
    int r = reg_index(r64);
    _VALIDATE_REG_INDEX(r, r64);
    make_mem(ei, IT_MEM_LDW, r, strtoull(addr24, NULL, 0));
}

ENCODER_DEFINE(ldd, ei, r64, addr24)
{
    int r = reg_index(r64);
    _VALIDATE_REG_INDEX(r, r64);
    make_mem(ei, IT_MEM_LDD, r, strtoull(addr24, NULL, 0));
}

ENCODER_DEFINE(ldq, ei, r64, addr24)
{
    int r = reg_index(r64);
    _VALIDATE_REG_INDEX(r, r64);
    make_mem(ei, IT_MEM_LDQ, r, strtoull(addr24, NULL, 0));
}

ENCODER_DEFINE(stb, ei, addr24, r64)
{
    int r = reg_index(r64);
    _VALIDATE_REG_INDEX(r, r64);
    make_mem(ei, IT_MEM_STB, r, strtoull(addr24, NULL, 0));
}

ENCODER_DEFINE(stw, ei, addr24, r64)
{
    int r = reg_index(r64);
    _VALIDATE_REG_INDEX(r, r64);
    make_mem(ei, IT_MEM_STW, r, strtoull(addr24, NULL, 0));
}

ENCODER_DEFINE(std, ei, addr24, r64)
{
    int r = reg_index(r64);
    _VALIDATE_REG_INDEX(r, r64);
    make_mem(ei, IT_MEM_STD, r, strtoull(addr24, NULL, 0));
}

ENCODER_DEFINE(stq, ei, addr24, r64)
{
    int r = reg_index(r64);
    _VALIDATE_REG_INDEX(r, r64);
    make_mem(ei, IT_MEM_STQ, r, strtoull(addr24, NULL, 0));
}

ENCODER_DEFINE(jmp, ei, src, a)
{
    (void)a;
    int r = 0;
    u64_it addr24 = 0;

    if (is_register(src, &r, &addr24))
    {
        make_xregreg(ei, IT_XREGREG_JMP, r, 0);
    }
    else
    {
        make_branch(ei, IT_BRANCH_JMP, addr24);
    }
}

ENCODER_DEFINE(call, ei, src, a)
{
    (void)a;
    int r = 0;
    u64_it addr24 = 0;

    if (is_register(src, &r, &addr24))
    {
        make_xregreg(ei, IT_XREGREG_CALL, r, 0);
    }
    else
    {
        make_branch(ei, IT_BRANCH_CALL, addr24);
    }
}

ENCODER_DEFINE(ret, ei, a, b)
{
    (void)a;
    (void)b;
    make_branch(ei, IT_BRANCH_RET, 0);
}

ENCODER_DEFINE(jb, ei, addr24, a)
{
    (void)a;
    make_xbranch(ei, IT_XBRANCH_JB, strtoull(addr24, NULL, 0));
}

ENCODER_DEFINE(je, ei, addr24, a)
{
    (void)a;
    make_xbranch(ei, IT_XBRANCH_JE, strtoull(addr24, NULL, 0));
}

ENCODER_DEFINE(jo, ei, addr24, a)
{
    (void)a;
    make_xbranch(ei, IT_XBRANCH_JO, strtoull(addr24, NULL, 0));
}

ENCODER_DEFINE(js, ei, addr24, a)
{
    (void)a;
    make_xbranch(ei, IT_XBRANCH_JS, strtoull(addr24, NULL, 0));
}

ENCODER_DEFINE(jae, ei, addr24, a)
{
    (void)a;
    make_xbranch(ei, IT_XBRANCH_JAE, strtoull(addr24, NULL, 0));
}

ENCODER_DEFINE(jne, ei, addr24, a)
{
    (void)a;
    make_xbranch(ei, IT_XBRANCH_JNE, strtoull(addr24, NULL, 0));
}

ENCODER_DEFINE(jno, ei, addr24, a)
{
    (void)a;
    make_xbranch(ei, IT_XBRANCH_JNO, strtoull(addr24, NULL, 0));
}

ENCODER_DEFINE(jns, ei, addr24, a)
{
    (void)a;
    make_xbranch(ei, IT_XBRANCH_JNS, strtoull(addr24, NULL, 0));
}

ENCODER_DEFINE(jg, ei, addr24, a)
{
    (void)a;
    make_xbranch(ei, IT_XBRANCH_JG, strtoull(addr24, NULL, 0));
}

ENCODER_DEFINE(jge, ei, addr24, a)
{
    (void)a;
    make_xbranch(ei, IT_XBRANCH_JGE, strtoull(addr24, NULL, 0));
}

ENCODER_DEFINE(jl, ei, addr24, a)
{
    (void)a;
    make_xbranch(ei, IT_XBRANCH_JL, strtoull(addr24, NULL, 0));
}

ENCODER_DEFINE(jle, ei, addr24, a)
{
    (void)a;
    make_xbranch(ei, IT_XBRANCH_JLE, strtoull(addr24, NULL, 0));
}

ENCODER_DEFINE(ja, ei, addr24, a)
{
    (void)a;
    make_xbranch(ei, IT_XBRANCH_JA, strtoull(addr24, NULL, 0));
}

ENCODER_DEFINE(jbe, ei, addr24, a)
{
    (void)a;
    make_xbranch(ei, IT_XBRANCH_JBE, strtoull(addr24, NULL, 0));
}

ENCODER_DEFINE(jp, ei, addr24, a)
{
    (void)a;
    make_xbranch(ei, IT_XBRANCH_JP, strtoull(addr24, NULL, 0));
}

ENCODER_DEFINE(jnp, ei, addr24, a)
{
    (void)a;
    make_xbranch(ei, IT_XBRANCH_JNP, strtoull(addr24, NULL, 0));
}

ENCODER_DEFINE(hlt, ei, a, b)
{
    (void)a;
    (void)b;
    make_misc(ei, IT_MISC_HLT);
}

ENCODER_DEFINE(nop, ei, a, b)
{
    (void)a;
    (void)b;
    make_misc(ei, IT_MISC_NOP);
}

// Mnemonic to encoder mapping.
// MUST be arranged alphabetically.
const struct instruction_entry instruction_table[] = {
    {"add", enc_add},
    {"and", enc_and},
    {"call", enc_call},
    {"cmp", enc_cmp},
    {"div", enc_div},
    {"hlt", enc_hlt},
    {"ja", enc_ja},
    {"jae", enc_jae},
    {"jb", enc_jb},
    {"jbe", enc_jbe},
    {"jc", enc_jb},
    {"je", enc_je},
    {"jg", enc_jg},
    {"jge", enc_jge},
    {"jl", enc_jl},
    {"jle", enc_jle},
    {"jmp", enc_jmp},
    {"jna", enc_jbe},
    {"jnae", enc_jb},
    {"jnb", enc_jae},
    {"jnbe", enc_ja},
    {"jnc", enc_jae},
    {"jne", enc_jne},
    {"jng", enc_jle},
    {"jnge", enc_jl},
    {"jnl", enc_jge},
    {"jnle", enc_jg},
    {"jno", enc_jno},
    {"jnp", enc_jnp},
    {"jns", enc_jns},
    {"jnz", enc_jne},
    {"jo", enc_jo},
    {"jp", enc_jp},
    {"jpe", enc_jp},
    {"jpo", enc_jnp},
    {"js", enc_js},
    {"jz", enc_je},
    {"ldb", enc_ldb},
    {"ldd", enc_ldd},
    {"ldip", enc_ldip},
    {"ldq", enc_ldq},
    {"ldw", enc_ldw},
    {"mov", enc_mov},
    {"mul", enc_mul},
    {"neg", enc_neg},
    {"nop", enc_nop},
    {"not", enc_not},
    {"or", enc_or},
    {"pop", enc_pop},
    {"popfq", enc_popfq},
    {"push", enc_push},
    {"pushfq", enc_pushfq},
    {"ret", enc_ret},
    {"stb", enc_stb},
    {"std", enc_std},
    {"stq", enc_stq},
    {"stw", enc_stw},
    {"sub", enc_sub},
    {"test", enc_test},
    {"xchg", enc_xchg},
    {"xor", enc_xor}
};

// The number of instructions. Includes aliases.
const uint16_t instruction_count = sizeof(instruction_table) / sizeof(instruction_table[0]);