#include <ctype.h>
#include "helpers.h"
#include "encoders.h"

int reg_index(const char *reg)
{
    for (int i = 0; i < NUM_REGS; i++)
    {
        if (strcmp(reg, reg_names[i]) == 0)
        {
            return i;
        }
    }
    return -1;
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
    ei.bytes[1] = (r32 & 0xf) << 4; // lower nibble reserved
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
    ei.bytes[1] = ((r32 & 0xf) << 4) | (imm20 & 0xf); // squeeze the two nibbles in one byte
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

EncodedInstruction enc_add(const char *rd32, const char *rs32)
{
    int r1 = reg_index(rd32);
    int r2 = reg_index(rs32);
    _VALIDATE_REG_INDEX(r1, rd32);
    _VALIDATE_REG_INDEX(r2, rs32);
    return make_regreg(REGREG_ADD, r1, r2);
}

EncodedInstruction enc_sub(const char *rd32, const char *rs32)
{
    int r1 = reg_index(rd32);
    int r2 = reg_index(rs32);
    _VALIDATE_REG_INDEX(r1, rd32);
    _VALIDATE_REG_INDEX(r2, rs32);
    return make_regreg(REGREG_SUB, r1, r2);
}

EncodedInstruction enc_mul(const char *rd32, const char *rs32)
{
    int r1 = reg_index(rd32);
    int r2 = reg_index(rs32);
    _VALIDATE_REG_INDEX(r1, rd32);
    _VALIDATE_REG_INDEX(r2, rs32);
    return make_regreg(REGREG_MUL, r1, r2);
}

EncodedInstruction enc_div(const char *rd32, const char *rs32)
{
    int r1 = reg_index(rd32);
    int r2 = reg_index(rs32);
    _VALIDATE_REG_INDEX(r1, rd32);
    _VALIDATE_REG_INDEX(r2, rs32);
    return make_regreg(REGREG_DIV, r1, r2);
}

EncodedInstruction enc_and(const char *rd32, const char *rs32)
{
    int r1 = reg_index(rd32);
    int r2 = reg_index(rs32);
    _VALIDATE_REG_INDEX(r1, rd32);
    _VALIDATE_REG_INDEX(r2, rs32);
    return make_regreg(REGREG_AND, r1, r2);
}

EncodedInstruction enc_or(const char *rd32, const char *rs32)
{
    int r1 = reg_index(rd32);
    int r2 = reg_index(rs32);
    _VALIDATE_REG_INDEX(r1, rd32);
    _VALIDATE_REG_INDEX(r2, rs32);
    return make_regreg(REGREG_OR, r1, r2);
}

EncodedInstruction enc_xor(const char *rd32, const char *rs32)
{
    int r1 = reg_index(rd32);
    int r2 = reg_index(rs32);
    _VALIDATE_REG_INDEX(r1, rd32);
    _VALIDATE_REG_INDEX(r2, rs32);
    return make_regreg(REGREG_XOR, r1, r2);
}

// not exactly reg-reg, oh well
EncodedInstruction enc_not(const char *r32, const char *)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_regreg(REGREG_NOT, r, 0);
}

EncodedInstruction enc_mov(const char *rd32, const char *rs32)
{
    int r1 = reg_index(rd32);
    int r2 = reg_index(rs32);
    _VALIDATE_REG_INDEX(r1, rd32);
    _VALIDATE_REG_INDEX(r2, rs32);
    return make_regreg(REGREG_MOV, r1, r2);
}

EncodedInstruction enc_swp(const char *rd32, const char *rs32)
{
    int r1 = reg_index(rd32);
    int r2 = reg_index(rs32);
    _VALIDATE_REG_INDEX(r1, rd32);
    _VALIDATE_REG_INDEX(r2, rs32);
    return make_regreg(REGREG_SWP, r1, r2);
}

EncodedInstruction enc_addi(const char *r32, const char *imm32)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_regimm(REGIMM_ADD, r, (uint32_t)strtol(imm32, NULL, 0));
}

EncodedInstruction enc_subi(const char *r32, const char *imm32)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_regimm(REGIMM_SUB, r, (uint32_t)strtol(imm32, NULL, 0));
}

EncodedInstruction enc_muli(const char *r32, const char *imm32)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_regimm(REGIMM_MUL, r, (uint32_t)strtol(imm32, NULL, 0));
}

EncodedInstruction enc_divi(const char *r32, const char *imm32)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_regimm(REGIMM_DIV, r, (uint32_t)strtol(imm32, NULL, 0));
}

EncodedInstruction enc_andi(const char *r32, const char *imm32)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_regimm(REGIMM_AND, r, (uint32_t)strtol(imm32, NULL, 0));
}

EncodedInstruction enc_ori(const char *r32, const char *imm32)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_regimm(REGIMM_OR, r, (uint32_t)strtol(imm32, NULL, 0));
}

EncodedInstruction enc_xori(const char *r32, const char *imm32)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_regimm(REGIMM_XOR, r, (uint32_t)strtol(imm32, NULL, 0));
}

EncodedInstruction enc_movi(const char *r32, const char *imm32)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_regimm(REGIMM_MOV, r, (uint32_t)strtol(imm32, NULL, 0));
}

EncodedInstruction enc_ldb(const char *r32, const char *imm20)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_mem(MEM_LDB, r, (uint32_t)strtol(imm20, NULL, 0));
}

EncodedInstruction enc_stb(const char *imm20, const char *r32)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_mem(MEM_STB, r, (uint32_t)strtol(imm20, NULL, 0));
}

EncodedInstruction enc_ldw(const char *r32, const char *imm20)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_mem(MEM_LDW, r, (uint32_t)strtol(imm20, NULL, 0));
}

EncodedInstruction enc_stw(const char *imm20, const char *r32)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_mem(MEM_STW, r, (uint32_t)strtol(imm20, NULL, 0));
}

EncodedInstruction enc_ldd(const char *r32, const char *imm20)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_mem(MEM_LDD, r, (uint32_t)strtol(imm20, NULL, 0));
}

EncodedInstruction enc_std(const char *imm20, const char *r32)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return make_mem(MEM_STD, r, (uint32_t)strtol(imm20, NULL, 0));
}

EncodedInstruction enc_br(const char *imm20, const char *)
{
    return make_branch(BRANCH_BR, (uint32_t)strtol(imm20, NULL, 0));
}

EncodedInstruction enc_bc(const char *imm20, const char *)
{
    return make_branch(BRANCH_BC, (uint32_t)strtol(imm20, NULL, 0));
}

EncodedInstruction enc_bnc(const char *imm20, const char *)
{
    return make_branch(BRANCH_BNC, (uint32_t)strtol(imm20, NULL, 0));
}

EncodedInstruction enc_bo(const char *imm20, const char *)
{
    return make_branch(BRANCH_BO, (uint32_t)strtol(imm20, NULL, 0));
}

EncodedInstruction enc_bno(const char *imm20, const char *)
{
    return make_branch(BRANCH_BNO, (uint32_t)strtol(imm20, NULL, 0));
}

EncodedInstruction enc_bz(const char *imm20, const char *)
{
    return make_branch(BRANCH_BZ, (uint32_t)strtol(imm20, NULL, 0));
}

EncodedInstruction enc_bnz(const char *imm20, const char *)
{
    return make_branch(BRANCH_BNZ, (uint32_t)strtol(imm20, NULL, 0));
}

EncodedInstruction enc_bs(const char *imm20, const char *)
{
    return make_branch(BRANCH_BS, (uint32_t)strtol(imm20, NULL, 0));
}

EncodedInstruction enc_bns(const char *imm20, const char *)
{
    return make_branch(BRANCH_BNS, (uint32_t)strtol(imm20, NULL, 0));
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
    {"addi", enc_addi},
    {"subi", enc_subi},
    {"muli", enc_muli},
    {"divi", enc_divi},
    {"andi", enc_andi},
    {"ori", enc_ori},
    {"xori", enc_xori},
    {"movi", enc_movi},
    {"ldb", enc_ldb},
    {"stb", enc_stb},
    {"ldw", enc_ldw},
    {"stw", enc_stw},
    {"ldd", enc_ldd},
    {"std", enc_std},
    {"br", enc_br},
    {"bc", enc_bc},
    {"bnc", enc_bnc},
    {"bo", enc_bo},
    {"bno", enc_bno},
    {"bz", enc_bz},
    {"bnz", enc_bnz},
    {"bs", enc_bs},
    {"bns", enc_bns},
    {"hlt", enc_hlt},
    {"nop", enc_nop}
};
const uint8_t instruction_count = sizeof(instruction_table) / sizeof(instruction_table[0]);
