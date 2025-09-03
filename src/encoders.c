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

uint32_t enc_mov(const char *rd32, const char *rs32)
{
    int r1 = reg_index(rd32);
    int r2 = reg_index(rs32);
    _VALIDATE_REG_INDEX(r1, rd32);
    _VALIDATE_REG_INDEX(r2, rs32);
    return ENCODE_RR(RR_MOV, r1, r2);
}

uint32_t enc_add(const char *rd32, const char *rs32)
{
    int r1 = reg_index(rd32);
    int r2 = reg_index(rs32);
    _VALIDATE_REG_INDEX(r1, rd32);
    _VALIDATE_REG_INDEX(r2, rs32);
    return ENCODE_RR(RR_ADD, r1, r2);
}

uint32_t enc_sub(const char *rd32, const char *rs32)
{
    int r1 = reg_index(rd32);
    int r2 = reg_index(rs32);
    _VALIDATE_REG_INDEX(r1, rd32);
    _VALIDATE_REG_INDEX(r2, rs32);
    return ENCODE_RR(RR_SUB, r1, r2);
}

uint32_t enc_movi(const char *r32, const char *imm20)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return ENCODE_RI(RI_MOV, r, (int)strtol(imm20, NULL, 0));
}

uint32_t enc_addi(const char *r32, const char *imm20)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return ENCODE_RI(RI_ADD, r, (int)strtol(imm20, NULL, 0));
}

uint32_t enc_subi(const char *r32, const char *imm20)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return ENCODE_RI(RI_SUB, r, (int)strtol(imm20, NULL, 0));
}

uint32_t enc_ldb(const char *r32, const char *imm20)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return ENCODE_MEM(MEM_LDB, r, (int)strtol(imm20, NULL, 0));
}

uint32_t enc_stb(const char *imm20, const char *r32)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return ENCODE_MEM(MEM_STB, r, (int)strtol(imm20, NULL, 0));
}

uint32_t enc_ldw(const char *r32, const char *imm20)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return ENCODE_MEM(MEM_LDW, r, (int)strtol(imm20, NULL, 0));
}

uint32_t enc_stw(const char *imm20, const char *r32)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return ENCODE_MEM(MEM_STW, r, (int)strtol(imm20, NULL, 0));
}

uint32_t enc_ldd(const char *r32, const char *imm20)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return ENCODE_MEM(MEM_LDD, r, (int)strtol(imm20, NULL, 0));
}

uint32_t enc_std(const char *imm20, const char *r32)
{
    int r = reg_index(r32);
    _VALIDATE_REG_INDEX(r, r32);
    return ENCODE_MEM(MEM_STD, r, (int)strtol(imm20, NULL, 0));
}

uint32_t enc_hlt(const char *, const char *)
{
    return ENCODE_SYS(SYS_HLT);
}

InstructionHandler instruction_table[] = {
    {"mov", enc_mov},
    {"add", enc_add},
    {"sub", enc_sub},
    {"movi", enc_movi},
    {"addi", enc_addi},
    {"subi", enc_subi},
    {"ldb", enc_ldb},
    {"stb", enc_stb},
    {"ldw", enc_ldw},
    {"stw", enc_stw},
    {"ldd", enc_ldd},
    {"std", enc_std},
    {"hlt", enc_hlt}
};
const size_t instruction_count = sizeof(instruction_table) / sizeof(instruction_table[0]);