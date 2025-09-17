#pragma once

// So we don't have to keep writing these.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define MAGIC_BYTES_SIZE 8
// RObust BINary
static const uint8_t magic_bytes[MAGIC_BYTES_SIZE] = {'\x7f', '\x00', '\x00', 'R', 'O', 'B', 'I', 'N'};

#define MEM_SIZE    0x100000            // 1 MiB unified memory
#define TEXT_BASE   (MEM_SIZE / 8)      // 12.5% into memory
#define DATA_BASE   (MEM_SIZE / 2)      // 50% into memory
#define STACK_BASE  (MEM_SIZE - 0x1000) // At the very top, with a little safety margin

#define ERR_ILLINT      0x7f    // Illegal instruction
#define ERR_MALFORMED   0x80    // Malformed (generic)
#define ERR_BOUND       0x81    // Out-of-bounds access

#define STAT_CF 0x1 // Carry
#define STAT_ZF 0x2 // Zero
#define STAT_OF 0x4 // Overflow
#define STAT_SF 0x8 // Sign

// Sections in memory
#define SECT_TEXT 0
#define SECT_DATA 1

// Useful aliases (depends on the fact that a "registers" variable exists)
#define dsp     registers[10]
#define dip     registers[16]
#define dstat   registers[17]

/* We use the "_td" suffix for typedefs and to avoid clashing with POSIX names */

typedef struct encoded_instruction
{
    uint8_t bytes[6];
    int length;
} encoded_instruction_td;

// 16 possible classes
typedef enum instruction_class
{
    IC_REGREG,
    IC_REGIMM,
    IC_MEM,
    IC_BRANCH,
    IC_MISC = 0xf
} instruction_class_td;

// 16 possible instructions per class
typedef enum opcode
{
    OC_REGREG_ADD,
    OC_REGREG_SUB,
    OC_REGREG_MUL,
    OC_REGREG_DIV,
    OC_REGREG_AND,
    OC_REGREG_OR,
    OC_REGREG_XOR,
    OC_REGREG_NOT,
    OC_REGREG_MOV,
    OC_REGREG_XCHG,
    OC_REGREG_PUSH,
    OC_REGREG_POP,

    OC_REGIMM_ADD = 0,
    OC_REGIMM_SUB,
    OC_REGIMM_MUL,
    OC_REGIMM_DIV,
    OC_REGIMM_AND,
    OC_REGIMM_OR,
    OC_REGIMM_XOR,
    OC_REGIMM_MOV,

    OC_MEM_LDB = 0,
    OC_MEM_STB,
    OC_MEM_LDW,
    OC_MEM_STW,
    OC_MEM_LDD,
    OC_MEM_STD,

    OC_BRANCH_JMP = 0,
    OC_BRANCH_JC,
    OC_BRANCH_JNC,
    OC_BRANCH_JZ,
    OC_BRANCH_JNZ,
    OC_BRANCH_JO,
    OC_BRANCH_JNO,
    OC_BRANCH_JS,
    OC_BRANCH_JNS,
    OC_BRANCH_CALL,
    OC_BRANCH_RET,

    OC_MISC_HLT = 0,
    OC_MISC_NOP
} opcode_td;

static inline int get_length(uint8_t opcode, uint8_t byte2)
{
    switch (opcode >> 4)
    {
        case IC_REGREG:
            return 2;
        case IC_REGIMM:
            return ((byte2 & 0xf) == 0)
                ? 3
                : ((byte2 & 0xf) == 1)
                ? 4
                : 6;
        case IC_MEM:
            return 4;
        case IC_BRANCH:
            return ((opcode & 0xf) == OC_BRANCH_RET) ? 1 : 4; // Exception for RET
        case IC_MISC:
            return 1; // For now
        default:
            return 1; // So we don't accidentally step over potentially valid instructions.
    }
}

static inline bool has_ext(const char *filename, const char *ext)
{
    size_t filename_length = strlen(filename);
    size_t ext_length = strlen(ext);
    if (filename_length < ext_length)
    {
        return false;
    }
    return strcmp(filename + filename_length - ext_length, ext) == 0;
}

// For the assembler
#define VALIDATE_REG_INDEX(idx, name) \
    if ((idx) < 0) \
    { \
        fprintf(stderr, "Invalid register: %s\n", name); \
        fclose(fin); \
        fclose(fout); \
        return ERR_MALFORMED; \
    }

#define _VALIDATE_REG_INDEX(idx, name) \
    if ((idx) < 0) \
    { \
        fprintf(stderr, "Invalid register: %s\n", name); \
        exit(ERR_MALFORMED); \
    }

#define JUMP(addr, condition) \
    if (condition) \
    { \
        dip = addr; \
        continue; \
    }

#define _
#undef _