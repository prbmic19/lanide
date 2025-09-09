#pragma once

// So we don't have to keep writing these.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAGIC_BYTES_SIZE 6
static const uint8_t magic_bytes[MAGIC_BYTES_SIZE] = {'\x7f', '\x00', 'W', 'O', 'O', 'F'};

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

// Useful aliases (depends on the fact that a "registers" variable exists)
#define dsp     registers[10]
#define dip     registers[16]
#define dstat   registers[17]

typedef struct
{
    uint8_t bytes[8];
    int length; // 1, 2, 4, or 6
} EncodedInstruction;

// 16 possible classes
typedef enum
{
    CLASS_REGREG,
    CLASS_REGIMM,
    CLASS_MEM,
    CLASS_BRANCH,
    CLASS_MISC = 0xf
} InstructionClass;

// 16 instructions per class

typedef enum
{
    REGREG_ADD,
    REGREG_SUB,
    REGREG_MUL,
    REGREG_DIV,
    REGREG_AND,
    REGREG_OR,
    REGREG_XOR,
    REGREG_NOT,
    REGREG_MOV,
    REGREG_XCHG,
    REGREG_PUSH,
    REGREG_POP,

    REGIMM_ADD = 0,
    REGIMM_SUB,
    REGIMM_MUL,
    REGIMM_DIV,
    REGIMM_AND,
    REGIMM_OR,
    REGIMM_XOR,
    REGIMM_MOV,

    MEM_LDB = 0,
    MEM_STB,
    MEM_LDW,
    MEM_STW,
    MEM_LDD,
    MEM_STD,

    BRANCH_JMP = 0,
    BRANCH_JC,
    BRANCH_JNC,
    BRANCH_JZ,
    BRANCH_JNZ,
    BRANCH_JO,
    BRANCH_JNO,
    BRANCH_JS,
    BRANCH_JNS,
    BRANCH_CALL,
    BRANCH_RET,

    MISC_HLT = 0,
    MISC_NOP
} Opcode;

static inline int get_length(uint8_t opcode)
{
    switch (opcode >> 4)
    {
        case CLASS_REGREG:
            return 2;
        case CLASS_REGIMM:
            return 6;
        case CLASS_MEM:
            return 4;
        case CLASS_BRANCH:
            return 4;
        case CLASS_MISC:
            return 1; // For now
        default:
            return 1;
    }
}

static inline _Bool has_ext(const char *filename, const char *ext)
{
    size_t filename_length = strlen(filename);
    size_t ext_length = strlen(ext);
    if (filename_length < ext_length)
    {
        return 0;
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