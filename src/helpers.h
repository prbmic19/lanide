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

// Reduce repetition!
#define TXT_ERROR   "\x1b[31merror:\x1b[0m "  // Red
#define TXT_WARN    "\x1b[35mwarning:\x1b[0m " // Purple

// Sections in memory
#define SECT_TEXT 0
#define SECT_DATA 1

// Useful aliases (depends on the fact that a "registers" variable exists)
#define dsp     registers[10]
#define dip     registers[16]
#define dstat   registers[17]

/* We use the "_td" suffix for typedefs and to avoid clashing with POSIX names */

typedef struct instruction
{
    uint8_t bytes[6];
    int length;
} instruction_td;

// 16 possible classes
typedef enum instruction_class
{
    IC_REGREG,
    IC_XREGREG,
    IC_REGIMM,
    IC_MEM,
    IC_BRANCH,
    IC_XBRANCH,
    IC_MISC = 0xf
} instruction_class_td;

// 16 possible instructions per class
typedef enum instruction_type
{
    IT_REGREG_ADD,
    IT_REGREG_SUB,
    IT_REGREG_MUL,
    IT_REGREG_DIV,
    IT_REGREG_AND,
    IT_REGREG_OR,
    IT_REGREG_XOR,
    IT_REGREG_NOT,
    IT_REGREG_NEG,
    IT_REGREG_MOV,
    IT_REGREG_CMP,
    IT_REGREG_TEST,
    IT_REGREG_PUSH,
    IT_REGREG_PUSHFD,
    IT_REGREG_POP,
    IT_REGREG_POPFD,

    IT_XREGREG_XCHG = 0,
    IT_XREGREG_LDIP,
    IT_XREGREG_JMP,
    IT_XREGREG_CALL,

    IT_REGIMM_ADD = 0,
    IT_REGIMM_SUB,
    IT_REGIMM_MUL,
    IT_REGIMM_DIV,
    IT_REGIMM_AND,
    IT_REGIMM_OR,
    IT_REGIMM_XOR,
    IT_REGIMM_MOV,
    IT_REGIMM_CMP,
    IT_REGIMM_TEST,

    IT_MEM_LDB = 0,
    IT_MEM_LDW,
    IT_MEM_LDD,
    IT_MEM_STB,
    IT_MEM_STW,
    IT_MEM_STD,

    IT_BRANCH_JMP = 0,
    IT_BRANCH_CALL,
    IT_BRANCH_RET,

    IT_XBRANCH_JC = 0, // JB too
    IT_XBRANCH_JZ,
    IT_XBRANCH_JO,
    IT_XBRANCH_JS,
    IT_XBRANCH_JNC, // JAE too
    IT_XBRANCH_JNZ,
    IT_XBRANCH_JNO,
    IT_XBRANCH_JNS,
    IT_XBRANCH_JG,
    IT_XBRANCH_JGE,
    IT_XBRANCH_JL,
    IT_XBRANCH_JLE,
    IT_XBRANCH_JA,
    IT_XBRANCH_JBE,

    IT_MISC_HLT = 0,
    IT_MISC_NOP
} instruction_type_td;

static inline int get_length(uint8_t opcode, uint8_t byte2)
{
    switch (opcode >> 4)
    {
        case IC_REGREG:
            return (((opcode & 0xf) == IT_REGREG_PUSHFD) || ((opcode & 0xf) == IT_REGREG_POPFD))
                ? 1
                : 2;
        case IC_XREGREG:
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
            return ((opcode & 0xf) == IT_BRANCH_RET) ? 1 : 4;
        case IC_XBRANCH:
            return 4;
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
        fprintf(stderr, TXT_ERROR "Invalid register: %s\n", name); \
        fclose(fin); \
        fclose(fout); \
        return ERR_MALFORMED; \
    }

#define _VALIDATE_REG_INDEX(idx, name) \
    if ((idx) < 0) \
    { \
        fprintf(stderr, TXT_ERROR "Invalid register: %s\n", name); \
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