#pragma once

// So we don't have to keep writing these.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAGIC_BYTES_SIZE 6
static const unsigned char magic_bytes[MAGIC_BYTES_SIZE] = {'\x7f', '\x00', 'W', 'O', 'O', 'F'};

#define NUM_REGS 18
// GCC warns that this variable is unused, but it is definitely used.
static const char *reg_names[NUM_REGS] = {
    "dxa", "dxt", "dxc",                        // accumulator, temporary, counter
    "dd0", "dd1", "dd2", "dd3", "dd4", "dd5",   // data/arguments
    "dbp", "dsp",                               // base pointer, stack pointer
    "ds0", "ds1", "ds2", "ds3", "ds4",          // callee-saved registers
    "dip", "dstat"                              // instruction pointer, Status/flags
};

#define MEM_SIZE (1024 * 1024)      // 1 MiB unified memory
#define TEXT_BASE (MEM_SIZE / 2)    // loads code in the middle of memory

#define ERR_ILLINT      0x7f    // illegal instruction
#define ERR_MALFORMED   0x80    // malformed (generic)
#define ERR_BOUND       0x81    // out-of-bounds access

#define STAT_CF 0x1 // carry
#define STAT_OF 0x2 // overflow
#define STAT_ZF 0x4 // zero
#define STAT_SF 0x8 // sign

// useful aliases (depends on the fact that a "registers" variable exists)
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
    CLASS_CTRLFLOW,
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
    REGREG_SWP,

    REGIMM_ADD = 0,
    REGIMM_SUB,
    REGIMM_MUL,
    REGIMM_DIV,
    REGIMM_AND,
    REGIMM_OR,
    REGIMM_XOR,
    REGIMM_NOT,
    REGIMM_MOV,

    MEM_LDB = 0,
    MEM_STB,
    MEM_LDW,
    MEM_STW,
    MEM_LDD,
    MEM_STD,
    
    MISC_HLT = 0,
    MISC_NOP,

    CTRLFLOW_UNIMPLEMENTED = 0
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
            return 4; // for now
        case CLASS_MISC:
            return 1; // for now
        default:
            return 4;
    }
}

// for the assembler
#define VALIDATE_REG_INDEX(idx, name) \
    if ((idx) < 0) \
    { \
        fprintf(stderr, "Invalid register: %s\n", name); \
        fclose(fin); \
        fclose(fout); \
        return ERR_BADSYM; \
    }

#define _VALIDATE_REG_INDEX(idx, name) \
    if ((idx) < 0) \
    { \
        fprintf(stderr, "Invalid register: %s\n", name); \
        exit(ERR_MALFORMED); \
    }

#define _
#undef _