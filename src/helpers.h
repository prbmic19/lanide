#pragma once

// So we don't have to keep writing these.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define MAGIC_BYTES_SIZE 5
static const unsigned char magic_bytes[MAGIC_BYTES_SIZE] = {0x03, 0x00, 0x52, 0x58, 0x45}; // \x03\x00RXE (Robust eXtended Edition)

#define NUM_REGS 18
// GCC warns that this variable is unused, but it is definitely used.
static const char *reg_names[NUM_REGS] = {
    "dxa", "dxt", "dxc",                        // Accumulator, temporary, counter
    "dd0", "dd1", "dd2", "dd3", "dd4", "dd5",   // Data/arguments
    "dbp", "dsp",                               // Base pointer, stack pointer
    "ds0", "ds1", "ds2", "ds3", "ds4",          // Callee-saved registers
    "dip", "dstat"                              // Instruction pointer, Status/flags
};

#define MEM_SIZE (1024 * 1024)      // 1 MiB unified memory
#define TEXT_BASE (MEM_SIZE / 2)    // Loads code in the middle of memory

#define ERR_ILLINT      0x7f    // Illegal instruction
#define ERR_MALFORMED   0x80    // Malformed (generic)
#define ERR_BOUND       0x81    // Out-of-bounds access

// 16 possible classes
typedef enum
{
    CLASS_RR, // reg-reg
    CLASS_RI, // reg-imm
    CLASS_MEM,
    CLASS_SYS
} InstructionClass;
typedef enum
{
    RR_MOV,
    RR_ADD,
    RR_SUB
} RegRegOp;
typedef enum
{
    RI_MOV,
    RI_ADD,
    RI_SUB
} RegImmOp;
typedef enum
{
    MEM_LDB,
    MEM_STB,
    MEM_LDW,
    MEM_STW,
    MEM_LDD,
    MEM_STD
} MemOp;
typedef enum
{
    SYS_HLT
} SysOp;

// Bits 15..0 are reserved
#define ENCODE_RR(subop, rd32, rs32) \
    (((CLASS_RR & 0xf) << 28) | \
        ((subop & 0xf) << 24) | \
        ((rd32 & 0xf) << 20) | \
        ((rs32 & 0xf) << 16))

#define ENCODE_RI(subop, rd32, imm20) \
    (((CLASS_RI & 0xf) << 28) | \
        ((subop & 0xf) << 24) | \
        ((rd32 & 0xf) << 20) | \
        ((imm20) & 0xfffff))

#define ENCODE_MEM(subop, rd32, imm20) \
    (((CLASS_MEM & 0xf) << 28) | \
        ((subop & 0xf) << 24) | \
        ((rd32 & 0xf) << 20) | \
        ((imm20) & 0xfffff))

// Bits 23..0 are reserved
#define ENCODE_SYS(subop) \
    (((CLASS_SYS & 0xf) << 28) | \
        ((subop & 0xf) << 24))

#define GET_CLASS(instruction) (((instruction) >> 28) & 0xf)
#define GET_SUBOP(instruction) (((instruction) >> 24) & 0xf)

#define GET_RR_RD32(instruction) (((instruction) >> 20) & 0xf)
#define GET_RR_RS32(instruction) (((instruction) >> 16) & 0xf)

#define GET_RI_R32                  GET_RR_RD32
#define GET_RI_IMM20(instruction)   ((instruction) & 0xfffff)

#define GET_MEM_R32     GET_RI_R32
#define GET_MEM_IMM20   GET_RI_IMM20

// For the assembler
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