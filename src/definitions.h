/** Definitions of common macros, constants, and types used. */

#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>

#define MAGIC_BYTES_SIZE 8
// Magic bytes put and expected at the start of every .lx file
static const uint8_t magic_bytes[MAGIC_BYTES_SIZE] = {'\x7f', '\x00', '\x00', 'R', 'O', 'B', 'I', 'N'};

/* Versions of each file */

#define RASM_VERSION    "0.2.3"
#define RDISASM_VERSION "0.2.3"
#define REMU_VERSION    "0.2.9"

// Amount of memory each process gets
#define MEM_SIZE    0x100000
// Start of .text section
#define TEXT_BASE   0x1000
// Start of .data section
#define DATA_BASE   (MEM_SIZE / 2)
// Start of stack, grows downward
#define STACK_BASE  MEM_SIZE

// Illegal instruction error
#define ERR_ILLINT      0x7f
// Generic malformity error
#define ERR_MALFORMED   0x80
// Out-of-bounds access error
#define ERR_BOUND       0x81

/* Implementation of x86 flags */
// Names such as RB<n> are reserved bits, and n denotes what bit they are. 

#define FLAG_CF     0x1
#define FLAG_RB1    0x2
#define FLAG_PF     0x4
#define FLAG_RB3    0x8
#define FLAG_AF     0x10
#define FLAG_RB5    0x20
#define FLAG_ZF     0x40
#define FLAG_SF     0x80
#define FLAG_TF     0x100
#define FLAG_IF     0x200
#define FLAG_DF     0x400
#define FLAG_OF     0x800
#define FLAG_IOPL1  0x1000
#define FLAG_IOPL2  0x2000
#define FLAG_NT     0x4000
#define FLAG_RB15   0x8000
#define FLAG_RF     0x10000
#define FLAG_VM     0x20000
#define FLAG_AC     0x40000
#define FLAG_VIF    0x80000
#define FLAG_VIP    0x100000
#define FLAG_ID     0x200000

/* Macros to print errors and warns */

#define ERROR(message)          fputs("\x1b[31merror:\x1b[0m " message "\n", stderr)
#define WARN(message)           fputs("\x1b[35mwarning:\x1b[0m " message "\n", stderr)
#define ERROR_FMT(format, ...)  fprintf(stderr, "\x1b[31merror:\x1b[0m " format "\n", __VA_ARGS__)
#define WARN_FMT(format, ...)   fprintf(stderr, "\x1b[35mwarning:\x1b[0m " format "\n", __VA_ARGS__)

// Macro to compare a string to another string of known length.
#define STR_EQUAL_LEN(string_dest, string_src, length) \
    (strncmp(string_dest, string_src, length) == 0 && string_src[length] == '\0')

/* IDs of sections in memory */

#define SECT_TEXT 0
#define SECT_DATA 1

/* Useful register macros (although depends on the fact that a "registers" array exists in the current context) */

#define dsp     registers[10]
#define dip     registers[16]
#define dflags  registers[17]

// Current maximum length of instructions.
#define MAX_INSTRUCTION_LENGTH 6

// Number of registers. Includes general-purpose ones, the instruction pointer, and flags/status.
#define REG_COUNT 18

// Struct to store the encoded instruction.
struct instruction
{
    uint8_t bytes[MAX_INSTRUCTION_LENGTH];
    int length;
};

// Enumeration of instruction classes. Maximum of 16.
// This will get stored as the higher nibble in the opcode.
// NOT stored alphabetically.
enum instruction_class
{
    IC_REGREG,
    IC_XREGREG,
    IC_REGIMM,
    IC_MEM,
    IC_BRANCH,
    IC_XBRANCH,
    IC_MISC = 0xf
};

// Enumeration of instruction types. Maximum of 16 per class.
// This will get stored as the lower nibble in the opcode.
// Arranged alphabetically by instruction type name.
enum instruction_type
{
    IT_REGREG_ADD,
    IT_REGREG_AND,
    IT_REGREG_CMP,
    IT_REGREG_DIV,
    IT_REGREG_MOV,
    IT_REGREG_MUL,
    IT_REGREG_NEG,
    IT_REGREG_NOT,
    IT_REGREG_OR,
    IT_REGREG_POP,
    IT_REGREG_POPFD,
    IT_REGREG_PUSH,
    IT_REGREG_PUSHFD,
    IT_REGREG_SUB,
    IT_REGREG_TEST,
    IT_REGREG_XOR,

    IT_XREGREG_CALL = 0,
    IT_XREGREG_JMP,
    IT_XREGREG_LDIP,
    IT_XREGREG_XCHG,

    IT_REGIMM_ADD = 0,
    IT_REGIMM_AND,
    IT_REGIMM_CMP,
    IT_REGIMM_DIV,
    IT_REGIMM_MOV,
    IT_REGIMM_MUL,
    IT_REGIMM_OR,
    IT_REGIMM_SUB,
    IT_REGIMM_TEST,
    IT_REGIMM_XOR,

    IT_MEM_LDB = 0,
    IT_MEM_LDD,
    IT_MEM_LDW,
    IT_MEM_STB,
    IT_MEM_STD,
    IT_MEM_STW,

    IT_BRANCH_CALL = 0,
    IT_BRANCH_JMP,
    IT_BRANCH_RET,

    IT_XBRANCH_JA = 0,
    IT_XBRANCH_JAE,
    IT_XBRANCH_JB,
    IT_XBRANCH_JBE,
    IT_XBRANCH_JE,
    IT_XBRANCH_JG,
    IT_XBRANCH_JGE,
    IT_XBRANCH_JL,
    IT_XBRANCH_JLE,
    IT_XBRANCH_JNO,
    IT_XBRANCH_JNE,
    IT_XBRANCH_JNP,
    IT_XBRANCH_JNS,
    IT_XBRANCH_JO,
    IT_XBRANCH_JP,
    IT_XBRANCH_JS,

    IT_MISC_HLT = 0,
    IT_MISC_NOP
};

// Returns the length of the instruction based on the opcode.
// Some exceptions exist and override the length expected by the class, such as RET.
static inline int get_length(uint8_t opcode, uint8_t byte2)
{
    // We need only the lower nibble.
    byte2 &= 0xf;

    switch (opcode >> 4)
    {
        case IC_REGREG:
            return (((opcode & 0xf) == IT_REGREG_PUSHFD) || ((opcode & 0xf) == IT_REGREG_POPFD))
                ? 1
                : 2;
        case IC_XREGREG:
            return 2;
        case IC_REGIMM:
            return (byte2 == 0)
                ? 3
                : (byte2 == 1)
                ? 4
                : 6;
        case IC_MEM:
            return 4;
        case IC_BRANCH:
            return ((opcode & 0xf) == IT_BRANCH_RET) ? 1 : 4;
        case IC_XBRANCH:
            return 4;
        case IC_MISC:
            // IC_MISC instructions have a length of 1 byte for now.
            return 1;
        default:
            // So we don't accidentally step over potentially valid instructions.
            return 1;
    }
}

// Checks if a file name ends in an extension.
static inline bool ends_with(const char *filename, const char *ext)
{
    size_t filename_length = strlen(filename);
    size_t ext_length = strlen(ext);
    if (filename_length < ext_length)
    {
        return false;
    }
    return strcmp(filename + filename_length - ext_length, ext) == 0;
}

// Register index validation, a macro exclusive to the assembler.
#define VALIDATE_REG_INDEX(idx, name) \
    if ((idx) < 0) \
    { \
        ERROR_FMT("Invalid register \"%s\"", name); \
        fclose(fin); \
        fclose(fout); \
        return ERR_MALFORMED; \
    }

// Validates the register index passed.
#define _VALIDATE_REG_INDEX(idx, name) \
    if ((idx) < 0) \
    { \
        ERROR_FMT("Invalid register \"%s\"", name); \
        exit(ERR_MALFORMED); \
    }

// Macro to conditionally jump to an address in memory.
#define JUMP(addr, condition) \
    if (condition) \
    { \
        dip = addr; \
        continue; \
    }

#define _
#undef _