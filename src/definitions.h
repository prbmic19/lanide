/** Definitions of common macros, constants, and types used. */

#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define MAGIC_BYTES_SIZE 8
// Magic bytes put and expected at the start of every .lx file
static const char magic_bytes[MAGIC_BYTES_SIZE] = {'\x7f', '\x00', '\x00', 'R', 'O', 'B', 'I', 'N'};

// Versions of each file
#define RASM_VERSION    "0.4.0"
#define RDISASM_VERSION "0.4.1"
#define REMU_VERSION    "0.4.3"

// Define these using `long long`. It's guaranteed already that `long long` is at least 64 bits wide.
// It's a bit dangerous to mix `uint64_t` and the `ULL` prefix for integer literals, the compiler might get pedantic about it.
typedef long long i64_it;
typedef unsigned long long u64_it;

// Amount of memory each process gets
#define MEM_SIZE    0x400000

// Start and end of .text section
#define TEXT_BASE   0x1000
#define TEXT_SIZE   (MEM_SIZE / 4)

// Start and end of .rodata section
#define RODATA_BASE (TEXT_BASE + TEXT_SIZE)
#define RODATA_SIZE (MEM_SIZE / 16)

// Start and end of .data section
#define DATA_BASE   (RODATA_BASE + RODATA_SIZE)
#define DATA_SIZE   (MEM_SIZE / 8)

// Start and end of heap
#define HEAP_BASE   (DATA_BASE + DATA_SIZE)
#define HEAP_SIZE   (MEM_SIZE * 5 / 16)

// Start and end of stack
#define STACK_BASE  MEM_SIZE
#define STACK_SIZE  (MEM_SIZE / 4)

// Offset of .text section in the actual .lx file
// Magic bytes, rodata offset, and data offset.
// Also represents the size of the header.
#define TEXT_FILE_OFFSET (MAGIC_BYTES_SIZE + sizeof(uint32_t) + sizeof(uint32_t))

/**
 * I implemented x86 flags here. I was too lazy to design up my own, and this felt enough.
 * The name RB<n> are reserved bits, and <n> denotes what bit they are.
 */
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

// Macro to compare a string to another string of known length.
#define STR_EQUAL_LEN(string_dest, string_src, length) \
    (strncmp(string_dest, string_src, length) == 0 && string_src[length] == '\0')

// IDs of sections in memory
#define SECT_TEXT       0
#define SECT_RODATA     1
#define SECT_DATA       2
#define SECT_INVALID    0xffff

// Useful register macros (although depends on the fact that a "registers" array exists in the current context)
#define rsp     registers[7]
#define rip     registers[16]
#define rflags  registers[17]

// Current maximum length of instructions.
#define MAX_INSTRUCTION_LENGTH 13

// Number of registers. Includes general-purpose ones, the instruction pointer, and flags/status.
#define REG_COUNT 18

// Struct to store the encoded instruction.
struct instruction
{
    uint8_t bytes[MAX_INSTRUCTION_LENGTH];
    uint8_t length;
    uint16_t operand_size;  // 8, 16, 32, 64, 128, 256, 512...
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
    IC_PREFIX,
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
    IT_REGREG_POPFQ,
    IT_REGREG_PUSH,
    IT_REGREG_PUSHFQ,
    IT_REGREG_SUB,
    IT_REGREG_TEST,
    IT_REGREG_XOR,
    IT_REGREG_INSTRUCTIONCOUNT, // Special: marks end (also gives count) of IC_REGREG instructions

    IT_XREGREG_CALL = 0,
    IT_XREGREG_JMP,
    IT_XREGREG_LDIP,
    IT_XREGREG_MULH,
    IT_XREGREG_SDIV,
    IT_XREGREG_SMULH,
    IT_XREGREG_XCHG,
    IT_XREGREG_INSTRUCTIONCOUNT, // Special: marks end (also gives count) of IC_XREGREG instructions

    IT_REGIMM_ADD = 0,
    IT_REGIMM_AND,
    IT_REGIMM_CMP,
    IT_REGIMM_DIV,
    IT_REGIMM_MOV,
    IT_REGIMM_MUL,
    IT_REGIMM_MULH,
    IT_REGIMM_OR,
    IT_REGIMM_SDIV,
    IT_REGIMM_SMULH,
    IT_REGIMM_SUB,
    IT_REGIMM_TEST,
    IT_REGIMM_XOR,
    IT_REGIMM_INSTRUCTIONCOUNT, // Special: marks end (also gives count) of IC_REGIMM instructions

    IT_MEM_LDB = 0,
    IT_MEM_LDD,
    IT_MEM_LDQ,
    IT_MEM_LDW,
    IT_MEM_STB,
    IT_MEM_STD,
    IT_MEM_STQ,
    IT_MEM_STW,
    IT_MEM_INSTRUCTIONCOUNT, // Special: marks end (also gives count) of IC_MEM instructions

    IT_BRANCH_CALL = 0,
    IT_BRANCH_JMP,
    IT_BRANCH_RET,
    IT_BRANCH_INSTRUCTIONCOUNT, // Special: marks end (also gives count) of IC_BRANCH instructions

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
    IT_XBRANCH_INSTRUCTIONCOUNT, // Special: marks end (also gives count) of IC_XBRANCH instructions

    IT_PREFIX_OS32 = 0,
    IT_PREFIX_OS16,
    IT_PREFIX_OS8,
    IT_PREFIX_INSTRUCTIONCOUNT, // Special: marks end (also gives count) of IC_PREFIX prefixes

    IT_MISC_HLT = 0,
    IT_MISC_NOP,
    IT_MISC_INSTRUCTIONCOUNT, // Special: marks end (also gives count) of IC_MISC isntructions
};

// Returns the length of the instruction based on the opcode and operand size.
// Some exceptions exist and override the length expected by the class, such as RET.
static inline int get_length(uint8_t opcode, uint16_t operand_size, bool prefix_present)
{
    enum instruction_class class = opcode >> 4;
    enum instruction_type op = opcode & 0xf;

    switch (class)
    {
        case IC_REGREG:
            // prefix + opcode + rbyte(optional)
            return prefix_present + (
                ((op == IT_REGREG_PUSHFQ) || op == IT_REGREG_POPFQ)
                    ? 1
                    : 2
            );
        case IC_XREGREG:
            // prefix + opcode + rbyte
            return prefix_present + 2;
        case IC_REGIMM:
        {
            // prefix + opcode + rbyte + imm

            uint8_t imm_bytes_count = 0;
            switch (operand_size)
            {
                case 8:
                    imm_bytes_count = 1;
                    break;
                case 16:
                    imm_bytes_count = 2;
                    break;
                case 32:
                    imm_bytes_count = 4;
                    break;
                case 64:
                    imm_bytes_count = 8;
            }

            return prefix_present + 2 + imm_bytes_count;
        }
        case IC_MEM:
            // opcode + rbyte + imm24(addr)
            return 5;
        case IC_BRANCH:
            // opcode + imm24(addr,optional)
            return (op == IT_BRANCH_RET) ? 1 : 4;
        case IC_XBRANCH:
            // opcode + imm24(addr)
            return 4;
        case IC_MISC:
            // opcode
            return 1;
        case IC_PREFIX:
            // prefix
            return 1;
        default:
            // Return 1 so we don't accidentally step over potentially valid instructions.
            return 1;
    }
}

// Checks if a file name ends in an extension.
static inline bool ends_with(const char *restrict filename, const char *restrict ext)
{
    size_t filename_length = strlen(filename);
    size_t ext_length = strlen(ext);
    if (filename_length < ext_length)
    {
        return false;
    }
    return strcmp(filename + filename_length - ext_length, ext) == 0;
}

// Validates the register index passed.
#define _VALIDATE_REG_INDEX(idx, name) \
    do \
    { \
        if ((idx) < 0) \
        { \
            emit_error("invalid register: '%s'", name); \
        } \
    } \
    while (false)

// Macro to conditionally jump to an address in memory.
#define JUMP(addr, condition) \
    do \
    { \
        if (condition) \
        { \
            rip = addr; \
            continue; \
        } \
    } \
    while (false)

#define _
#undef _