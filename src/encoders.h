#pragma once
#include <stdint.h>

typedef struct
{
    const char *mnemonic;
    uint32_t (*encode)(const char *operand1, const char *operand2);
} InstructionHandler;

extern InstructionHandler instruction_table[];
extern const size_t instruction_count;