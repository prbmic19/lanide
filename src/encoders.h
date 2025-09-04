#pragma once
#include <stdint.h>

typedef EncodedInstruction (*EncodeFunction)(const char *, const char *);

typedef struct
{
    const char *mnemonic;
    EncodeFunction encode;
} InstructionHandler;

extern InstructionHandler instruction_table[];
extern const uint8_t instruction_count;