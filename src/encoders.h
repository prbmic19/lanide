/** Declarations for instruction encoding. */

#pragma once
#include <stdint.h>

// Encoder function type.
typedef struct instruction (*encoder_td)(const char *destination, const char *source);

// Maps mnemonic to an encoder.
// Multiple mnemonics can have the same encoder, thus having the same opcode.
struct instruction_entry
{
    const char *mnemonic;
    encoder_td encode;
};

extern const struct instruction_entry instruction_table[];
extern const uint16_t instruction_count;