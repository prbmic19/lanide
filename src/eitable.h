/** Declarations for instruction encoding. */

#pragma once
#include <stdint.h>

// Encoder function type.
typedef void (*encoder_fn)(struct instruction *ei, const char *restrict destination, const char *restrict source);

// Maps mnemonic to an encoder.
// Multiple mnemonics can have the same encoder, thus having the same opcode.
struct instruction_entry
{
    const char *mnemonic;
    encoder_fn encode;
};

extern const struct instruction_entry instruction_table[];
extern const uint16_t instruction_count;