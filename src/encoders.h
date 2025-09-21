#pragma once
#include <stdint.h>

struct instruction_handler
{
    const char *mnemonic;
    struct instruction (*encode)(const char *, const char *);
};

extern const struct instruction_handler instruction_table[];
extern const uint8_t instruction_count;