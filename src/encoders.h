#pragma once
#include <stdint.h>

typedef struct instruction_handler
{
    const char *mnemonic;
    instruction_td (*encode)(const char *, const char *);
} instruction_handler_td;

extern const instruction_handler_td instruction_table[];
extern const uint8_t instruction_count;