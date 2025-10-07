/** Declaration of utilities for managing memory. */

#pragma once
#include "definitions.h"

// Size of one memory page
#define PAGE_SIZE 0x1000
// Number of memory pages
#define PAGE_COUNT (MEM_SIZE / PAGE_SIZE)

/* Permissions for each page */

#define PERM_PRESENT    0x1
#define PERM_READ       0x2
#define PERM_WRITE      0x4
#define PERM_EXECUTE    0x8

// Properties of a page.
struct mempage
{
    u64 ppage_index;
    uint8_t permissions;
};

extern struct mempage page_table[PAGE_COUNT];

extern void map_page(u64 vpage, u64 ppage, uint8_t permissions);
extern void unmap_page(u64 vpage);
extern u64 translate(u64 vaddr, uint8_t access_perm);
extern void setup_initial_mappings(void);

extern uint8_t load8(u64 vaddr);
extern uint16_t load16(u64 vaddr);
extern uint32_t load32(u64 vaddr);
extern u64 load64(u64 vaddr);

extern void store8(u64 vaddr, uint8_t value);
extern void store16(u64 vaddr, uint16_t value);
extern void store32(u64 vaddr, uint32_t value);
extern void store64(u64 vaddr, u64 value);

extern uint8_t fetch8(u64 vaddr);