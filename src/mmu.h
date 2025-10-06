/** Declaration of utilities for managing memory. */

#pragma once
#include "definitions.h"

// Note: ppage = physical page, vpage = virtual page

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
struct page_entry
{
    u64_it ppage_index;
    uint8_t permissions;
};

extern struct page_entry page_table[PAGE_COUNT];

extern void map_page(u64_it vpage, u64_it ppage, uint8_t permissions);
extern void unmap_page(u64_it vpage);
extern u64_it translate(u64_it vaddr, uint8_t access_perm);
extern void setup_initial_mappings(void);

extern uint8_t load8(u64_it vaddr);
extern uint16_t load16(u64_it vaddr);
extern uint32_t load32(u64_it vaddr);
extern u64_it load64(u64_it vaddr);

extern void store8(u64_it vaddr, uint8_t value);
extern void store16(u64_it vaddr, uint16_t value);
extern void store32(u64_it vaddr, uint32_t value);
extern void store64(u64_it vaddr, u64_it value);

extern uint8_t fetch8(u64_it vaddr);