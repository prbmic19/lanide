/** Definition of utilities for managing memory. */

#include "mmu.h"
#include "diag.h"

struct page_entry page_table[PAGE_COUNT] = {0};
extern uint8_t *memory;

// Simple identity mapping; vpage = ppage
void map_page(u64_it vpage, u64_it ppage, uint8_t permissions)
{
    if (vpage >= PAGE_COUNT)
    {
        emit_fatal("virtual page index out of bounds: %llu", vpage);
    }
    if (ppage >= PAGE_COUNT)
    {
        emit_fatal("physical page index out of bounds: %llu", ppage);
    }

    page_table[vpage].ppage_index = ppage;
    page_table[vpage].permissions = permissions | PERM_PRESENT;
}

void unmap_page(u64_it vpage)
{
    if (vpage >= PAGE_COUNT)
    {
        emit_fatal("virtual page index out of bounds: %llu", vpage);
    }

    page_table[vpage].permissions = 0;
}

// Translate virtual to physical byte address, and check permissions.
u64_it translate(u64_it vaddr, uint8_t access_perms)
{
    // Let's refrain from using the term "fault" here until we get a proper exception handler.

    u64_it vpage = vaddr / PAGE_SIZE;
    u64_it offset = vaddr % PAGE_SIZE;

    if (vpage >= PAGE_COUNT)
    {
        emit_fatal("virtual address out of bounds: 0x%llx", vaddr);
    }

    struct page_entry pe = page_table[vpage];

    // Check if it's mapped.
    if (!(pe.permissions & PERM_PRESENT))
    {
        emit_fatal("unmapped virtual page: %llu", vaddr, vpage);
    }

    // Check if the page has perm R.
    if ((access_perms & PERM_READ) && !(pe.permissions & PERM_READ))
    {
        emit_fatal("tried to read from non-readable page: %llu", vpage);
    }

    // Check if the page has perm W.
    if ((access_perms & PERM_WRITE) && !(pe.permissions & PERM_WRITE))
    {
        emit_fatal("tried to write to read-only page: %llu", vpage);
    }

    // Check if the page has perm X.
    if ((access_perms & PERM_EXECUTE) && !(pe.permissions & PERM_EXECUTE))
    {
        emit_fatal("tried to execute on non-executable page: %llu", vpage);
    }

    return pe.ppage_index * PAGE_SIZE + offset;
}

void setup_initial_mappings(void)
{
    // Clear all page table entries.
    for (u64_it i = 0; i < PAGE_COUNT; i++)
    {
        page_table[i].permissions = 0;
    }

    // Keep virtual page 0 unmapped so null pointers fault.
    unmap_page(0);

    // .text (RX)
    u64_it text_start = TEXT_BASE / PAGE_SIZE;
    u64_it text_end = RODATA_BASE / PAGE_SIZE;
    for (u64_it page = text_start; page < text_end; page++)
    {
        map_page(page, page, PERM_READ | PERM_EXECUTE);
    }

    // .rodata (R only)
    u64_it rodata_start = RODATA_BASE / PAGE_SIZE;
    u64_it rodata_end = DATA_BASE / PAGE_SIZE;
    for (u64_it page = rodata_start; page < rodata_end; page++)
    {
        map_page(page, page, PERM_READ);
    }

    // .data (RW)
    u64_it data_start = DATA_BASE / PAGE_SIZE;
    u64_it data_end = HEAP_BASE / PAGE_SIZE;
    for (u64_it page = data_start; page < data_end; page++)
    {
        map_page(page, page, PERM_READ | PERM_WRITE);
    }

    // heap (RW, grows upward)
    u64_it heap_start = HEAP_BASE / PAGE_SIZE;
    u64_it heap_end = (STACK_BASE - STACK_SIZE) / PAGE_SIZE;
    for (u64_it page = heap_start; page < heap_end; page++)
    {
        map_page(page, page, PERM_READ | PERM_WRITE);
    }

    // stack (RW, grows downward)
    u64_it stack_start = (STACK_BASE - STACK_SIZE) / PAGE_SIZE;
    u64_it stack_end = STACK_BASE / PAGE_SIZE;
    for (u64_it page = stack_start; page < stack_end; page++)
    {
        map_page(page, page, PERM_READ | PERM_WRITE);
    }

    // Unmap one guard page between heap and stack
    unmap_page(heap_end);
}

/* Typed loads/stores */

uint8_t load8(u64_it vaddr)
{
    u64_it p = translate(vaddr, PERM_READ);
    return memory[p];
}
uint16_t load16(u64_it vaddr)
{
    return (uint16_t)load8(vaddr) | ((uint16_t)load8(vaddr + 1) << 8); 
}
uint32_t load32(u64_it vaddr)
{
    return (uint32_t)load16(vaddr) | ((uint32_t)load16(vaddr + 2) << 16);
}
u64_it load64(u64_it vaddr)
{
    return (u64_it)load32(vaddr) | ((u64_it)load32(vaddr + 4) << 32); 
}

void store8(u64_it vaddr, uint8_t value)
{
    u64_it p = translate(vaddr, PERM_WRITE);
    memory[p] = value;
}
void store16(u64_it vaddr, uint16_t value)
{
    store8(vaddr, value & 0xff);
    store8(vaddr + 1, value >> 8);
}
void store32(u64_it vaddr, uint32_t value)
{
    store16(vaddr, value & 0xffff);
    store16(vaddr + 2, value >> 16);
}
void store64(u64_it vaddr, u64_it value)
{
    store32(vaddr, value & 0xffffffff);
    store32(vaddr + 4, value >> 32);
}

// Special: requires PERM_EXECUTE for fetching instructions

uint8_t fetch8(u64_it vaddr)
{
    u64_it p = translate(vaddr, PERM_EXECUTE);
    return memory[p];
}