/** Definition of utilities for managing memory. */

#include "mmu.h"
#include "diag.h"

struct mempage page_table[PAGE_COUNT] = {0};
extern uint8_t *memory;

void map_page(u64 vpage, u64 ppage, uint8_t permissions)
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

void unmap_page(u64 vpage)
{
    if (vpage >= PAGE_COUNT)
    {
        emit_fatal("virtual page index out of bounds: %llu", vpage);
    }

    page_table[vpage].permissions = 0;
}

// Translate virtual to physical byte address, and check permissions.
u64 translate(u64 vaddr, uint8_t access_perms)
{
    // Let's refrain from using the term "fault" here until we get a proper exception handler.

    u64 vpage = vaddr / PAGE_SIZE;
    u64 offset = vaddr % PAGE_SIZE;

    if (vpage >= PAGE_COUNT)
    {
        emit_fatal("virtual address out of bounds: 0x%llx", vaddr);
    }

    struct mempage pe = page_table[vpage];

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
    for (u64 i = 0; i < PAGE_COUNT; i++)
    {
        unmap_page(i);
    }

    // .text (RX)
    u64 text_start = TEXT_BASE / PAGE_SIZE;
    u64 text_end = RODATA_BASE / PAGE_SIZE;
    for (u64 page = text_start; page < text_end; page++)
    {
        map_page(page, page, PERM_READ | PERM_EXECUTE);
    }

    // .rodata (R only)
    u64 rodata_start = RODATA_BASE / PAGE_SIZE;
    u64 rodata_end = DATA_BASE / PAGE_SIZE;
    for (u64 page = rodata_start; page < rodata_end; page++)
    {
        map_page(page, page, PERM_READ);
    }

    // .data (RW)
    u64 data_start = DATA_BASE / PAGE_SIZE;
    u64 data_end = HEAP_BASE / PAGE_SIZE;
    for (u64 page = data_start; page < data_end; page++)
    {
        map_page(page, page, PERM_READ | PERM_WRITE);
    }

    // heap (RW, grows upward)
    u64 heap_start = HEAP_BASE / PAGE_SIZE;
    u64 heap_end = (STACK_BASE - STACK_SIZE) / PAGE_SIZE;
    for (u64 page = heap_start; page < heap_end; page++)
    {
        map_page(page, page, PERM_READ | PERM_WRITE);
    }

    // stack (RW, grows downward)
    u64 stack_start = (STACK_BASE - STACK_SIZE) / PAGE_SIZE;
    u64 stack_end = STACK_BASE / PAGE_SIZE;
    for (u64 page = stack_start; page < stack_end; page++)
    {
        map_page(page, page, PERM_READ | PERM_WRITE);
    }

    // Unmap one guard page between heap and stack
    unmap_page(heap_end);
}

/* Typed loads/stores */

uint8_t load8(u64 vaddr)
{
    u64 p = translate(vaddr, PERM_READ);
    return memory[p];
}
uint16_t load16(u64 vaddr)
{
    return (uint16_t)load8(vaddr) | ((uint16_t)load8(vaddr + 1) << 8); 
}
uint32_t load32(u64 vaddr)
{
    return (uint32_t)load16(vaddr) | ((uint32_t)load16(vaddr + 2) << 16);
}
u64 load64(u64 vaddr)
{
    return (u64)load32(vaddr) | ((u64)load32(vaddr + 4) << 32); 
}

void store8(u64 vaddr, uint8_t value)
{
    u64 p = translate(vaddr, PERM_WRITE);
    memory[p] = value;
}
void store16(u64 vaddr, uint16_t value)
{
    store8(vaddr, value & 0xff);
    store8(vaddr + 1, value >> 8);
}
void store32(u64 vaddr, uint32_t value)
{
    store16(vaddr, value & 0xffff);
    store16(vaddr + 2, value >> 16);
}
void store64(u64 vaddr, u64 value)
{
    store32(vaddr, value & 0xffffffff);
    store32(vaddr + 4, value >> 32);
}

// Special: requires PERM_EXECUTE for fetching instructions
uint8_t fetch8(u64 vaddr)
{
    u64 p = translate(vaddr, PERM_READ | PERM_EXECUTE);
    return memory[p];
}