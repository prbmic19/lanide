.section .data
    .dword 0xAABBCCDD

    ; Sneak a NOP here :P
    ; We could also just have wrote "nop"
    .byte 0xF1

.section .text
    ; Access the dword at address 0x80000 (start of data section)
    ldd dxa, 0x80000

    hlt