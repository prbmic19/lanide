.section .data
    .dword 0xAABBCCDD

    ; Sneak a NOP here :P
    ; We could also just have wrote "nop", oh well.
    .byte 0xF1

.section .rodata
    ; Just an arbitrary integer
    .qword 0x431E0E0AAD500

.section .text
    ; Access the dword at address 0x141000 (start of data section)
    ldd dxa, 0x141000

    ; Since the section it's in is writeable... @_@

    mul rxa, 3
    ; Overwrite the NOP there too
    stq 0x141000, rxa

    ; Access the qword at address 0x101000 (start of rodata section)
    ldq rxb, 0x101000

    ; Since the section it's in is read-only, we can't and shouldn't modify it.
    ; mul rxb, 2
    ; stq 0x101000, rxb

    hlt