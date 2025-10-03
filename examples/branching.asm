; Write a NOP (0xF1) and a HLT (0xF0) to an arbitrary address, e.g., 0x1ABCD
; Then branch there.

.section .text
    ; NOP
    mov al, 0xF1
    stb 0x1ABCD, al

    ; HLT
    mov al, 0xF0
    stb 0x1ABCE, al

    mov rxa, 0xCAFEBABE

    ; Jump to the injected code
    jmp 0x1ABCD

    ; The code below should never be reached
    mov rxa, 0xDEADBEEF
    hlt