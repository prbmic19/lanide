; Write a NOP (0xF1) and a HLT (0xF0) to an arbitrary address, e.g., 0x1ABCD
; Then branch there.

; NOP
mov dxa, 0xF1
stb 0x1ABCD, dxa

; HLT
mov dxa, 0xF0
stb 0x1ABCE, dxa

mov dxa, 0xCAFEBABE

; Jump to the injected code
jmp 0x1ABCD

; The code below should never be reached
mov dxa, 0xDEADBEEF
hlt