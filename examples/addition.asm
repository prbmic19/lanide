.section .text
    ; Set DXA to 2500
    mov dxa, 2500

    ; Set DXB to 7500
    mov dxb, 7500

    ; Add the two registers
    add dxa, dxb

    ; DXA should now be 10000

    ; Halt the execution
    hlt