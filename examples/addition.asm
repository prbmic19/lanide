.section .text
    ; Set RXA to 2500
    mov rxa, 2500

    ; Set RXB to 7500
    mov rxb, 7500

    ; Add the two registers
    add rxa, rxb

    ; RXA should now be 10000

    ; Halt the execution
    hlt