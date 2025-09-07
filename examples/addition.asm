; Set DXA (accumulator) to 2500
mov dxa, 2500

; Set DXT (temporary) to 7500
mov dxt, 7500

; Add the two registers
add dxa, dxt

; DXA should now be 10000

; Halt the execution
hlt