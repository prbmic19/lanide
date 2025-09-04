; Set DXA (accumulator) to 0x4000 (16384)
movi dxa, 0x4000

; Set DXT (temporary) to 0x2000 (8192)
movi dxt, 0x2000

; Add the two registers
add dxa, dxt

; DXA should now be 0x6000 (24576)

; Halt the execution
hlt