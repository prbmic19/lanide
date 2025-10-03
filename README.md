# Lanide Robust Extended — a 64-bit RISC ISA
[![License: MIT](https://img.shields.io/badge/License-MIT-red.svg)](LICENSE)

> [!WARNING]
> This is still incomplete/experimental, and everything is subject to change.

## Introduction
Lanide Robust Extended 64 (**RX64**) is the 64-bit extension of my 32-bit Lanide Extended ISA. 
It comes with everything you need to mess around with RX64 programs, from writing code to running and inspecting binaries.

I built this mostly out of curiosity—I wanted to actually *see* how ISAs, assemblers, and emulators come together. So think of it less as a production-ready toolchain and more as a playground for ISA design. (and yeah, also because it's fun.)

---

## What makes this special?
Most RISC designs stick to fixed 32-bit instruction widths. RX64 doesn't.
Instead, it goes with variable-length instructions so you get tighter code density without making decoding a nightmare.

## Tools
RX currently ships with three main tools:
- Assembler (`rasm`): turns RX64 assembly into `.lx` binaries
- Emulator (`remu`): runs those `.lx` programs instruction by instruction
- Disassembler (`rdisasm`): dumps `.lx` binaries in a GNU `objdump`-style, showing addresses, raw bytes, and mnemonics side by side

## Build

### Prerequisites
You'll need the following tools installed:
- [GCC](https://gcc.gnu.org/)
- [Make](https://www.gnu.org/software/make/)

Clone the repo and run `make` (cross-platform: works on Linux/macOS and Windows):
```sh
git clone https://github.com/prbmic19/lanide
cd lanide
make
```

### Clean
To remove build artifacts:
```sh
make clean
```

## Example
Here's a tiny RX64 assembly program taken from `examples/addition.asm`.
It adds two numbers and halts. (nothing fancy, but it shows the basics):
```asm
; examples/addition.asm
.section .text
    mov rxa, 2500
    mov rxb, 7500
    add rxa, dxt
    hlt
```
Assembling it:
```sh
./build/rasm examples/addition.asm -o addition.lx
```
Disassembling the output (you can optionally add color to the disassembly):
```sh
./build/rdisasm addition.lx
```
And you'll see something like:
```
Target: addition.lx

Disassembly of section .text:

   0x1000: 	24 00 c4 09 00 00 00 00 00 00          	mov     rxa,0x9c4
   0x100a: 	24 10 4c 1d 00 00 00 00 00 00          	mov     rxb,0x1d4c
   0x1014: 	00 01                                  	add     rxa,rxb
   0x1016: 	f0                                     	hlt
```
Finally, running it with the emulator, displaying register values at the end:
```sh
./build/remu --dump-regs addition.lx
```
You'll see that `rxa` holds the result `10000`.

## Credits
RX64 pulls inspiration from a bunch of places:
- x86 for the variable-length instruction idea and mnemonics
- ARM for keeping the core simplicity
- GNU objdump for the disassembler output style

Big thanks to the open-source community in general—staring at other people's assemblers and emulators taught me a lot.

## Future Plans
This is just a playground for now, but here's where I'd like to take it:
- More instructions
- Better error messages
- Proper documentation
- Test suites for validation
- A ~~toy~~ compiler that targets RX64

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.