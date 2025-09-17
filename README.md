# Lanide Robust Extended — a 32-bit RISC ISA
[![License: MIT](https://img.shields.io/badge/License-MIT-red.svg)](LICENSE)

> [!WARNING]
> This is still incomplete/experimental, and everything is subject to change. Expect jank.

Lanide Robust Extended (**RX**) is the 32-bit extension of my original 16-bit Lanide Robust Native ISA. 
It comes with everything you need to mess around with RX programs, from writing code to running and inspecting binaries.

I built this mostly out of curiosity—I wanted to actually *see* how ISAs, assemblers, and emulators come together. So think of it less as a production-ready toolchain and more as a playground for ISA design. (and yeah, also because it's fun.)

---

## What makes this special?
Most RISC designs stick to fixed 32-bit instruction widths. RX doesn't.
Instead, it goes with variable-length instructions so you get tighter code density without making decoding a nightmare.

### Philosophy
- Still RISC at heart: load/store only, regular formats, and a small, consistent set of flags (CF, ZF, OF, SF)
- No wasted bytes: immediates aren't cramped into awkward bit fields
- Readable encoding: easy to follow for anyone writing an assembler or hacking on the emulator
- Consistent flags: all ALU ops update CF, ZF, OF, and SF in a predictable way

## Tools
RX ships with three main tools, all written in C:
- Assembler (`rasm`): turns RX assembly into `.lx` binaries
- Emulator (`remu`): runs those `.lx` programs instruction by instruction
- Disassembler (`rdisasm`): dumps `.lx` binaries in a GNU `objdump`-style, showing addresses, raw bytes, and mnemonics side by side

## Build

### Prerequisites
- git
- GCC
- Make

Clone the repo and run `make` (cross-platform: works on Linux/macOS and Windows):
```sh
git clone https://github.com/prbmic19/lanide32
cd lanide32
make
```

### Clean
To wipe build artifacts:
```sh
make clean
```

## Example
Here's a tiny RX program taken from `examples/addition.asm`.
It adds two numbers and halts. (nothing fancy, but it shows the basics):
```asm
; examples/addition.asm
mov dxa, 2500
mov dxt, 7500
add dxa, dxt
hlt
```
Assembling it:
```sh
./build/rasm examples/addition.asm addition.lx
```
Disassembling the output:
```sh
./build/rdisasm addition.lx
```
And you'll see something like:
```
Disassembly of addition.lx:

   20000:   17 01 c4 09          mov     dxa,0x9c4
   20004:   17 11 4c 1d          mov     dxt,0x1d4c
   20008:   00 01                add     dxa,dxt
   2000a:   f0                   hlt
```
Finally, running it with the emulator:
```sh
./build/remu addition.lx
```
Now, `dxa` holds the result `10000`.

## Credits
RX pulls inspiration from a bunch of places:
- x86 for the variable-length instruction idea and mnemonics
- ARM for keeping the core simplicity
- GNU objdump for the disassembler output style

Big thanks to the open-source community in general—staring at other people's assemblers and emulators taught me a lot.

## Future Plans
This is just a playground for now, but here's where I'd like to take it:
- More instructions
- Better error messages
- A ~~toy~~ compiler that targets RX
- 64-bit extension someday

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.