# Lanide Robust Extended — a 32-bit RISC ISA
[![License: MIT](https://img.shields.io/badge/License-MIT-red.svg)](LICENSE)

<br>

Lanide Robust Extended (**RX**) is the 32-bit sibling of my original **Lanide Robust Native (16-bit)** ISA. The project includes everything needed to experiment with RX programs end-to-end, from writing source code to running and inspecting binaries.

I started this project out of curiosity about how instruction sets, assemblers, and emulators really work under the hood. It's a sandbox for experimenting with ISA design—and yeah, just for fun too.

---

## What makes this special?
Most RISC designs go all-in on **fixed 32-bit instruction widths**. RX breaks that mold: it uses **variable-length instructions** for better code density without giving up decode simplicity.

### Philosophy
- Still **RISC at heart** → load/store only, regular formats, and a small, consistent set of flags (CF, ZF, OF, SF)
- **No wasted bytes** → immediates aren't cramped into awkward bit fields.
- **Readable encoding** → easy to follow for anyone writing an assembler or hacking on the emulator.
- **Consistent flags** → all ALU ops update CF, ZF, OF, and SF in a predictable, uniform way.

## Tools
RX ships with three main tools, all written in C:

- **Assembler (`rasm`)** → translates RX assembly into `.lx` binaries.
- **Emulator (`remu`)** → runs `.lx` programs by fetching, decoding, and executing RX instructions.
- **Disassembler (`rdisasm`)** → prints `.lx` binaries in a style **inspired by GNU `objdump`**, showing addresses, raw bytes, and mnemonics side by side.

## Build
Clone the repo and run `make`.
By default, binaries are built in `release/`:
```sh
git clone https://github.com/prbmic19/lanide32
cd lanide32
make
```

### Debug build
If you want symbols + no optimizations (for stepping through in GDB):
```sh
make DEBUG=1
```
This will drop the binaries in `debug/` instead.

### Clean
To remove build artifacts:
```sh
make clean
```

## Usage
Assemble, disassemble, and run a program:

```sh
./release/rasm examples/addition.asm addition.lx
./release/rdisasm addition.lx
./release/remu addition.lx
```

---

⚠️ **Note:** This is still incomplete/experimental. Expect jank.