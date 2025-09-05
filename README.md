# Lanide Robust Extended — a 32-bit RISC ISA
[![License: MIT](https://img.shields.io/badge/License-MIT-red.svg)](LICENSE)

<br>

Lanide Robust Extended (**RX**) is the 32-bit sibling of my original **Lanide Robust Native (16-bit)** ISA. It ships with a tiny assembler and emulator written in C.

I started this project out of curiosity about how instruction sets, assemblers, and emulators really work under the hood. It's a sandbox for experimenting with ISA design—and yeah, just for fun too.

---

## What makes this special?
Most RISC designs go all-in on **fixed 32-bit instruction widths**. RX breaks that mold: it uses **variable-length instructions** for better code density without giving up decode simplicity.

### Philosophy
- Still **RISC at heart** → load/store only, regular formats, and a small, consistent set of flags (CF, OF, ZF, SF)
- **No wasted bytes** → immediates aren't cramped into awkward bit fields.
- **Readable encoding** → easy to follow for anyone writing an assembler or hacking on the emulator.
- **Consistent flags** → all ALU ops update CF, OF, ZF, and SF in a predictable, uniform way.

---

⚠️ **Note:** This is still incomplete/experimental. Expect jank.