CC = gcc
CCFLAGS = -Wall -Wextra -Wpedantic
BUILD_DIR = build
ASMSRC = src/rasm.c src/encoders.c
DISASMSRC = src/rdisasm.c
EMUSRC = src/remu.c
ASMEXE = $(BUILD_DIR)/rasm$(DEBUG_SUFFIX)
DISASMEXE = build/rdisasm$(DEBUG_SUFFIX)
EMUEXE = $(BUILD_DIR)/remu$(DEBUG_SUFFIX)

DEBUG ?= 0
ifeq ($(DEBUG), 1)
	CCFLAGS += -ggdb -g3 -fno-inline -O0
	DEBUG_SUFFIX = _debug
else
	CCFLAGS += -s -O2
	DEBUG_SUFFIX =
endif

ifeq ($(OS),Windows_NT)
	MKDIR = if not exist $(BUILD_DIR) mkdir $(BUILD_DIR)
	CLEAN = del /Q $(BUILD_DIR)\*
else
	MKDIR = mkdir -p $(BUILD_DIR)
	CLEAN = rm -rf $(BUILD_DIR)/*
endif

all: $(BUILD_DIR) assembler disassembler emulator

$(BUILD_DIR):
	$(MKDIR)

assembler:
	$(CC) $(CCFLAGS) $(ASMSRC) -o $(ASMEXE)

disassembler:
	$(CC) $(CCFLAGS) $(DISASMSRC) -o $(DISASMEXE)

emulator:
	$(CC) $(CCFLAGS) $(EMUSRC) -o $(EMUEXE)

clean:
	$(CLEAN)

.PHONY: all clean assembler disassembler emulator