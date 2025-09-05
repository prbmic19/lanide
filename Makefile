CC = gcc
CCFLAGS = -Wall -Wextra -Wpedantic
ASMSRC = src/rasm.c src/encoders.c
EMUSRC = src/remu.c
ASMEXE = $(BUILD_DIR)/rasm
EMUEXE = $(BUILD_DIR)/remu

DEBUG ?= 0
ifeq ($(DEBUG), 1)
	CCFLAGS += -ggdb -g3 -fno-inline -O0
	BUILD_DIR = debug
else
	CCFLAGS += -s -O2
	BUILD_DIR = release
endif

ifeq ($(OS),Windows_NT)
	MKDIR = if not exist $(BUILD_DIR) mkdir $(BUILD_DIR)
	CLEAN = del /Q $(BUILD_DIR)\*
else
	MKDIR = mkdir -p $(BUILD_DIR)
	CLEAN = rm -rf $(BUILD_DIR)/*
endif

all: $(BUILD_DIR) assembler emulator

$(BUILD_DIR):
	$(MKDIR)

assembler:
	$(CC) $(CCFLAGS) $(ASMSRC) -o $(ASMEXE)

emulator:
	$(CC) $(CCFLAGS) $(EMUSRC) -o $(EMUEXE)

clean:
	$(CLEAN)

.PHONY: all clean assembler emulator