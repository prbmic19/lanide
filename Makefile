CC = gcc
CCFLAGS = -Wall -Wextra -Wpedantic -MMD -MP
BUILD_DIR = build
SOURCE_DIR = src

# Source files
ASMSRC = rasm.c eitable.c argparser.c diag.c
DISASMSRC = rdisasm.c argparser.c diag.c
EMUSRC = remu.c argparser.c diag.c

# Object files
ASMOBJ = $(addprefix $(BUILD_DIR)/,$(ASMSRC:.c=.o))
DISASMOBJ = $(addprefix $(BUILD_DIR)/,$(DISASMSRC:.c=.o))
EMUOBJ = $(addprefix $(BUILD_DIR)/,$(EMUSRC:.c=.o))

# Executables
ASMEXE = $(BUILD_DIR)/rasm$(DEBUG_SUFFIX)
DISASMEXE = $(BUILD_DIR)/rdisasm$(DEBUG_SUFFIX)
EMUEXE = $(BUILD_DIR)/remu$(DEBUG_SUFFIX)

# Debug mode toggle
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

all: $(BUILD_DIR) $(ASMEXE) $(DISASMEXE) $(EMUEXE)

$(BUILD_DIR):
	$(MKDIR)

# .c -> .o
$(BUILD_DIR)/%.o: $(SOURCE_DIR)/%.c
	$(CC) $(CCFLAGS) -c $< -o $@

# Executables depend on object files
$(ASMEXE): $(ASMOBJ)
	$(CC) $(CCFLAGS) $^ -o $@

$(DISASMEXE): $(DISASMOBJ)
	$(CC) $(CCFLAGS) $^ -o $@

$(EMUEXE): $(EMUOBJ)
	$(CC) $(CCFLAGS) $^ -o $@

clean:
	$(CLEAN)

# Pull in all generated dependency files (if they exist)
-include $(ASMOBJ:.o=.d) $(DISASMOBJ:.o=.d) $(EMUOBJ:.o=.d)

.PHONY: all clean