# Compiler and flags
CC = gcc
CFLAGS = -g -O0 -fno-stack-protector -z execstack -fno-pie -no-pie
STATIC_FLAGS = -static
DEBUG_FLAGS = -v

# Source files
SIMPLE_SRC = test_binary.c

# Target binaries
SIMPLE_BIN = test_binary
STATIC_BIN = test_binary_static
DEBUG_BIN = test_binary_debug

# Default target
all: $(SIMPLE_BIN)

# Simple test binary
$(SIMPLE_BIN): $(SIMPLE_SRC)
	$(CC) $(CFLAGS) -o $@ $<

# Static binary (more gadgets, self-contained)
$(STATIC_BIN): $(SIMPLE_SRC)
	$(CC) $(CFLAGS) $(STATIC_FLAGS) -o $@ $<

# Debug binary with verbose output
$(DEBUG_BIN): $(SIMPLE_SRC)
	$(CC) $(CFLAGS) $(DEBUG_FLAGS) -o $@ $<

# Analysis targets
analyze: $(SIMPLE_BIN)
	@echo "=== File Information ==="
	file $(SIMPLE_BIN)
	@echo "\n=== Security Features ==="
	checksec --file=$(SIMPLE_BIN) 2>/dev/null || echo "checksec not available"
	@echo "\n=== ELF Header ==="
	readelf -h $(SIMPLE_BIN)
	@echo "\n=== Disassembly (first 50 lines) ==="
	objdump -d $(SIMPLE_BIN) | head -50

# Clean up
clean:
	rm -f $(SIMPLE_BIN) $(STATIC_BIN)
	rm -f *.o

# Help target
help:
	@echo "Available targets:"
	@echo "  all         - Build all test binaries"
	@echo "  $(SIMPLE_BIN)    - Build simple test binary"
	@echo "  $(STATIC_BIN)    - Build static test binary"
	@echo "  $(DEBUG_BIN)     - Build with verbose debugging"
	@echo "  analyze     - Analyze the simple binary"
	@echo "  clean       - Remove binaries"
	@echo "  help        - Show this help"

.PHONY: all analyze test clean distclean help
