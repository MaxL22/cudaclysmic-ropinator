# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -Iinclude
DEBUG_FLAGS = -g -DDEBUG
RELEASE_FLAGS = -O2 -DNDEBUG

# Libraries
LIBS = -lcapstone
LDFLAGS = 

# Check if capstone is installed via pkg-config
CAPSTONE_CFLAGS = $(shell pkg-config --cflags capstone 2>/dev/null)
CAPSTONE_LIBS = $(shell pkg-config --libs capstone 2>/dev/null)

# Use pkg-config if available, otherwise fall back to default
ifneq ($(CAPSTONE_CFLAGS),)
    CFLAGS += $(CAPSTONE_CFLAGS)
    LIBS = $(CAPSTONE_LIBS)
endif

# Directories
SRC_DIR = src
INC_DIR = include
BIN_DIR = bin
OBJ_DIR = obj

# Project name (change this to your executable name)
TARGET = cudaclysmic-ropinator

# Source files
SOURCES = $(wildcard $(SRC_DIR)/*.c)
OBJECTS = $(SOURCES:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

# Default target
.PHONY: all clean debug release install check-deps

all: check-deps release

# Check dependencies
check-deps:
	@echo "Checking for Capstone library..."
	@pkg-config --exists capstone 2>/dev/null || \
		(echo "Warning: Capstone library not found via pkg-config. Make sure libcapstone-dev is installed." && \
		 echo "On Ubuntu/Debian: sudo apt-get install libcapstone-dev" && \
		 echo "On CentOS/RHEL: sudo yum install capstone-devel" && \
		 echo "On macOS: brew install capstone")

# Release build
release: CFLAGS += $(RELEASE_FLAGS)
release: $(BIN_DIR)/$(TARGET)

# Debug build
debug: CFLAGS += $(DEBUG_FLAGS)
debug: $(BIN_DIR)/$(TARGET)

# Create executable
$(BIN_DIR)/$(TARGET): $(OBJECTS) | $(BIN_DIR)
	$(CC) $(OBJECTS) $(LDFLAGS) $(LIBS) -o $@

# Compile source files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Create directories
$(BIN_DIR):
	mkdir -p $(BIN_DIR)

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# Clean build artifacts
clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

# Install (optional - modify path as needed)
install: release
	cp $(BIN_DIR)/$(TARGET) /usr/local/bin/

# Print variables for debugging
print-%:
	@echo $* = $($*)

# Dependencies (optional - for header dependency tracking)
-include $(OBJECTS:.o=.d)

$(OBJ_DIR)/%.d: $(SRC_DIR)/%.c | $(OBJ_DIR)
	@$(CC) $(CFLAGS) -MM -MT $(@:.d=.o) $< > $@
