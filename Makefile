# Compiler and flags
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -Iinclude
DEBUG_FLAGS = -g -DDEBUG
RELEASE_FLAGS = -O2 -DNDEBUG

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
.PHONY: all clean debug release install

all: release

# Release build
release: CFLAGS += $(RELEASE_FLAGS)
release: $(BIN_DIR)/$(TARGET)

# Debug build
debug: CFLAGS += $(DEBUG_FLAGS)
debug: $(BIN_DIR)/$(TARGET)

# Create executable
$(BIN_DIR)/$(TARGET): $(OBJECTS) | $(BIN_DIR)
	$(CC) $(OBJECTS) -o $@

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
