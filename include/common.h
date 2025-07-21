#ifndef COMMON_H
#define COMMON_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Check if compiled with nvcc
#ifdef __CUDACC__
#include <cuda_runtime.h>
#define CUDA_COMPILED 1
#else
#define CUDA_COMPILED 0
#endif


/* Architecture types */
typedef enum {
  ARCH_UNKNOWN = 0,
  ARCH_X86,
  ARCH_X86_64,
  ARCH_ARM,
  ARCH_ARM64
} architecture_t;

/* Binary format types */
typedef enum {
  FORMAT_UNKNOWN = 0,
  FORMAT_ELF,
  FORMAT_PE,
  FORMAT_MACH_O
} binary_format_t;

/* Gadget types */
typedef enum {
  GADGET_UNKNOWN = 0,
  GADGET_RET,     // ret
  GADGET_POP_RET, // pop reg; ret
  GADGET_MOV_RET, // mov reg, reg; ret
  GADGET_ADD_RET, // add reg, imm; ret
  GADGET_SUB_RET, // sub reg, imm; ret
  GADGET_JMP,     // jmp reg
  GADGET_CALL,    // call reg
  GADGET_SYSCALL  // syscall; ret
} gadget_type_t;

/* Gadget structure */
typedef struct {
  uint64_t address;    // Virtual address of gadget
  uint8_t *bytes;      // Raw instruction bytes
  size_t length;       // Length of gadget in bytes
  char *disasm;        // Disassembled string
  gadget_type_t type;  // Type of gadget
  architecture_t arch; // Architecture
} gadget_t;

/* Gadget collection */
typedef struct {
  gadget_t *gadgets; // Array of gadgets
  size_t count;      // Number of gadgets
  size_t capacity;   // Array capacity
} gadget_collection_t;

/* Binary section */
typedef struct {
  char name[64];         // Section name
  uint64_t virtual_addr; // Virtual address
  uint64_t file_offset;  // File offset
  size_t size;           // Section size
  uint8_t *data;         // Section data
  bool executable;       // Is executable
  bool readable;         // Is readable
} binary_section_t;

/* Binary information */
typedef struct {
  char *filename;             // Binary filename
  FILE *file;                 // File handle
  binary_format_t format;     // Binary format
  architecture_t arch;        // Architecture
  uint64_t entry_point;       // Entry point address
  uint64_t base_address;      // Base load address
  binary_section_t *sections; // Array of sections
  size_t section_count;       // Number of sections
  size_t file_size;           // File size
} binary_info_t;

/* Configuration structure */
typedef struct {
  char *input_file;          // Input binary file
  char *output_file;         // Output file (optional)
  int max_gadget_length;     // Maximum gadget length
  bool verbose;              // Verbose output
  bool use_cuda;             // Enable CUDA acceleration
  architecture_t arch; // Force architecture
} config_t;

/* Function result codes */
typedef enum {
  RESULT_SUCCESS = 0,
  RESULT_ERROR_GENERIC,
  RESULT_ERROR_PARAM,
  RESULT_ERROR_FILE,
  RESULT_ERROR_FORMAT,
  RESULT_ERROR_MEMORY,
  RESULT_ERROR_ARCH,
  RESULT_ERROR_CUDA
} result_t;

/* Utility macros */
#define MAX_GADGET_LENGTH 20
#define MAX_SECTIONS 64
#define GADGET_INITIAL_CAPACITY 1000

/* Memory management helpers */
#define SAFE_FREE(ptr)                                                         \
  do {                                                                         \
    if (ptr) {                                                                 \
      free(ptr);                                                               \
      ptr = NULL;                                                              \
    }                                                                          \
  } while (0)

/* Error handling */
#define CHECK_NULL(ptr, msg)                                                   \
  do {                                                                         \
    if (!(ptr)) {                                                              \
      fprintf(stderr, "Error: %s\n", msg);                                     \
      return RESULT_ERROR_MEMORY;                                              \
    }                                                                          \
  } while (0)

#endif /* COMMON_H */
