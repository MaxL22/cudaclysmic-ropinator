#include "../include/common.h"
#include "../include/gadget_finder.h"
#include <capstone/capstone.h> // Disassembly engine
#include <stdio.h>
#include <string.h>

// Glbal handles for disassembly
static csh cs_handle = 0;
static bool cs_initialized = false;

/*
 * Starting from the binary and search config,
 * all populated, gadget_collection initialized,
 * To find the gadgets:
 *     For each section, check if it's executable
 *     and if it is, call the appropriate search function
 */
result_t find_gadgets(const binary_info_t *binary,
                      const search_config_t *config,
                      gadget_collection_t *collection) {

  result_t result;

  // Check arch, if it's not supported we're getting it out of the way early
  switch (binary->arch) {
  case ARCH_X86:
  case ARCH_X86_64:
    break;
  case ARCH_ARM:
  case ARCH_ARM64:
  case ARCH_UNKNOWN:
  default:
    fprintf(stderr, "Error: architecture not yet supported\n");
    return RESULT_ERROR_ARCH;
  }

  // For each section call the correct function
  for (size_t i = 0; i < binary->section_count; i++) {
    binary_section_t *sec = binary->sections + i;

    if (!sec->executable)
      continue;
    switch (binary->arch) {
    case ARCH_X86:
    case ARCH_X86_64:
      result = find_in_section_x86_64(sec, config, collection);
      break;
    default:
      fprintf(stderr,
              "Error: you should not be seeing this, architecture error\n");
      return RESULT_ERROR_ARCH;
    }
    if (result != RESULT_SUCCESS)
      fprintf(stderr, "Error while searching in section: %s", sec->name);
  }

  return RESULT_SUCCESS;
}

result_t init_gadget_collection(gadget_collection_t *collection) {
  // Parameter validation
  if (!collection) {
    return RESULT_ERROR_PARAM;
  }

  // Initialize the collection structure
  collection->gadgets = malloc(GADGET_INITIAL_CAPACITY * sizeof(gadget_t));
  if (!collection->gadgets) {
    return RESULT_ERROR_MEMORY;
  }

  collection->count = 0;
  collection->capacity = GADGET_INITIAL_CAPACITY;

  return RESULT_SUCCESS;
}

result_t cleanup_gadget_collection(gadget_collection_t *collection) {
  if (!collection)
    return RESULT_ERROR_PARAM;

  for (size_t i = 0; i < collection->count; i++) {
    SAFE_FREE(collection->gadgets[i].bytes);
    SAFE_FREE(collection->gadgets[i].disasm);
  }

  SAFE_FREE(collection->gadgets);

  collection->count = 0;
  collection->capacity = 0;

  return RESULT_SUCCESS;
}

// Adds gadget to collection, CONSUMES THE GADGET
result_t add_gadget(gadget_collection_t *collection, gadget_t *gadget) {
  if (!collection || !gadget) {
    return RESULT_ERROR_PARAM;
  }

  // Check if we need to resize the array, double it just in case
  if (collection->count >= collection->capacity) {
    // Realloc
    gadget_t *new_gadgets = realloc(
        collection->gadgets, collection->capacity * 2 * sizeof(gadget_t));
    if (!new_gadgets) {
      return RESULT_ERROR_MEMORY;
    }
    // Update
    collection->gadgets = new_gadgets;
    collection->capacity *= 2;
  }

  // Copy the gadget data
  gadget_t *dest = collection->gadgets + collection->count;

  // Copy fields
  dest->address = gadget->address;
  dest->length = gadget->length;
  dest->type = gadget->type;
  dest->arch = gadget->arch;
  // Copy bytes array
  if (gadget->bytes && gadget->length > 0) {
    dest->bytes = malloc(gadget->length);
    if (!dest->bytes) {
      return RESULT_ERROR_MEMORY;
    }
    memcpy(dest->bytes, gadget->bytes, gadget->length);
  } else {
    dest->bytes = NULL;
  }
  // Copy disassembly string
  if (gadget->disasm) {
    size_t disasm_len = strlen(gadget->disasm) + 1;
    dest->disasm = malloc(disasm_len);
    if (!dest->disasm) {
      SAFE_FREE(dest->bytes);
      return RESULT_ERROR_MEMORY;
    }
    strcpy(dest->disasm, gadget->disasm);
  } else {
    dest->disasm = NULL;
  }

  collection->count++;

  // Free the gadget
  free_gadget(gadget);

  return RESULT_SUCCESS;
}

void free_gadget(gadget_t *gadget) {
  SAFE_FREE(gadget->bytes);
  SAFE_FREE(gadget->disasm);
  SAFE_FREE(gadget);
}

result_t setup_search_configuration(search_config_t *config,
                                    const config_t *params,
                                    const binary_info_t *binary_info) {
  if (!config)
    return RESULT_ERROR_PARAM;

  config->max_gadget_length = params->max_gadget_length;
  config->find_rop_gadgets = true;
  config->find_syscall_gadgets = true;
  config->target_arch = binary_info->arch;

  return RESULT_SUCCESS;
}

// Just checks if it's a ret, for readability
bool is_ret_instruction(const uint8_t *bytes, size_t offset) {
  if (!bytes)
    return false;
  return bytes[offset] == X86_64_RET_OPCODE;
}

// Initialize capstone
result_t init_capstone() {
  if (cs_initialized) {
    return RESULT_SUCCESS;
  }

  if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle) != CS_ERR_OK) {
    fprintf(stderr,
            "Error: Failed to initialize Capstone disassembly engine\n");
    return RESULT_ERROR_GENERIC;
  }

  // Set options for better disassembly
  cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);
  cs_option(cs_handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);

  cs_initialized = true;
  return RESULT_SUCCESS;
}

// Clean capstone
void cleanup_capstone() {
  if (cs_initialized) {
    cs_close(&cs_handle);
    cs_initialized = false;
  }
}

/*
 * Create actual assembly using capstone
 * Takes a byte string, length of said string and starting address for the
 * instructions
 * returns the disassembled string
 */
char *create_disassembly(const uint8_t *bytes, size_t length,
                         uint64_t address) {
  if (!bytes || length == 0)
    return NULL;
  // Initialize Capstone if not already done
  if (init_capstone() != RESULT_SUCCESS) {
    return NULL;
  }

  cs_insn *insn;
  size_t count = cs_disasm(cs_handle, bytes, length, address, 0, &insn);

  // If it fails
  if (count == 0) {
    // Fallback to hex if disassembly fails
    size_t hex_len = length * 3 + 20; // Extra space for "db " prefixes
    char *disasm = malloc(hex_len);
    if (!disasm)
      return NULL;

    char *ptr = disasm;
    for (size_t i = 0; i < length; i++) {
      if (i > 0) {
        ptr += sprintf(ptr, "; ");
      }
      ptr += sprintf(ptr, "db 0x%02x", bytes[i]);
    }
    return disasm;
  }

  // Calculate required buffer size
  size_t total_len = 0;
  for (size_t i = 0; i < count; i++) {
    total_len += strlen(insn[i].mnemonic) + strlen(insn[i].op_str) +
                 4; // mnemonic + " " + op_str + "; "
  }
  total_len += 1; // null terminator

  char *disasm = malloc(total_len);
  if (!disasm) {
    cs_free(insn, count);
    return NULL;
  }

  char *ptr = disasm;
  for (size_t i = 0; i < count; i++) {
    if (i > 0) {
      ptr += sprintf(ptr, "; ");
    }

    if (strlen(insn[i].op_str) > 0) {
      ptr += sprintf(ptr, "%s %s", insn[i].mnemonic, insn[i].op_str);
    } else {
      ptr += sprintf(ptr, "%s", insn[i].mnemonic);
    }
  }
  *ptr = '\0';

  cs_free(insn, count);
  return disasm;
}

// Classify x86/x64 gadgets, returns the type
gadget_type_t classify_x86_64_gadget(gadget_t *gadget) {
  uint8_t *bytes = gadget->bytes;
  size_t length = gadget->length;

  if (!bytes || length == 0)
    return GADGET_UNKNOWN;
  // Check if it's just a ret
  if (length == 1 && bytes[0] == X86_64_RET_OPCODE) {
    return GADGET_RET;
  }
  // Must end with ret
  if (bytes[length - 1] != X86_64_RET_OPCODE) {
    return GADGET_UNKNOWN;
  }
  // Initialize Capstone if not already done
  if (init_capstone() != RESULT_SUCCESS) {
    return GADGET_UNKNOWN;
  }

  cs_insn *insn;
  size_t count = cs_disasm(cs_handle, bytes, length, gadget->address, 0, &insn);
  if (count == 0) {
    return GADGET_UNKNOWN;
  }

  gadget_type_t type = GADGET_UNKNOWN;

  // Analyze instructions (excluding the final ret)
  for (size_t i = 0; i < count - 1; i++) {
    const char *mnemonic = insn[i].mnemonic;
    // Check for pop instructions
    if (strncmp(mnemonic, "pop", 3) == 0) {
      type = GADGET_POP_RET;
      break;
    }
    // Check for mov instructions
    if (strncmp(mnemonic, "mov", 3) == 0) {
      type = GADGET_MOV_RET;
      break;
    }
    // Check for add instructions
    if (strncmp(mnemonic, "add", 3) == 0) {
      type = GADGET_ADD_RET;
      break;
    }
    // Check for sub instructions
    if (strncmp(mnemonic, "sub", 3) == 0) {
      type = GADGET_SUB_RET;
      break;
    }
    // Check for syscall instruction
    if (strncmp(mnemonic, "syscall", 7) == 0) {
      type = GADGET_SYSCALL;
      break;
    }
    // Check for xor instructions (useful for zeroing registers)
    if (strncmp(mnemonic, "xor", 3) == 0) {
      if (type == GADGET_UNKNOWN)
        type = GADGET_MOV_RET; // Treat as mov-like
    }
    // Check for inc/dec instructions
    if (strncmp(mnemonic, "inc", 3) == 0 || strncmp(mnemonic, "dec", 3) == 0) {
      if (type == GADGET_UNKNOWN)
        type = GADGET_ADD_RET; // Treat as add-like
    }
  }
  cs_free(insn, count);
  return type;
}

/* Main function to analyze a sequence and create a gadget */
result_t analyze_sequence(const uint8_t *data, size_t length,
                          uint64_t base_addr, architecture_t arch,
                          gadget_t *gadget) {
  if (!data || !gadget || length == 0) {
    return RESULT_ERROR_PARAM;
  }
  // Initialize gadget structure
  memset(gadget, 0, sizeof(gadget_t));
  // Set basic properties
  gadget->address = base_addr;
  gadget->length = length;
  gadget->arch = arch;

  // Allocate and copy instruction bytes
  gadget->bytes = malloc(length);
  if (!gadget->bytes) {
    return RESULT_ERROR_MEMORY;
  }
  memcpy(gadget->bytes, data, length);

  // Create disassembly string
  gadget->disasm = create_disassembly(data, length, base_addr);
  if (!gadget->disasm) {
    SAFE_FREE(gadget->bytes);
    return RESULT_ERROR_MEMORY;
  }

  // Classify the gadget
  switch (arch) {
  case ARCH_X86:
  case ARCH_X86_64:
    gadget->type = classify_x86_64_gadget(gadget);
    break;
  default:
    fprintf(stderr,
            "Error: you should not be seeing this, architecture error\n");
    return RESULT_ERROR_ARCH;
  }

  return RESULT_SUCCESS;
}

/* Main function to find gadgets in an x86-64 section */
result_t find_in_section_x86_64(const binary_section_t *section,
                                const search_config_t *config,
                                gadget_collection_t *collection) {
  if (!section || !config || !collection) {
    return RESULT_ERROR_PARAM;
  }
  if (!section->data || section->size == 0) {
    return RESULT_SUCCESS; // Nothing to search, I guess it's a win
  }
  // Initialize Capstone
  if (init_capstone() != RESULT_SUCCESS) {
    return RESULT_ERROR_GENERIC;
  }
  result_t result = RESULT_SUCCESS;

  // Search through the section data for ret instructions (0xC3)
  for (size_t i = 0; i < section->size; i++) {
    if (section->data[i] != X86_64_RET_OPCODE) {
      continue;
    }

    // Found a ret instruction, now search backwards for gadgets
    // Try different gadget lengths, starting from length 1 (just ret) up to max
    int max_len = config->max_gadget_length;
    if (max_len <= 0 || max_len > MAX_GADGET_LENGTH) {
      max_len = MAX_GADGET_LENGTH;
    } // This check is here in case it eventually becomes an actual parameter

    for (int gadget_len = 1; gadget_len <= max_len; gadget_len++) {
      // Calculate start position (gadget_len bytes ending at position i)
      if (gadget_len > (int)(i + 1))
        break; // Can't go before section start

      size_t start_pos = i + 1 - gadget_len;
      uint64_t gadget_addr = section->virtual_addr + start_pos;

      // Create a temporary gadget to analyze this sequence
      gadget_t *temp_gadget = malloc(sizeof(gadget_t));
      result = analyze_sequence(section->data + start_pos, gadget_len,
                                gadget_addr, config->target_arch, temp_gadget);

      if (result != RESULT_SUCCESS) {
        continue; // Skip this sequence
      }
      if (temp_gadget->type == GADGET_UNKNOWN) {
        continue;
      }

      // Check if this is a valid gadget based on configuration
      bool should_add = false;

      if (config->find_rop_gadgets) {
        switch (temp_gadget->type) {
        case GADGET_RET:
        case GADGET_POP_RET:
        case GADGET_MOV_RET:
        case GADGET_ADD_RET:
        case GADGET_SUB_RET:
          should_add = true;
          break;
        default:
          break;
        }
      }

      if (config->find_syscall_gadgets && temp_gadget->type == GADGET_SYSCALL) {
        should_add = true;
      }

      if (!should_add) {
        free_gadget(temp_gadget);
        continue;
      }

      result = add_gadget(collection, temp_gadget);
      if (result != RESULT_SUCCESS) {
        return result;
      }
    }
  }

  return RESULT_SUCCESS;
}

int compare_gadgets_by_address(const void *a, const void *b) {
  const gadget_t *gadget_a = (const gadget_t *)a;
  const gadget_t *gadget_b = (const gadget_t *)b;

  if (gadget_a->address < gadget_b->address) {
    return -1;
  } else if (gadget_a->address > gadget_b->address) {
    return 1;
  } else {
    return 0;
  }
}

/* Sort gadgets in collection by address */
result_t sort_gadgets(gadget_collection_t *collection) {
  if (!collection) {
    return RESULT_ERROR_PARAM;
  }

  if (collection->count == 0 || !collection->gadgets) {
    return RESULT_SUCCESS; // Nothing to sort
  }

  // Use qsort to sort the gadgets array by address
  qsort(collection->gadgets, collection->count, sizeof(gadget_t),
        compare_gadgets_by_address);

  return RESULT_SUCCESS;
}
