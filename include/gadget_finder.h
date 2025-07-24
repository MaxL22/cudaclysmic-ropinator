/* include/gadget_finder.h - Gadget finding interface */
#ifndef GADGET_FINDER_H
#define GADGET_FINDER_H

#include "common.h"

#define X86_64_RET_OPCODE 0xC3

/* Function prototypes */
result_t find_gadgets(const binary_info_t *binary,
                      const search_config_t *config,
                      gadget_collection_t *collection);
result_t find_in_section_x86_64(const binary_section_t *section,
                                 const search_config_t *config,
                                 gadget_collection_t *collection);
result_t analyze_sequence(const uint8_t *data, size_t length,
                                      uint64_t base_addr, architecture_t arch,
                                      gadget_t *gadget);

/* Gadget collection management */
result_t init_gadget_collection(gadget_collection_t *collection);
result_t add_gadget(gadget_collection_t *collection, gadget_t *gadget);
result_t cleanup_gadget_collection(gadget_collection_t *collection);
result_t sort_gadgets(gadget_collection_t *collection);
result_t filter_gadgets(gadget_collection_t *collection, gadget_type_t type);
void free_gadget(gadget_t *gadget);
result_t setup_search_configuration(search_config_t *config,
                                    const config_t *params,
                                    const binary_info_t *binary_info);

/* Gadget analysis */
bool is_valid_gadget(const gadget_t *gadget);
bool is_ret_instruction(const uint8_t *bytes, size_t offset);
gadget_type_t classify_x86_64_gadget(gadget_t *gadget);
int compare_gadgets_by_address(const void *a, const void *b);

/* Capstone stuff */
result_t init_capstone();
void cleanup_capstone();
char *create_disassembly(const uint8_t *bytes, size_t length,
                                uint64_t address);

/* CUDA interface (if available) */
#ifdef CUDA_COMPILED
result_t find_gadgets_cuda(const binary_info_t *binary,
                           const search_config_t *config,
                           gadget_collection_t *collection);
#endif

#endif /* GADGET_FINDER_H */
