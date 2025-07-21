/* src/main.c - Main program entry point */
#include "../include/arg_parser.h"
#include "../include/binary_parser.h"
#include "../include/common.h" // This includes
// #include "../include/gadget_finder.h"
#include <stdio.h>
// Checks if CUDA is available
#ifdef __CUDACC__
#include <cuda_runtime.h>
#define CUDA_COMPILED 1
#else
#define CUDA_COMPILED 0
#endif

/* Main function */
int main(int argc, char *argv[]) {
  // Initial config, parameters
  config_t config;
  // Informations about the binary, name, size, sections
  binary_info_t binary_info;
  // Gadgets found
  gadget_collection_t gadgets;
  // Search parameters,
  // search_config_t search_config;
  // Ret value
  result_t result;

  // Parse command line arguments, populates the config
  result = parse_arguments(argc, argv, &config);
  if (result != RESULT_SUCCESS) {
    return RESULT_ERROR_GENERIC;
  }
  if (config.verbose) {
    print_config(&config);
  }
  // Parse binary
  result = parse_binary(config.input_file, &binary_info);
  if (result != RESULT_SUCCESS) {
    fprintf(stderr, "Failed to parse binary file\n");
    cleanup_config(&config);
    return 1;
  }
  // Override architecture, if forced
  if (config.arch != ARCH_UNKNOWN && config.arch != binary_info.arch) {
    fprintf(stderr, "WARNING: architecture mismatch, %s detected, %s forced \n",
            arch_to_string(binary_info.arch), arch_to_string(config.arch));
    binary_info.arch = config.arch;
  }

  // Print binary information
  if (config.verbose) {
    printf("\n");
    print_binary_info(&binary_info);
    printf("\n");
  }

  /*
  // Initialize gadget collection
  result = init_gadget_collection(&gadgets);
  if (result != RESULT_SUCCESS) {
    fprintf(stderr, "Failed to initialize gadget collection\n");
    cleanup_binary_info(&binary_info);
    cleanup_config(&config);
    return 1;
  }

  // Setup search configuration
  search_config.max_gadget_length = config.max_gadget_length;
  search_config.find_rop_gadgets = true;
  search_config.find_syscall_gadgets = true;
  search_config.target_arch = binary_info.arch;

  // Find gadgets
  if (config.verbose) {
    printf("Searching for gadgets...\n");
  }

  if (config.use_cuda) {
#ifdef CUDA_ENABLED
    result = find_gadgets_cuda(&binary_info, &search_config, &gadgets);
#else
    fprintf(stderr,
            "Warning: CUDA support not compiled in, using CPU version\n");
    result = find_gadgets(&binary_info, &search_config, &gadgets);
#endif
  } else {
    result = find_gadgets(&binary_info, &search_config, &gadgets);
  }

  if (result != RESULT_SUCCESS) {
    fprintf(stderr, "Failed to find gadgets\n");
    cleanup_gadget_collection(&gadgets);
    cleanup_binary_info(&binary_info);
    cleanup_config(&config);
    return 1;
  }

  // Sort gadgets by address
  if (config.verbose) {
    printf("Sorting gadgets...\n");
  }
  sort_gadgets(&gadgets);

  // Output results
  if (config.verbose) {
    printf("\nFound %zu gadgets:\n", gadgets.count);
    printf("===================\n");
  }

  FILE *output = stdout;
  if (config.output_file) {
    output = fopen(config.output_file, "w");
    if (!output) {
      fprintf(stderr, "Error: Cannot open output file %s\n",
              config.output_file);
      output = stdout;
    }
  }

  // Print gadgets
  for (size_t i = 0; i < gadgets.count; i++) {
    const gadget_t *gadget = &gadgets.gadgets[i];
    fprintf(output, "0x%08lx: %s\n", gadget->address, gadget->disasm);
  }

  if (output != stdout) {
    fclose(output);
    printf("Results written to: %s\n", config.output_file);
  }

  printf("\nSummary:\n");
  printf("  Total gadgets found: %zu\n", gadgets.count);
  printf("  Binary format: %s\n", format_to_string(binary_info.format));
  printf("  Architecture: %s\n", arch_to_string(binary_info.arch));
  */

  // Cleanup
  // cleanup_gadget_collection(&gadgets);
  cleanup_binary_info(&binary_info);
  cleanup_config(&config);

  return 0;
}
