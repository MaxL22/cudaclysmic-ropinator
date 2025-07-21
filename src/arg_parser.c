#include "../include/arg_parser.h"
#include "../include/common.h"
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>

// Checks if CUDA is available on the system
bool is_cuda_available() {
#if CUDA_COMPILED
  int deviceCount = 0;
  cudaError_t error = cudaGetDeviceCount(&deviceCount);
  return (error == cudaSuccess && deviceCount > 0);
#else
  return false;
#endif
}

const char *arch_to_string(architecture_t arch) {
  switch (arch) {
  case ARCH_UNKNOWN:
    return "unknown";
  case ARCH_X86:
    return "x86";
  case ARCH_X86_64:
    return "x86_64";
  case ARCH_ARM:
    return "arm";
  case ARCH_ARM64:
    return "arm64";
  default:
    return "invalid";
  }
}

/* Print usage information */
void print_usage(const char *program_name) {
  printf("Usage: %s [OPTIONS] <binary_file>\n", program_name);
  printf("\nDescription: A CUDA-accelerated tool to turn binaries "
         "into open books and give your CPU an existential crysis, ending "
         "gadgets once and for all (preferably with a jmp).\n");
  printf("\nOptions:\n");
  printf("  -h, --help              Show this help message\n");
  printf("  -v, --verbose           Enable verbose output\n");
  printf("  -o, --output FILE       Output results to file\n");
  printf("  -l, --length LENGTH     Maximum gadget length (default: %d)\n",
         MAX_GADGET_LENGTH);
  printf("  -a, --arch ARCH         Force architecture (x86, x86_64, arm, "
         "arm64)\n");
  printf("  -c, --cuda-disable      Force disable CUDA acceleration\n");
  printf("\nExamples:\n");
  printf("  %s ./test_binary\n", program_name);
  printf("  %s -v -l 15 ./test_binary\n", program_name);
  printf("  %s -o gadgets.txt ./test_binary\n", program_name);
}

/* Parse architecture string */
architecture_t parse_architecture(const char *arch_str) {
  if (!arch_str)
    return ARCH_UNKNOWN;

  if (strcasecmp(arch_str, "x86") == 0) {
    return ARCH_X86;
  } else if (strcasecmp(arch_str, "x86_64") == 0 ||
             strcasecmp(arch_str, "x64") == 0) {
    return ARCH_X86_64;
  } else if (strcasecmp(arch_str, "arm") == 0) {
    return ARCH_ARM;
  } else if (strcasecmp(arch_str, "arm64") == 0 ||
             strcasecmp(arch_str, "aarch64") == 0) {
    return ARCH_ARM64;
  }

  return ARCH_UNKNOWN;
}

/* Parse command line arguments */
result_t parse_arguments(int argc, char *argv[], config_t *config) {
  // Changes options to their long form
  static struct option long_options[] = {
      {"help", no_argument, 0, 'h'},
      {"verbose", no_argument, 0, 'v'},
      {"output", required_argument, 0, 'o'},
      {"length", required_argument, 0, 'l'},
      {"arch", required_argument, 0, 'a'},
      {"cuda-disable", required_argument, 0, 'c'},
      {0, 0, 0, 0}};

  // Initialize config with defaults
  memset(config, 0, sizeof(config_t));
  config->max_gadget_length = MAX_GADGET_LENGTH;
  config->verbose = false;
  config->arch = ARCH_UNKNOWN;
  config->use_cuda = is_cuda_available();

  int option_index = 0;
  int option;

  // Iterates over the options
  while ((option = getopt_long(argc, argv, "hvo:l:a:c:", long_options,
                               &option_index)) != -1) {
    switch (option) {
    // --help used, print help
    case 'h':
      print_usage(argv[0]);
      exit(0);
      break;
    // Verbose mode
    case 'v':
      config->verbose = true;
      break;
    // Prints output to file
    case 'o':
      config->output_file = strdup(optarg);
      CHECK_NULL(config->output_file,
                 "Error: Failed to allocate memory for output file\n");
      break;
    // Sets gadget length instead of default
    case 'l':
      config->max_gadget_length = atoi(optarg);
      if (config->max_gadget_length <= 0 || config->max_gadget_length > 50) {
        fprintf(stderr, "Error: Invalid gadget length %d (must be 1-50)\n",
                config->max_gadget_length);
        return RESULT_ERROR_MEMORY;
      }
      break;
    // Set architecture
    case 'a':
      config->arch = parse_architecture(optarg);
      if (config->arch == ARCH_UNKNOWN) {
        fprintf(stderr, "Error: Unknown architecture '%s'\n", optarg);
        return RESULT_ERROR_ARCH;
      }
      break;
    // to CUDA or not to CUDA, that is the question
    case 'c':
      config->use_cuda = false;
      break;
    // I don't remember why this is here
    case '?':
      return RESULT_ERROR_MEMORY;

    default:
      fprintf(stderr, "Error: parameter parsing gone wrong\n");
      return RESULT_ERROR_PARAM;
    }
  }

  // Check for input file
  if (optind >= argc) {
    fprintf(stderr, "Error: No input file specified\n");
    print_usage(argv[0]);
    return RESULT_ERROR_FILE;
  }
  config->input_file = strdup(argv[optind]);
  CHECK_NULL(config->input_file,
             "Error: Failed to allocate memory for input file\n");

  return RESULT_SUCCESS;
}

/* Cleanup configuration */
void cleanup_config(config_t *config) {
  if (!config)
    return;

  SAFE_FREE(config->input_file);
  SAFE_FREE(config->output_file);
  memset(config, 0, sizeof(config_t));
}

void print_config(config_t *config) {
  printf("Configuration:\n");
  printf("  Input file: %s\n", config->input_file);
  printf("  Output file: %s\n",
         config->output_file ? config->output_file : "(stdout)");
  printf("  Max gadget length: %d\n", config->max_gadget_length);
  printf("  Force architecture: %s\n", arch_to_string(config->arch));
  printf("  Verbose: %s\n", config->verbose ? "Yes" : "No");
  printf("  CUDA Enabled: %s\n", config->use_cuda ? "Yes" : "No");
  printf("\n");
}
