#ifndef ARG_PARSER_H
#define ARG_PARSER_H

#include "../include/common.h"
#include <getopt.h>

architecture_t parse_architecture(const char *arch_str); 
result_t parse_arguments(int argc, char *argv[], config_t *config);
void print_config(config_t *config);
void print_usage(const char *program_name);
const char *arch_to_string(architecture_t arch);
void cleanup_config(config_t *config);
bool is_cuda_available();

#endif
