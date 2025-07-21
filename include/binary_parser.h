/* include/binary_parser.h - Binary parsing interface */
#ifndef BINARY_PARSER_H
#define BINARY_PARSER_H

#include "common.h"
#include <elf.h>

/* ELF helper macros */
#define ELF_MAGIC 0x464C457F
#define MZ_HEADER 0x5A4D
#define MACH_1 0xFEEDFACE
#define MACH_2 0xFEEDFACF
#define MACH_3 0xCEFAEDFE
#define MACH_4 0xCFFAEDFE

/* Function prototypes */
result_t parse_binary(const char *filename, binary_info_t *info);
result_t detect_format(FILE *file, binary_format_t *format);
result_t parse_elf(binary_info_t *info);
result_t parse_elf_sections(binary_info_t *info);
result_t load_section_data(binary_info_t *info);
void cleanup_binary_info(binary_info_t *info);

/* ELF parsing helpers */
result_t parse_elf32(binary_info_t *info);
result_t parse_elf64(binary_info_t *info);
bool is_section_executable(const binary_section_t *section);
uint64_t get_section_virtual_address(const binary_section_t *section);

/* Utility functions */
const char *format_to_string(binary_format_t format);
void print_binary_info(const binary_info_t *info);

#endif /* BINARY_PARSER_H */
