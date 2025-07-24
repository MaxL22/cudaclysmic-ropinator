#include "../include/arg_parser.h"
#include "../include/binary_parser.h"
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Flow:
 *  Parse binary: this calls, in order:
 *    detect_format()       -> gets the file format (ELF only is supported)
 *    parse_elf()           -> takes all the pretty ELF thingies inside the
 *      binary calls the 32 or 64 bit version
 *      parse_elf_sections()
 * Then the binary_info_t sections array should be populated
 */

/* Main binary parsing function */
result_t parse_binary(const char *filename, binary_info_t *info) {
  // Validate
  if (!filename || !info) {
    return RESULT_ERROR_GENERIC;
  }
  // Initialize binary info structure
  memset(info, 0, sizeof(binary_info_t));

  // Store filename
  info->filename = malloc(strlen(filename) + 1);
  CHECK_NULL(info->filename, "Failed to allocate memory for filename");
  strcpy(info->filename, filename);

  // Open file
  info->file = fopen(filename, "rb");
  if (!info->file) {
    fprintf(stderr, "Error: Cannot open file '%s': %s\n", filename,
            strerror(errno));
    SAFE_FREE(info->filename);
    return RESULT_ERROR_FILE;
  }

  // Get file size
  struct stat st;
  if (fstat(fileno(info->file), &st) != 0) {
    fprintf(stderr, "Error: Cannot get file size: %s\n", strerror(errno));
    fclose(info->file);
    SAFE_FREE(info->filename);
    return RESULT_ERROR_FILE;
  }
  info->file_size = st.st_size;

  // Detect binary format
  result_t result = detect_format(info->file, &info->format);
  if (result != RESULT_SUCCESS) {
    fprintf(stderr, "Error: can't detect binary format");
    cleanup_binary_info(info);
    return result;
  }

  // Parse based on format
  switch (info->format) {
  case FORMAT_ELF:
    result = parse_elf(info);
    break;
  case FORMAT_PE:
    fprintf(stderr, "Error: PE format supported\n");
    result = RESULT_ERROR_FORMAT;
    break;
  case FORMAT_MACH_O:
    fprintf(stderr, "Error: Mach-O format supported\n");
    result = RESULT_ERROR_FORMAT;
    break;
  default:
    fprintf(stderr, "Error: Unknown or unsupported binary format\n");
    result = RESULT_ERROR_FORMAT;
    break;
  }
  if (result != RESULT_SUCCESS) {
    cleanup_binary_info(info);
  }

  // Detect architecture
  result = detect_architecture(info);
  if (result != RESULT_SUCCESS) {
    cleanup_binary_info(info);
    return result;
  }

  return result;
}

/* Detect binary format by examining file header, reads magic number */
result_t detect_format(FILE *file, binary_format_t *format) {
  // Archtecture is supposed to be detected and set during parsing
  if (!file || !format) {
    return RESULT_ERROR_GENERIC;
  }
  // Looks for the magic number to determine the file type
  uint32_t magic;
  *format = FORMAT_UNKNOWN;
  // Reads magic number
  if (fseek(file, 0, SEEK_SET) != 0 ||
      fread(&magic, sizeof(magic), 1, file) != 1) {
    fprintf(stderr, "Error: Cannot read file magic number\n");
    return RESULT_ERROR_FILE;
  }
  // Check for ELF magic
  if (magic == ELF_MAGIC) {
    *format = FORMAT_ELF;
  }
  // Check for PE magic (MZ header)
  if ((magic & 0xFFFF) == MZ_HEADER) {
    *format = FORMAT_PE;
  }
  // Check for Mach-O magic
  if (magic == MACH_1 || magic == MACH_2 || magic == MACH_3 ||
      magic == MACH_4) {
    *format = FORMAT_MACH_O;
  }
  // Return result
  return *format != FORMAT_UNKNOWN ? RESULT_SUCCESS : RESULT_ERROR_FORMAT;
}

/* Parse ELF binary */
result_t parse_elf(binary_info_t *info) {
  // Check
  if (!info || !info->file) {
    return RESULT_ERROR_GENERIC;
  }
  // Go to start of file
  if (fseek(info->file, 0, SEEK_SET) != 0) {
    return RESULT_ERROR_FILE;
  }
  // Reads identifier
  unsigned char e_ident[EI_NIDENT];
  if (fread(e_ident, sizeof(e_ident), 1, info->file) != 1) {
    fprintf(stderr, "Error: Cannot read ELF identification\n");
    return RESULT_ERROR_FILE;
  }
  // Check ELF class (32/64-bit)
  if (e_ident[EI_CLASS] == ELFCLASS32) {
    return parse_elf32(info);
  } else if (e_ident[EI_CLASS] == ELFCLASS64) {
    return parse_elf64(info);
  } else {
    fprintf(stderr, "Error: Invalid ELF class\n");
    return RESULT_ERROR_FORMAT;
  }
}

/* Parse 32-bit ELF */
result_t parse_elf32(binary_info_t *info) {
  // ELF Header, should coincide with start of file
  Elf32_Ehdr ehdr;
  if (fseek(info->file, 0, SEEK_SET) != 0) {
    return RESULT_ERROR_FILE;
  }
  if (fread(&ehdr, sizeof(ehdr), 1, info->file) != 1) {
    fprintf(stderr, "Error: Cannot read ELF32 header\n");
    return RESULT_ERROR_FILE;
  }

  // Set basic info
  info->entry_point = ehdr.e_entry;
  info->base_address = 0; // To be updated when parsing program headers

  // Parse sections
  info->section_count = ehdr.e_shnum; // Number of sections
  if (info->section_count > MAX_SECTIONS) {
    fprintf(stderr, "Error: Too many sections (%zu > %d)\n",
            info->section_count, MAX_SECTIONS);
    return RESULT_ERROR_FORMAT;
  }
  if (info->section_count < 1) {
    fprintf(stderr, "Error during section parsing (%zu sections)\n",
            info->section_count);
    return RESULT_ERROR_FORMAT;
  }

  // Alloc space for sections
  info->sections = calloc(info->section_count, sizeof(binary_section_t));
  CHECK_NULL(info->sections, "Failed to allocate memory for sections");

  // Place *file on section headers start
  if (fseek(info->file, ehdr.e_shoff, SEEK_SET) != 0) {
    return RESULT_ERROR_FILE;
  }

  // Alloc for section headers
  Elf32_Shdr *shdrs = calloc(info->section_count, sizeof(Elf32_Shdr));
  CHECK_NULL(shdrs, "Failed to allocate memory for section headers");

  // Reads the section headers
  if (fread(shdrs, sizeof(Elf32_Shdr), info->section_count, info->file) !=
      info->section_count) {
    fprintf(stderr, "Error: Cannot read section headers\n");
    free(shdrs);
    return RESULT_ERROR_FILE;
  }

  // Read section header string table
  char *shstrtab = NULL;
  if (ehdr.e_shstrndx == SHN_UNDEF || ehdr.e_shstrndx >= info->section_count) {
    fprintf(stderr, "Error: cannot read section header string table (%u)",
            ehdr.e_shstrndx);
    return RESULT_ERROR_FILE;
  }

  // Section header struct, from section headers
  //    take the section header string table
  Elf32_Shdr *shstr_hdr = (shdrs + ehdr.e_shstrndx);
  shstrtab = malloc(shstr_hdr->sh_size);
  CHECK_NULL(shstrtab, "section header string table allocation failed");

  // Go to start of section
  if (fseek(info->file, shstr_hdr->sh_offset, SEEK_SET) != 0) {
    fprintf(stderr, "Error: while reading section header");
    return RESULT_ERROR_FILE;
  }
  // Read the sh string table
  fread(shstrtab, 1, shstr_hdr->sh_size, info->file);

  // Process sections
  for (size_t i = 0; i < info->section_count; i++) {
    // We're writing section i of our info struct
    binary_section_t *section = &info->sections[i];
    // Section from the file
    Elf32_Shdr *shdr = &shdrs[i];

    // Copy section name
    // shdr->sh_name is the offset in the shstrtab
    //     so we're just checking that we're in bound
    if (shstrtab && shdr->sh_name < shdrs[ehdr.e_shstrndx].sh_size) {
      // Copy the section name, from the offset in the shstrtab
      strncpy(section->name, (shstrtab + shdr->sh_name),
              sizeof(section->name) - 1);
      section->name[sizeof(section->name) - 1] = '\0'; // End line
    } else { // If something is wrong use a default name, and say smth
      snprintf(section->name, sizeof(section->name), "section_%zu", i);
      fprintf(stderr,
              "WARNING: name not read from string table for section_%zu", i);
    }

    section->virtual_addr = shdr->sh_addr;  // Where section loads in memory
    section->file_offset = shdr->sh_offset; // Section offset in file
    section->size = shdr->sh_size;          // Section size
    // Is the section executable and readable, respectively?
    section->executable = (shdr->sh_flags & SHF_EXECINSTR) != 0;
    section->readable = (shdr->sh_flags & SHF_ALLOC) != 0;
  }

  // All parsed, free shstrtab and space for the section headers
  SAFE_FREE(shstrtab);
  SAFE_FREE(shdrs);

  return parse_elf_sections(info);
}

/* Parse 64-bit ELF */
result_t parse_elf64(binary_info_t *info) {
  Elf64_Ehdr ehdr;

  // Goto start of file
  if (fseek(info->file, 0, SEEK_SET) != 0) {
    return RESULT_ERROR_FILE;
  }
  // Read ELF header
  if (fread(&ehdr, sizeof(ehdr), 1, info->file) != 1) {
    fprintf(stderr, "Error: Cannot read ELF64 header\n");
    return RESULT_ERROR_FILE;
  }
  // Set basic info
  info->entry_point = ehdr.e_entry;
  info->base_address = 0; // Will be updated when parsing program headers

  // Parse sections
  info->section_count = ehdr.e_shnum;
  if (info->section_count > MAX_SECTIONS) {
    fprintf(stderr, "Error: Too many sections (%zu > %d)\n",
            info->section_count, MAX_SECTIONS);
    return RESULT_ERROR_FORMAT;
  }

  if (info->section_count < 1) {
    fprintf(stderr, "Error during section parsing (%zu sections)\n",
            info->section_count);
    return RESULT_ERROR_FORMAT;
  }
  // Alloc memory for sections
  info->sections = calloc(info->section_count, sizeof(binary_section_t));
  CHECK_NULL(info->sections, "Failed to allocate memory for sections");

  // Goto section headers
  if (fseek(info->file, ehdr.e_shoff, SEEK_SET) != 0) {
    return RESULT_ERROR_FILE;
  }
  // Alloc section headers
  Elf64_Shdr *shdrs = calloc(info->section_count, sizeof(Elf64_Shdr));
  CHECK_NULL(shdrs, "Failed to allocate memory for section headers");
  // Read sections
  if (fread(shdrs, sizeof(Elf64_Shdr), info->section_count, info->file) !=
      info->section_count) {
    fprintf(stderr, "Error: Cannot read section headers\n");
    free(shdrs);
    return RESULT_ERROR_FILE;
  }

  // Read section header string table
  char *shstrtab = NULL;
  if (ehdr.e_shstrndx == SHN_UNDEF || ehdr.e_shstrndx >= info->section_count) {
    fprintf(stderr, "Error: cannot read section header string table (%u)",
            ehdr.e_shstrndx);
    return RESULT_ERROR_FILE;
  }
  // Actually read the shstrtab
  Elf64_Shdr *shstr_hdr = (shdrs + ehdr.e_shstrndx);
  shstrtab = malloc(shstr_hdr->sh_size);
  CHECK_NULL(shstrtab, "section header string table allocation failed");

  // Go to start of section
  if (fseek(info->file, shstr_hdr->sh_offset, SEEK_SET) != 0) {
    fprintf(stderr, "Error: while reading section header");
    return RESULT_ERROR_FILE;
  }
  // Read the sh string table
  fread(shstrtab, 1, shstr_hdr->sh_size, info->file);

  // Process sections
  for (size_t i = 0; i < info->section_count; i++) {
    // Take i-th section
    binary_section_t *section = &info->sections[i];
    Elf64_Shdr *shdr = &shdrs[i];

    // Copy section name
    if (shstrtab && shdr->sh_name < shdrs[ehdr.e_shstrndx].sh_size) {
      strncpy(section->name, &shstrtab[shdr->sh_name],
              sizeof(section->name) - 1);
      section->name[sizeof(section->name) - 1] = '\0';
    } else {
      snprintf(section->name, sizeof(section->name), "section_%zu", i);
      fprintf(stderr,
              "WARNING: name not read from string table for section_%zu", i);
    }
    // Copy data
    section->virtual_addr = shdr->sh_addr;  // Where program is loaded in memory
    section->file_offset = shdr->sh_offset; // Offset from file start
    section->size = shdr->sh_size;          // Section size
    // Check if the section is executable and readable
    section->executable = (shdr->sh_flags & SHF_EXECINSTR) != 0;
    section->readable = (shdr->sh_flags & SHF_ALLOC) != 0;
  }

  // Free resources
  SAFE_FREE(shstrtab);
  SAFE_FREE(shdrs);

  return parse_elf_sections(info);
}

/* Parse ELF sections and load data if needed */
result_t parse_elf_sections(binary_info_t *info) {
  if (!info || !info->sections) {
    return RESULT_ERROR_GENERIC;
  }

  for (size_t i = 0; i < info->section_count; i++) {
    binary_section_t *section = &info->sections[i];

    // Only load data for executable sections or sections with data
    //     This is used to skip empty sections (.bss, NULL)
    if (section->size > 0 && section->file_offset > 0) {
      section->data = malloc(section->size);
      if (!section->data) {
        fprintf(stderr, "Warning: Cannot allocate memory for section '%s'\n",
                section->name);
        continue;
      }
      // Goto start of section in file
      if (fseek(info->file, section->file_offset, SEEK_SET) != 0) {
        fprintf(stderr, "Warning: Cannot seek to section '%s' offset\n",
                section->name);
        SAFE_FREE(section->data);
        continue;
      }
      // Read the section data
      if (fread(section->data, 1, section->size, info->file) != section->size) {
        fprintf(stderr, "Warning: Cannot read section '%s' data\n",
                section->name);
        SAFE_FREE(section->data);
        continue;
      }
    }
  }

  return RESULT_SUCCESS;
}

/* Clean up binary info structure */
void cleanup_binary_info(binary_info_t *info) {
  if (!info) {
    return;
  }
  // Close file if open
  if (info->file) {
    fclose(info->file);
    info->file = NULL;
  }
  // Free filename
  SAFE_FREE(info->filename);
  // Free sections and their data
  if (info->sections) {
    for (size_t i = 0; i < info->section_count; i++) {
      SAFE_FREE(info->sections[i].data);
    }
    SAFE_FREE(info->sections);
  }
  // Reset counts
  info->section_count = 0;
  info->file_size = 0;
}

/* Check if section is executable */
bool is_section_executable(const binary_section_t *section) {
  return section ? section->executable : false;
}

/* Get section virtual address */
uint64_t get_section_virtual_address(const binary_section_t *section) {
  return section ? section->virtual_addr : 0;
}

/* Convert binary format to string */
const char *format_to_string(binary_format_t format) {
  switch (format) {
  case FORMAT_ELF:
    return "ELF";
  case FORMAT_PE:
    return "PE";
  case FORMAT_MACH_O:
    return "Mach-O";
  case FORMAT_UNKNOWN:
  default:
    return "Unknown";
  }
}

/* Print binary information */
void print_binary_info(const binary_info_t *info) {
  if (!info) {
    printf("Binary info: NULL\n");
    return;
  }

  printf("Binary Information:\n");
  printf("  Filename: %s\n", info->filename ? info->filename : "N/A");
  printf("  Format: %s\n", format_to_string(info->format));
  printf("  Architecture: %s\n", arch_to_string(info->arch));
  printf("  Entry Point: 0x%lx\n", info->entry_point);
  printf("  Base Address: 0x%lx\n", info->base_address);
  printf("  File Size: %zu bytes\n", info->file_size);
  printf("  Sections: %zu\n", info->section_count);

  if (info->sections && info->section_count > 0) {
    printf("\nSections:\n");
    for (size_t i = 0; i < info->section_count; i++) {
      const binary_section_t *section = &info->sections[i];
      printf("  [%2zu] %-20s VA: 0x%08lx Size: %8zu %s%s\n", i, section->name,
             section->virtual_addr, section->size,
             section->executable ? "X" : "-", section->readable ? "R" : "-");
    }
  }
}

/* Detect architecture from ELF */
result_t detect_architecture(binary_info_t *info) {
  unsigned char e_ident[EI_NIDENT];
  uint16_t e_machine;

  fseek(info->file, 0, SEEK_SET);
  if (fread(e_ident, EI_NIDENT, 1, info->file) != 1) {
    return RESULT_ERROR_FILE;
  }

  // Read machine type
  fseek(info->file, offsetof(Elf64_Ehdr, e_machine), SEEK_SET);
  if (fread(&e_machine, sizeof(e_machine), 1, info->file) != 1) {
    return RESULT_ERROR_FILE;
  }

  // Determine architecture
  switch (e_machine) {
  case EM_386:
    info->arch = ARCH_X86;
    break;
  case EM_X86_64:
    info->arch = ARCH_X86_64;
    break;
  case EM_ARM:
    info->arch = ARCH_ARM;
    break;
  case EM_AARCH64:
    info->arch = ARCH_ARM64;
    break;
  default:
    info->arch = ARCH_UNKNOWN;
    return RESULT_ERROR_ARCH;
  }

  return RESULT_SUCCESS;
}
