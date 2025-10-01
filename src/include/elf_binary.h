#ifndef __BINARY__
#define __BINARY__

#include "elf_core.h"
#include <capstone/capstone.h>

typedef struct individual_binary_info_struct{
	char bin_name[FILE_NAME_SIZE];
	int parsed;
	size_t phdr_num;
	// GElf_Phdr *phdr;
	Elf32_Addr base_address;
	Elf32_Addr end_address; 
}individual_binary_info; 

// typedef struct elf_binary_info_struct{
// 	uint32_t start_address;
// 	cs_insn* instlist;
// 	uint32_t* lookuptable;
// }elf_binary_info;	

// Updated structure to include binary count and end address
typedef struct elf_binary_info_struct{
    char* binary_path;           // Path to the binary file
    uint32_t start_address;      // Start address in memory
    uint32_t end_address;        // End address in memory (for range checking)
    uint32_t inst_count;         // Number of instructions
    cs_insn* instlist;           // Instruction list
    uint32_t* lookuptable;       // Lookup table for fast address->instruction mapping
}elf_binary_info;

// Container for multiple binaries
typedef struct binary_collection_struct{
    elf_binary_info* binaries;   // Array of binary info structures
    size_t count;                 // Number of binaries loaded
    size_t capacity;              // Allocated capacity
}binary_collection;

// Structure to hold binary configuration from YAML
typedef struct binary_config_struct {
    char* binary_path;      // Relative path from sysroot
    uint32_t start_address; // Start address where binary is loaded
    uint32_t end_address;   // End address of binary mapping
} binary_config;

// Structure to hold all configurations parsed from YAML
typedef struct config_data_struct {
    binary_config* binaries;
    size_t count;
} config_data;

elf_binary_info *parse_binary(const char* filename, uint32_t start_address);

binary_collection* parse_binaries_from_sysroot(const char* sysroot_path, const char* config_path) {

int destroy_bin_info(elf_binary_info *bin_info);

int destroy_bin_collection_info(binary_collection* bin_collection);

cs_insn *lookup_instruction(binary_collection* collection, uint32_t address);

#endif
