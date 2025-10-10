#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include "access_memory.h"
#include "elf_core.h"
#include "elf_binary.h"
#include "insthandler_arm.h"
#include "disassemble.h"
#include "thread_selection.h"
#include "inst_data.h"

#ifdef MEMAC
#include "bintrace.capnp.h"
#endif

#include "arm_define.h"
#include "reverse_log.h"
#include "global.h"

#define PATH_MAX 512
#ifdef VSA
#define REGINFODEM ":"
#define LOG_MAX_SIZE 256
#define REGDEM ";"
#define INFODEM ":"
static void process_log_line(char* line, operand_val_t * oplog){

	char *str1, *str2, *saveptr1, *saveptr2; 
	char *token, *regid, *regval;
	char *endptr;  
	int regcount; 

	int vallen; 
	int i, j;
	
	for(regcount = 0, str1 = line; ;regcount++, str1 = NULL){
		token = strtok_r(str1, REGDEM, &saveptr1);
		if(token == NULL)
			break; 	
			
		regid = strtok_r(token, INFODEM, &saveptr2);
		assert(regid != NULL);
		regval = strtok_r(NULL, INFODEM, &saveptr2);
		assert(regval != NULL);

		//process the id and the value 
		oplog->regs[regcount].reg_num = strtol(regid, &endptr, 10);

		//conver the string to value
		//as the length of the string is varying, 
		//we use iterations instead of strtol 
		
		if(regval[strlen(regval)-1] == '\n')
			regval[strlen(regval)-1] = 0;
		
		for(i = strlen(regval) - 2, j = 0; i >=2; i -= 2, j++){
			char temp[5];
			temp[0] = '0';
			temp[1] = 'x';
			temp[4] = '\0';
			memcpy(&temp[2], &regval[i], 2);
			((char*)&oplog->regs[regcount].val)[j] = (char)strtol(temp, &endptr, 16);
		}
	}
	oplog->regnum = regcount;
}
static void load_line_dlregion(char *line, dlregion_list_t *dlregion) {

        int opcount;
        char *str, *saveptr, *token, *endptr;

        for (opcount = 0, str = line; ;opcount++, str = NULL) {
                token = strtok_r(str, REGINFODEM, &saveptr);
                if (token == NULL) break;
                //printf("%d: %s ", opcount, token);
                dlregion->dlreg_list[opcount] = (unsigned long)strtoll(token, &endptr, 10);
        }

	assert(opcount <= 2);
        dlregion->dlreg_num = opcount;
}

// load region_DL file into dlregionlist data structure
int load_dlregion(char *dlregion_file, dlregion_list_t *dlregionlist){
        char line[LINE_SIZE];
        FILE *file;
        char *start, *end, *saveptr, *token;
        int i;
        if ((file = fopen(dlregion_file, "r")) == NULL){
                LOG(stderr, "ERROR: dlregion file open error\n");
                return -1;
        }

        i = 0;
        while (fgets(line, sizeof(line), file) != NULL) {
                load_line_dlregion(line, dlregionlist + i);
                i++;
        }

        return 0;
}
unsigned long count_linenum_ptlog(char *filename){
	char line[256];
	FILE *file;
	if ((file = fopen(filename, "r")) == NULL) {
		LOG(stderr, "ERROR: open error\n");
		return -1;
	}
	unsigned long linenum = 0;
	while (fgets(line, sizeof line, file) != NULL) {
		if ((strncmp(line, "[disabled]", 10) == 0)) continue;
		if ((strncmp(line, "[enabled]", 9) == 0)) continue;
		if ((strncmp(line, "[resumed]", 9) == 0)) continue;
		linenum++;
	}

	LOG(stdout, "RESULT: Valid Address Number - 0x%lx\n", linenum);
	return linenum;
}

unsigned long gcd(unsigned long a, unsigned long b) {
	int tmp;
	while(b != 0) {
		tmp = b;
		b = a % b;
		a = tmp;
	}
	return a;
}


//count the number of instructions that have valid data logging
unsigned long count_linenum(char * filename){
	char line[256];
	FILE *file;
	unsigned long linenum;

	if ((file = fopen(filename, "r")) == NULL) {
		LOG(stderr, "ERROR: cannot open file %s\n",filename);
		return -1;
	}

	linenum = 0;
	while(fgets(line, sizeof(line), file) != NULL){
		if (linenum >= get_max_rev_ins_num()){
			break;
		}
		linenum++;
	}

	LOG(stdout, "RESULT: Valid Address Number - 0x%lx\n", linenum);
	return linenum;
}
#endif
config_data* parse_config_file(const char* config_path);

unsigned long countvalidaddress(char *filename){
    char line[80];
    FILE *file;
    if ((file = fopen(filename, "r")) == NULL) {
        LOG(stderr, "ERROR: open error\n");
        return -1;
    }
    unsigned long linenum = 0;
    while (fgets(line, sizeof line, file) != NULL) {
        if (linenum >= get_max_rev_ins_num()){
            break;
        }
        if ((strncmp(line, "[disabled]", 10) == 0)) continue;
        if ((strncmp(line, "[enabled]", 9) == 0)) continue;
        if ((strncmp(line, "[resumed]", 9) == 0)) continue;
        linenum++;
    }

    LOG(stdout, "RESULT: Valid Address Number - 0x%ld\n", linenum);
    return linenum;
}


// Parse memory dump and registers
coredata_t * load_coredump(const char* core_path){

	coredata_t * coredata = NULL;	

    FILE* file = fopen(core_path, "r");
    if (file == NULL){
    	LOG(stderr, "Error When Open ELF core file: %s\n", strerror(errno));
    	return NULL;
    }

    coredata = (coredata_t*)malloc(sizeof(coredata_t));

    if (coredata == NULL){
    	LOG(stderr, "Error When Memory Allocation\n");
        fclose(file);
        return NULL;
    }	

    memset(coredata, 0, sizeof(coredata_t));
    LOG(stdout, "STATE: Parsing Core File: %s\n", core_path);

    uint32_t base_address = 0;
	uint32_t current_address = 0;
	uint32_t prev_address = 0;
    uint8_t *current_data = NULL;
    size_t current_size = 0;

    uint8_t byte_count, record_type;
    uint32_t offset;
    uint8_t byte;
	uint32_t linear_address;

    char line[512];
	const char* reg_names[] = {
		"zero","r0","r1","r2","r3","r4","r5","r6","r7",
		"r8","r9","r10","r11","r12","lr","pc","sp","cpsr","","",
        "d1","d2","d3","d4","d5","d6","d7","d8","d9","d10",
        "d11","d12","d13","d14","d15","d16","d17","d18","d19","d20",
        "d21","d22","d23","d24","d25","d26","d27","d28","d29","d30",
        "d31"

	};

    while (fgets(line, sizeof(line), file)) {
        if (line[0] == ':') {
            // Parse the hex record
            sscanf(line + 1, "%2hhx%4hx%2hhx", &byte_count, &offset, &record_type);
			offset &= 0xFFFF;
            // Data record
            if (record_type == 0) {
                // Calculate the data size
				current_address = base_address + offset;
				if (prev_address == 0 || (prev_address + byte_count < current_address)){
					// Not continuous memory
					current_size = 0;
					coredata->memsegnum++;
					coredata->coremem = (memseg_t*)realloc(coredata->coremem, coredata->memsegnum * sizeof(memseg_t));
					coredata->coremem[coredata->memsegnum - 1].low = current_address;
                    current_data = NULL;
				}
				prev_address = current_address;
                if (current_data) {
                    current_data = (uint8_t *)realloc(current_data, current_size + byte_count);
                } else {
                    current_data = (uint8_t *)malloc(byte_count);
                }
                for (size_t i = 0; i < byte_count; i++) {
                    sscanf(line + 9 + i * 2, "%2hhx", &byte);
                    current_data[current_size + i] = byte;
                }
                current_size += byte_count;
				coredata->coremem[coredata->memsegnum - 1].data = current_data;
				coredata->coremem[coredata->memsegnum - 1].high = coredata->coremem[coredata->memsegnum - 1].low + current_size ;
            }
            // End of file record
            else if (record_type == 1) {
                // ....
            }
            // Extended segment address record
            else if (record_type == 2) {
                // ...
                LOG(stderr, "Record type %d is not supported.\n", record_type);
            }
            // Start segment address record
            else if (record_type == 3) {
                // ...
                LOG(stderr, "Record type %d is not supported.\n", record_type);
            }
            // Extended linear address record
            else if (record_type == 4) {
                // Extract 32-bit linear address from data
                sscanf(line + 9, "%4hx", &linear_address);
                base_address = linear_address << 16;
            }
            // Start linear address record
            else if (record_type == 5) {
                // ...
                LOG(stderr, "Record type %d is not supported.\n", record_type);
            }
        }
		else {
			for (int i = 0; i < 51; i++) {
                // not assigned any register
                if(i==18 || i==19){
                    continue;
                }
				if (strncmp(line, reg_names[i], strlen(reg_names[i])) == 0) {
					sscanf(line + strlen(reg_names[i]) + 1, "%lx", &coredata->corereg.regs[i]);
					break;
				}
			}
		}
	}
    fclose(file);

	return coredata;
}

void parse_binaries_for_thumb_insts(binary_insts_is_thumb **binary_insts_is_thumb_arr, size_t *binary_insts_is_thumb_arr_len, const char* config_path, const char* sysroot_path, char *trace_file){
    LOG(stdout, "DEBUG: Parsing binaries for thumb insts\n");
    
    unsigned long max_num_inst;
    binary_insts_is_thumb *binary_insts_is_thumb_arr_tmp;

    FILE *file;
    struct capn ctx;
    TraceEvent_ptr pevent;
    struct TraceEvent event;
    struct Instruction instruction;

    size_t i, inst_binary_idx;
    uint32_t inst_offset;

    config_data* config = parse_config_file(config_path);
    
    binary_insts_is_thumb_arr_tmp = (binary_insts_is_thumb*)malloc(config->count * sizeof(binary_insts_is_thumb));
    *binary_insts_is_thumb_arr_len = config->count;
    if (!binary_insts_is_thumb_arr_tmp){
        LOG(stderr, "ERROR: Failed to allocate memory for binary_insts_is_thumb_arr_tmp\n");
        return;
    }

    for(i=0; i<*binary_insts_is_thumb_arr_len; i++){
        // instructions are even aligned, so maximum number of possible instructions is divided by 2
        max_num_inst = (config->binaries[i].end_address - config->binaries[i].start_address) >> 1;

        binary_insts_is_thumb_arr_tmp[i].arr_len = max_num_inst;

        // allocate array of max possible num of inst, value at each offset indicates if instruction is thumb or not
        binary_insts_is_thumb_arr_tmp[i].is_thumb_arr = (uint8_t *)malloc(max_num_inst * sizeof(uint8_t));
        if(!binary_insts_is_thumb_arr_tmp[i].is_thumb_arr){
            LOG(stderr, "ERROR: Failed to allocate memory for binary_insts_is_thumb_arr_tmp[i].is_thumb_arr\n");
            free(binary_insts_is_thumb_arr_tmp);
            return;
        }
        // LOG(stdout, "DEBUG: Allocated memory for binary_insts_is_thumb_arr_tmp[%u].is_thumb_arr\n", i);
        // pre-initialise values to 0xFF, if value remains as 0xFF means instruction at that address is not used
        memset(binary_insts_is_thumb_arr_tmp[i].is_thumb_arr, 0xFF, max_num_inst * sizeof(uint8_t));
        binary_insts_is_thumb_arr_tmp[i].binary_start_address = config->binaries[i].start_address;
    }
    
    // parse memac.bin file
    // count the number of executed instructions
    if ((file = fopen(trace_file, "rb" )) == NULL){
        LOG(stderr, "ERROR: trace file open error\n");
        return -1;
    }

    while (0==capn_init_fp(&ctx, file, 0)) {

        pevent.p = capn_getp(capn_root(&ctx), 0, 0);
        read_TraceEvent(&event, pevent);

        if(event.which == TraceEvent_instruction){
            read_Instruction(&instruction, event.instruction);

            // find corresponding array to write is thumb value
            for(i=0; i<*binary_insts_is_thumb_arr_len; i++){
                // compare instruction pc with start and end addresses
                // LOG(stdout, "Start address for %d is %#x, end address is %#x\n", i, config->binaries[i].start_address, config->binaries[i].end_address);
                // inst in binary addr range
                if((instruction.pc >= config->binaries[i].start_address) && (instruction.pc < config->binaries[i].end_address)){
                    inst_binary_idx = i;
                    break;
                }
            }

            inst_offset = (instruction.pc - config->binaries[inst_binary_idx].start_address) >> 1;
            // if(instruction.pc == 0x40816b54){
            //     LOG(stdout, "DEBUG: Instruction %#x has offset %#x with start address %#x and bin idx of %d\n", instruction.pc, inst_offset, config->binaries[inst_binary_idx].start_address, inst_binary_idx);
            // }
            // write is thumb value: 1 for Thumb, 0 for non thumb
            binary_insts_is_thumb_arr_tmp[inst_binary_idx].is_thumb_arr[inst_offset] = instruction.isThumb;
        }
    }

    *binary_insts_is_thumb_arr = binary_insts_is_thumb_arr_tmp;

	fclose(file);

}

#ifdef MEMAC
int load_trace_mem(binary_collection * bin_collection, char *trace_file, size_t* instnum, cs_insn** instlist, struct Access** accesslist){

    size_t tmpinst, tmpac;
    FILE *file;
    uint32_t address;
    cs_insn *instlist_tmp;
    struct Access *accesslist_tmp;

    struct capn ctx;
    TraceEvent_ptr pevent;
    struct TraceEvent event;
    struct Instruction instruction;

    // count the number of executed instructions
    if ((file = fopen(trace_file, "rb" )) == NULL){
        LOG(stderr, "ERROR: trace file open error\n");
        return -1;
    }

    tmpinst = 0; 	
    tmpac = 0;

    fseek(file, 0, SEEK_SET);

    while (0==capn_init_fp(&ctx, file, 0)) {
        pevent.p = capn_getp(capn_root(&ctx), 0, 0);
        read_TraceEvent(&event, pevent);
        switch (event.which)
        {
        case TraceEvent_instruction:
            tmpinst++;
            break;
        case TraceEvent_access:
            tmpac++;
            break;
        }
    }

    *instnum = tmpinst;

    // fill instlist
    instlist_tmp = (cs_insn*)malloc(tmpinst * sizeof(cs_insn));

    // use NULL as padding
    accesslist_tmp = (struct Access*)malloc((tmpac+tmpinst) * sizeof(struct Access)); 
    
    if (!instlist_tmp || !accesslist_tmp){
        LOG(stderr, "ERROR: instlist/accesslist malloc error\n");
        return false;
    }
    memset(accesslist_tmp, 0, (tmpac+tmpinst) * sizeof(struct Access));
    memset(instlist_tmp, 0, tmpinst * sizeof(cs_insn));

    // int ttt = tmpac + tmpinst;

    // reset file pointer and fill the list
    fseek(file, 0, SEEK_SET);

    while (0==capn_init_fp(&ctx, file, 0)) {

        pevent.p = capn_getp(capn_root(&ctx), 0, 0);
        read_TraceEvent(&event, pevent);

        switch (event.which)
        {
            case TraceEvent_instruction:
                tmpinst--;
                read_Instruction(&instruction, event.instruction);
                instlist_tmp[tmpinst] = *lookup_instruction(bin_collection, instruction.pc);
                accesslist_tmp[tmpac+tmpinst].pc = instruction.pc; 
                break;
            case TraceEvent_access:
                tmpac--;
                read_Access(&accesslist_tmp[tmpac+tmpinst], event.access);
				// LOG(stdout, "[load_trace_mem]: Read Access %d\n", tmpac);
                break;
        }
    }
	fclose(file);

    *instlist = instlist_tmp;
    *accesslist = accesslist_tmp;

    // for (int i = 0; i < ttt; i++) {
    //     if (accesslist_tmp[i].size == 0) {
    //         LOG(stdout, "i = %d, empty\n", i);
    //     } else {
    //         LOG(stdout, "i = %d, %s %d bytes at %#x\n",
    //         i, accesslist_tmp[i].type == MEM_READ_AFTER ? "read" : "write",
    //         accesslist_tmp[i].size, accesslist_tmp[i].address);
    //     }
    // }
    return 0;
}
#else 
unsigned long load_trace(elf_binary_info * binary_info, char *trace_file, cs_insn *instlist){

    char line[ADDRESS_SIZE + 2];
    int offset = 0;
    char inst_buf[INST_LEN];
    unsigned long i;
    FILE *file;
    cs_insn inst;
    uint32_t address;

    if ((file = fopen(trace_file, "r" )) == NULL){
        LOG(stderr, "ERROR: trace file open error\n");
        return -1;
    }

    i = 0; 	

    while (fgets(line, sizeof(line), file) != NULL) {
        // need to check the result of strtoll instead of strncmp
        if (i >= get_max_rev_ins_num()){
            break;
        }
        if (strncmp(line, "[disabled]", 10) == 0) continue;
        if (strncmp(line, "[enabled]", 9) == 0) continue;
        if (strncmp(line, "[resumed]", 9) == 0) continue;

        // strtol return unsigned long.
        // So if input is bigger than 0x80000000, it will return 0x7fffffff
        address = (uint32_t)strtoll(line, NULL, 16);
        // LOG(stdout, "Processing 0x%08x...\n", address);
        // LOG(stdout,"1. address = %x\n", address);
        // LOG(stdout,"2. binary_info->start_address = %x\n", binary_info->start_address);
        // LOG(stdout,"3. lookuptable[%x]\n", (address - binary_info->start_address)>>1);
        // LOG(stdout,"4. instlist[%x]\n", binary_info->lookuptable[(address - binary_info->start_address)>>1]);
        // LOG(stdout,"5. instlist[%x].address = %x\n", binary_info->lookuptable[(address - binary_info->start_address)>>1], binary_info->instlist[binary_info->lookuptable[(address - binary_info->start_address)>>1]].address);
        instlist[i++] = binary_info->instlist[binary_info->lookuptable[(address - binary_info->start_address)>>1]];

    }

	fclose(file);
    return i;
}
#endif

#ifdef VSA
unsigned long load_log(char* log_path, operand_val_t *oploglist){

	unsigned index;
	char log_buf[LOG_MAX_SIZE];

	FILE* file; 


	if((file = fopen(log_path, "r")) == NULL){
		LOG(stderr, "ERROR: Cannot open file for log data\n");
		return -1;
	}

	index = 0;


	memset(log_buf, 0, LOG_MAX_SIZE);
	while(fgets(log_buf, sizeof(log_buf), file) != 0){
		if (index >= get_max_rev_ins_num()){
			break;
		}
		if(strncmp(log_buf, "noreg", 5) == 0){
			oploglist[index].regnum = 0;
			memset(oploglist[index].regs, 0, sizeof(oploglist[index].regs));
		}else{
			//process this line to get the tokens
			process_log_line(log_buf, &oploglist[index]);
		}

		index++;
		memset(log_buf, 0, LOG_MAX_SIZE);
	}
}
#endif



void destroy_instlist(cs_insn * instlist){
	if(instlist)
		free(instlist);
	instlist = NULL;
}

static char *useless_inst[] = {
	"prefetcht0",
	"lfence"
};

#define NUINST (sizeof(useless_inst)/sizeof(char *))

bool verify_useless_inst(cs_insn *inst) {
	int i;

	if (!inst) {
		return false;
	}

	for (i = 0; i < NUINST; i++) {
		if (strcmp(inst->mnemonic, useless_inst[i]) == 0)
			return true;
	}
        return false;
}

// destroy elf_binary_info structure
int destroy_bin_info(elf_binary_info * bin_info){
	// if (bin_info && bin_info->binary_info_set){
	// 	destroy_binary_set(bin_info);
	// }
	if (bin_info->instlist) {
		free(bin_info->instlist);
	}
	if (bin_info->lookuptable) {
		free(bin_info->lookuptable);
	} 
	if (bin_info){
		free(bin_info);
		bin_info = NULL;
	}
	return 0;
}

// destroy binary collection structure
int destroy_bin_collection_info(binary_collection* bin_collection){
	if(bin_collection != NULL){
		for(int i; i<bin_collection->count; i++){
			destroy_bin_info(&bin_collection->binaries[i]);
		}
	}
}

#ifdef VSA
void destroy_dlregionlist(dlregion_list_t *dlregionlist) {
        if (dlregionlist) {
                free(dlregionlist);
        	dlregionlist = NULL;
        }
}

int get_segment_from_addr(unsigned address) {
	int seg_id = -1, index;
	for (index = 0; index < re_ds.coredata->memsegnum; index++) {
		if ((address>=re_ds.coredata->coremem[index].low) &&
		    (address<re_ds.coredata->coremem[index].high)) {
			seg_id = index;
			break;
		}
	} 
	return seg_id;
}

#endif
// process all the binary files mapped by the core file,
// including the binary and the dynamic libraries
int count_bin_file_num(core_nt_file_info nt_file_info){
	int num = 0;
	int i = 0;
	char *prev_name, *next_name;
	prev_name = basename(nt_file_info.file_info[0].name);

	if (strlen(prev_name) > 0) num++;
	for (i=1; i< nt_file_info.nt_file_num; i++){
		next_name = basename(nt_file_info.file_info[i].name);
		if (!strlen(next_name)) continue;
		if (!strcmp(prev_name, next_name)){		
			continue;
        } else {
			num++;
			prev_name = next_name;
		}		
	}
	LOG(stdout, "DEBUG: The number of different binary files is %d\n", num);
	return num; 
}

// Parse config.yml file to get binary paths and their load addresses
config_data* parse_config_file(const char* config_path) {
    FILE* file = fopen(config_path, "r");
    if (!file) {
        LOG(stderr, "ERROR: Cannot open config file %s: %s\n", config_path, strerror(errno));
        return NULL;
    }

    config_data* config = (config_data*)malloc(sizeof(config_data));
    if (!config) {
        fclose(file);
        return NULL;
    }

    config->binaries = NULL;
    config->count = 0;
    size_t capacity = 0;

    char line[1024];
    char current_path[PATH_MAX] = {0};
    uint32_t current_start_address = 0;
    uint32_t current_end_address = 0;
    int in_binaries_section = 0;
    int has_path = 0;
    int has_start = 0;
    int has_end = 0;

    fseek(file, 0, SEEK_SET);

    while (fgets(line, sizeof(line), file)) {
        // Trim whitespace
        char* trimmed = line;
        while (*trimmed == ' ' || *trimmed == '\t') trimmed++;
        
        // Check for binaries section
        if (strncmp(trimmed, "binaries:", 9) == 0) {
            in_binaries_section = 1;
            continue;
        }

        if (!in_binaries_section) continue;

        // Parse path line (e.g., "  - path: /bin/busybox")
        if (strstr(trimmed, "- path:") || strstr(trimmed, "path:")) {
            char* path_start = strchr(trimmed, ':');
            if (path_start) {
                path_start++;
                while (*path_start == ' ' || *path_start == '\t') path_start++;
                
                // Remove trailing newline and whitespace
                char* end = path_start + strlen(path_start) - 1;
                while (end > path_start && (*end == '\n' || *end == '\r' || *end == ' ')) {
                    *end = '\0';
                    end--;
                }
                
                strncpy(current_path, path_start, sizeof(current_path) - 1);
                has_path = 1;
            }
        }
        // Parse start address line (e.g., "    start_address: 0x10000" or "    start: 0x10000")
        else if (strstr(trimmed, "start_address:") || strstr(trimmed, "start:")) {
            char* addr_start = strchr(trimmed, ':');
            if (addr_start) {
                addr_start++;
                current_start_address = (uint32_t)strtoul(addr_start, NULL, 0);
                has_start = 1;
            }
        }
        // Parse end address line (e.g., "    end_address: 0x20000" or "    end: 0x20000")
        else if (strstr(trimmed, "end_address:") || strstr(trimmed, "end:")) {
            char* addr_start = strchr(trimmed, ':');
            if (addr_start) {
                addr_start++;
                current_end_address = (uint32_t)strtoul(addr_start, NULL, 0);
                has_end = 1;
            }
        }
        
        // Check if we have all required fields for this entry
        if (has_path && has_start && has_end) {
            if (config->count >= capacity) {
                capacity = (capacity == 0) ? 16 : capacity * 2;
                config->binaries = (binary_config*)realloc(
                    config->binaries,
                    capacity * sizeof(binary_config)
                );
                if (!config->binaries) {
                    LOG(stderr, "ERROR: Failed to allocate config memory\n");
                    free(config);
                    fclose(file);
                    return NULL;
                }
            }
            
            config->binaries[config->count].binary_path = strdup(current_path);
            config->binaries[config->count].start_address = current_start_address;
            config->binaries[config->count].end_address = current_end_address;
            config->count++;
            
            LOG(stdout, "CONFIG: %s -> [0x%x - 0x%x]\n", 
                current_path, current_start_address, current_end_address);
            
            // Reset for next entry
            current_path[0] = '\0';
            current_start_address = 0;
            current_end_address = 0;
            has_path = 0;
            has_start = 0;
            has_end = 0;
        }
    }

    fclose(file);
    
    if (config->count == 0) {
        free(config);
        return NULL;
    }

    return config;
}

// parse binary
elf_binary_info* parse_single_binary(csh *handle, const char* bin_path, uint32_t start_address, binary_insts_is_thumb *binary_insts_is_thumb_arr, size_t binary_insts_is_thumb_arr_len) {
    cs_insn* insn;
    size_t count;
    bool is_thumb;

    size_t i, cur_binary_idx;
    uint32_t cur_addr, addr_offset;

    FILE* file = fopen(bin_path, "rb");
    if (file == NULL) {
        LOG(stderr, "Error When Open ELF file %s: %s\n", bin_path, strerror(errno));
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    size_t filesize = ftell(file);
    fseek(file, 0, SEEK_SET);

    uint8_t* buffer = (uint8_t*)malloc(filesize);
    if (buffer == NULL) {
        LOG(stderr, "Error When Memory Allocation\n");
        fclose(file);
        return NULL;
    }
    // uint8_t* cur_buffer_ptr = buffer;

    size_t bytes_read = fread(buffer, 1, filesize, file);
    if (bytes_read != filesize) {
        LOG(stderr, "Error When Reading ELF file %s: %s\n", bin_path, strerror(errno));
        fclose(file);
        free(buffer);
        return NULL;
    }

    elf_binary_info* binary_info = (elf_binary_info*)malloc(sizeof(elf_binary_info));
    if (binary_info == NULL) {
        LOG(stderr, "Error When Memory Allocation binary_info\n");
        cs_close(handle);
        fclose(file);
        free(buffer);
        return NULL;
    }
    // Initialize the structure
    memset(binary_info, 0, sizeof(elf_binary_info));
    binary_info->binary_path = strdup(bin_path);
    binary_info->start_address = start_address;
    // find binary idx of current binary in binary_insts_is_thumb_arr
    for(i=0; i<binary_insts_is_thumb_arr_len; i++){
        // LOG(stdout, "Finding idx of current binary\n");
        if(start_address == binary_insts_is_thumb_arr[i].binary_start_address){
            LOG(stdout, "Found idx of current binary %u\n", i);
            cur_binary_idx = i;
            break;
        }
    }
    
    size_t instlist_len = binary_insts_is_thumb_arr[cur_binary_idx].arr_len;

    // need to separate instlist_idx from subsequent i value as some values of i may not contain instruction that we want to analyse
    size_t instlist_idx = 0;

    // allocate memory for instlist based on max possible number of instructions, although should usually need less than that
    binary_info->instlist = (cs_insn *)malloc(instlist_len * sizeof(cs_insn));
    binary_info->inst_count = 0;
    
    binary_info->lookuptable = (uint32_t*)malloc(binary_insts_is_thumb_arr[cur_binary_idx].arr_len * sizeof(uint32_t));

    // TODO: handle failed mallocs
    if(!binary_info->instlist || !binary_info->lookuptable){
        LOG(stderr, "ERROR: Failed to allocated memory for binary_info->instlist/binary_info->lookuptable\n");
        return NULL;
    }

    // initialise with oversized value so program will crash if attempted to look for instruction at an address which wasn't executed 
    memset(binary_info->lookuptable, 0xFFFFFFFF, binary_insts_is_thumb_arr[cur_binary_idx].arr_len * sizeof(uint32_t));
    // LOG(stdout, "memset binary_info->lookuptable succeded\n");

    LOG(stdout, "binary_insts_is_thumb_arr[cur_binary_idx].binary_start_address: %#x\n", binary_insts_is_thumb_arr[cur_binary_idx].binary_start_address);
    // TODO: need to toggle between thumb mode and non thumb mode
    for(i=0; i<binary_insts_is_thumb_arr[cur_binary_idx].arr_len; i++){
        if(binary_insts_is_thumb_arr[cur_binary_idx].is_thumb_arr[i] == 0x1){
            cs_option(*handle, CS_OPT_MODE, CS_MODE_THUMB);
            is_thumb = true;
        }
        else if(binary_insts_is_thumb_arr[cur_binary_idx].is_thumb_arr[i] == 0){
            cs_option(*handle, CS_OPT_MODE, CS_MODE_ARM);
            is_thumb = false;
        }
        else{
            // instruction not executed, don't need to disasm
            continue;
        }

        // disasm one instruction at a time
        // offset = (addr - start_addr) >> 1
        // addr = offset << 1 + start_addr
        // LOG(stdout, "Disassembling inst at address %#x\n", i<<1 + binary_insts_is_thumb_arr[cur_binary_idx].binary_start_address);
        addr_offset = (uint32_t)((i<<1)&0xFFFFFFFF);
        cur_addr =  addr_offset + binary_insts_is_thumb_arr[cur_binary_idx].binary_start_address;
        count = cs_disasm(*handle, buffer+addr_offset, 4, cur_addr, 1, &insn);
        
        // if reach this path, means trying to disassemble instruction that was executed. If zero, means error in disasm
        if(count == 0){
            LOG(stderr, "ERROR: Failed to disassemble %s at current buffer ptr %#x for instruction at address %#x!\n", bin_path, cur_addr, i<<1 + binary_insts_is_thumb_arr[cur_binary_idx].binary_start_address);
            free(binary_info->binary_path);
            free(binary_info);
            cs_close(handle);
            fclose(file);
            free(buffer);
            return NULL;
        }

        if(insn->address & 1){
            LOG(stderr, "WARNING: instruction address is not aligned at %#lx\n", insn->address);
        }

        if (insn->id == ARM_INS_POP) {
            for (int op_idx = 0; op_idx < insn->detail->arm.op_count; op_idx++) {
                if (insn->detail->arm.operands[op_idx].access & CS_AC_READ) {
                    insn->detail->arm.operands[op_idx].access = CS_AC_WRITE;
                }
            }
        }

        // Bugfix: capstone wrongly disassembles negative displacement
        if (strstr(insn->op_str, "#-")) {
            insn->detail->arm.operands[1].mem.disp = -insn->detail->arm.operands[1].mem.disp;
        }

        // LOG(stdout, "Instruction %lx has address %#x and offset %#lx with start address %#x\n", instlist_idx, (uint32_t)((i<<1)&0xFFFFFFFF) + binary_insts_is_thumb_arr[cur_binary_idx].binary_start_address, i, binary_insts_is_thumb_arr[cur_binary_idx].binary_start_address);
        memcpy(&binary_info->instlist[instlist_idx], insn, sizeof(cs_insn));
        binary_info->inst_count++;
        // i is effectively the offset of the instruction since we are iterating through the is_thumb arr which contains a index for all possible instructions
        binary_info->lookuptable[i] = instlist_idx;
        instlist_idx++;
        // if(is_thumb){
        //     // thumb instructions are 2 bytes
        //     cur_buffer_ptr += 2;
        // }
        // else{
        //     cur_buffer_ptr += 4;
        // }

    }

    // count = cs_disasm(*handle, buffer, filesize, start_address, 0, &insn);
    // if (count > 0) {
    //     LOG(stdout, "DEBUG: Binary %s - %zu instructions\n", bin_path, count);
        
    //     binary_info->instlist = insn;
    //     binary_info->inst_count = count;
    //     binary_info->lookuptable = (uint32_t*)malloc(count * 2 * sizeof(uint32_t));
    //     memset(binary_info->lookuptable, 0xFFFFFFFF, count * 2 * sizeof(uint32_t));
    //     if (binary_info->lookuptable == NULL) {
    //         LOG(stderr, "Error When Memory Allocation lookuptable\n");
    //         cs_free(insn, count);
    //         free(binary_info->binary_path);
    //         free(binary_info);
    //         cs_close(handle);
    //         fclose(file);
    //         free(buffer);
    //         return NULL;
    //     }

    //     for (size_t j = 0; j < count; j++) {
    //         if (insn[j].address & 1) {
    //             LOG(stderr, "WARNING: instruction address is not aligned at %#x\n", insn[j].address);
    //         }
            
    //         // Bugfix: capstone wrongly disassembles some POP instructions
    //         if (insn[j].id == ARM_INS_POP) {
    //             for (int op_idx = 0; op_idx < insn[j].detail->arm.op_count; op_idx++) {
    //                 if (insn[j].detail->arm.operands[op_idx].access & CS_AC_READ) {
    //                     insn[j].detail->arm.operands[op_idx].access = CS_AC_WRITE;
    //                 }
    //             }
    //         }
            
    //         // Bugfix: capstone wrongly disassembles negative displacement
    //         if (strstr(insn[j].op_str, "#-")) {
    //             insn[j].detail->arm.operands[1].mem.disp = -insn[j].detail->arm.operands[1].mem.disp;
    //         }

    //         uint32_t offset = (insn[j].address - start_address) >> 1;
    //         // LOG(stdout, "Instruction %d has address %#x and offset %#x\n", j, insn[j].address, offset);
    //         binary_info->lookuptable[offset] = j;

    //     }
        
    // } else {
    //     LOG(stderr, "ERROR: Failed to disassemble %s!\n", bin_path);
    //     free(binary_info->binary_path);
    //     free(binary_info);
    //     cs_close(handle);
    //     fclose(file);
    //     free(buffer);
    //     return NULL;
    // }

    fclose(file);
    free(buffer);

    return binary_info;
}

// Main function to parse all binaries in sysroot using config file
binary_collection* parse_binaries_from_sysroot(binary_insts_is_thumb *binary_insts_is_thumb_arr, size_t binary_insts_is_thumb_arr_len, const char* sysroot_path, const char* config_path) {
    LOG(stdout, "STATE: Processing Binaries from Sysroot: %s\n", sysroot_path);
    LOG(stdout, "STATE: Using config file: %s\n", config_path);

	csh handle;

	if (cs_open(CS_ARCH_ARM, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        LOG(stderr, "ERROR: Failed to initialize capstone engine for %s!\n", sysroot_path);
        return NULL;
    }

    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    // Parse the config file
    config_data* config = parse_config_file(config_path);
    if (!config) {
        LOG(stderr, "ERROR: Failed to parse config file\n");
        return NULL;
    }

    binary_collection* collection = (binary_collection*)malloc(sizeof(binary_collection));
    if (!collection) {
        LOG(stderr, "ERROR: Failed to allocate binary collection\n");
        // Free config
        for (size_t i = 0; i < config->count; i++) {
            free(config->binaries[i].binary_path);
        }
        free(config->binaries);
        free(config);
		cs_close(&handle);
        return NULL;
    }

    collection->binaries = NULL;
    collection->count = 0;
    collection->capacity = config->count;
    collection->binaries = (elf_binary_info*)malloc(collection->capacity * sizeof(elf_binary_info));
    
    if (!collection->binaries) {
        LOG(stderr, "ERROR: Failed to allocate binaries array\n");
        free(collection);
        for (size_t i = 0; i < config->count; i++) {
            free(config->binaries[i].binary_path);
        }
        free(config->binaries);
        free(config);
		cs_close(&handle);
        return NULL;
    }

    // Process each binary from the config
    for (size_t i = 0; i < config->count; i++) {
        char full_path[PATH_MAX];
        
        // Construct full path: sysroot + binary_path
        // Handle case where binary_path might start with '/'
        const char* rel_path = config->binaries[i].binary_path;
        if (rel_path[0] == '/') {
            rel_path++; // Skip leading slash
        }
        snprintf(full_path, sizeof(full_path), "%s/%s", sysroot_path, rel_path);

         LOG(stdout, "Processing: %s at address range [0x%x - 0x%x]\n", 
            full_path, config->binaries[i].start_address, config->binaries[i].end_address);

        elf_binary_info* bin_info = parse_single_binary(
			&handle,
            full_path, 
            config->binaries[i].start_address,
            binary_insts_is_thumb_arr,
            binary_insts_is_thumb_arr_len
        );
        
        if (bin_info) {
			bin_info->end_address = config->binaries[i].end_address;

            collection->binaries[collection->count] = *bin_info;
            collection->count++;
            free(bin_info); // We copied the contents, free the wrapper
        } else {
            LOG(stderr, "WARNING: Failed to parse %s\n", full_path);
        }
    }

    // Cleanup config
    for (size_t i = 0; i < config->count; i++) {
        free(config->binaries[i].binary_path);
    }
    free(config->binaries);
    free(config);

    LOG(stdout, "STATE: Successfully loaded %zu binaries from sysroot\n", collection->count);
    
    if (collection->count == 0) {
        free(collection->binaries);
        free(collection);
        return NULL;
    }

	re_ds.handle = handle;
    return collection;
}

// Multi-range lookup function
cs_insn* lookup_instruction(binary_collection* collection, uint32_t address) {
    if (!collection) return NULL;

    // First, find which binary contains this address
    for (size_t i = 0; i < collection->count; i++) {
        elf_binary_info* bin = &collection->binaries[i];
        
        if (address >= bin->start_address && address < bin->end_address) {
            // Found the correct binary, now lookup within it
            uint32_t offset = (address - bin->start_address) >> 1;
            
            // Bounds check
            uint32_t max_offset = ((bin->end_address - bin->start_address) >> 1);
            if (offset >= max_offset) {
                LOG(stderr, "WARNING: Offset %u exceeds bounds for binary %s\n", 
                    offset, bin->binary_path);
                return NULL;
            }
            
            uint32_t inst_index = bin->lookuptable[offset];
            
            if (inst_index >= bin->inst_count) {
                // LOG(stderr, "Address %#x has offset value of 0x%#x and index of %u and retrieved inst has address\n", address, offset, inst_index);
                LOG(stderr, "WARNING: Invalid instruction index %u for address %#x\n", 
                    inst_index, address);
                return NULL;
            }
            
            return &bin->instlist[inst_index];
        }
    }

    // Address not found in any binary
    LOG(stderr, "WARNING: Address %#x not found in any loaded binary\n", address);
    return NULL;
}
