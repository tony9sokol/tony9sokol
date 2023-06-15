#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "elf64.h"

#define	ET_NONE	0	//No file type 
#define	ET_REL	1	//Relocatable file 
#define	ET_EXEC	2	//Executable file 
#define	ET_DYN	3	//Shared object file 
#define	ET_CORE	4	//Core file 


/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */
unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val) {
    int symbol_name_length = strlen(symbol_name);
    FILE *file = fopen(exe_file_name, "rb");
    Elf64_Ehdr header1;
    fseek(file, 0, SEEK_SET);
    fread(&header1, sizeof(Elf64_Ehdr), 1, file);

    if (header1.e_type != ET_EXEC) {
        *error_val = -3;
        fclose(file);
        return 0;
    }
    int num_of_sec_headers = header1.e_shnum;
    Elf64_Shdr sectable[num_of_sec_headers];
    fseek(file, header1.e_shoff, SEEK_SET);
    fread(&sectable, sizeof(Elf64_Shdr), num_of_sec_headers, file);
    Elf64_Shdr my_strtab;
    Elf64_Shdr my_symtab;
    for (int i = 0; i < num_of_sec_headers; i++) {
        if (sectable[i].sh_type == 2) {//check if SYMTAB
            my_symtab = sectable[i];
        }
        if (sectable[i].sh_type == 3 && i != header1.e_shstrndx) {//check if wright STRTAB
            my_strtab = sectable[i];
        }

    }
    int symtab_total_size = my_symtab.sh_size;
    int numentries = (int) (symtab_total_size / sizeof(Elf64_Sym));
    Elf64_Sym symbols[numentries];

    int curr_offset;
    bool is_global=false;
    bool is_local=false;
    bool defined=true;
    bool exists = false;
    int string_sec_offset=my_strtab.sh_offset;
    char *curr_name = "";
    int index_of_symbol=0;

    for (int i = 0; i < numentries; i++) {
        curr_offset = symbols[i].st_name;
        fseek(file, (curr_offset + string_sec_offset), SEEK_SET);
        fread(curr_name, symbol_name_length, 1, file);
        if (strcmp(curr_name, symbol_name) == 0) {
            index_of_symbol = i;
            exists = true;
            if (ELF64_ST_BIND(symbols[i].st_info) == 0) {
                is_global = 1;
            }
            if (ELF64_ST_BIND(symbols[i].st_info) == 1)
                is_local = 1;
        }
    }
    if (!exists) {
        *error_val= -1;
        fclose(file);
        return 0;
    }
    defined = (symbols[index_of_symbol].st_shndx != SHN_UNDEF);
    if (is_global && defined) {
        *error_val = 1;
        fclose(file);
        return symbols[index_of_symbol].st_value;
    }
    if (is_global && !defined) {
        *error_val = -4;
        fclose(file);
        return 0;
    }
    if (is_local && !is_global) {
        *error_val = -2;
        fclose(file);
        return 0;
    }
}
int main(int argc, char *const argv[]) {
	int err = 0;
	unsigned long addr = find_symbol(argv[1], argv[2], &err);

	if (err >= 0)
		printf("%s will be loaded to 0x%lx\n", argv[1], addr);
	else if (err == -2)
		printf("%s is not a global symbol! :(\n", argv[1]);
	else if (err == -1)
		printf("%s not found!\n", argv[1]);
	else if (err == -3)
		printf("%s not an executable! :(\n", argv[2]);
	else if (err == -4)
		printf("%s is a global symbol, but will come from a shared library\n", argv[1]);
	return 0;
}