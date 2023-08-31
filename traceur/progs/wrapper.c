#define _GNU_SOURCE
/**
 * Author : Nicolas Ducarton
 *
 * The wrappeur is launching the program we want to trace.
 * It must first find the functions that can be traced
 * that are specified in the config file.
 * It'll next build a library to store instructions later.
 * It's final task is to inject our tracing library into the traced code. 
*/
#include <stdio.h> //frpintf,stderr
#include <fcntl.h>//open files
#include <libelf.h>//open elf files
#include <string.h>//strcmp, strchr
#include <stdbool.h>
#include <stdlib.h> //malloc
#include <unistd.h> //write
#include <errno.h>
#include <sys/wait.h>//wait for the program to stop.
#include <sys/stat.h>//mkdir
//the dissasembler
#include "capstone/capstone.h"
#include <omp.h>
#include <ctype.h>
#include <mpi.h>
#include "readfiles.h"

#define MIN_TRACING_SIZE 19
#define CALL_SIZE 14
#define JMP_SIZE 14 

Elf * executable;

struct symbols {
    int i;
    char * name;
    Elf64_Sym sym;
};

bool omp = false;//TODO: do not use these global variables
bool mpi = false;//use parameters instead.

int fdexe; //the file descriptor of the executable
int function_number;//the number of functions we are tracing
struct symbols * function_list;
int * tramp_lenghts;//the needed lenght of each tramp

//If you add names to this list, do not forget to increment "exclusym_nb" below.
char * reserved_symbols[] =  {"_start", "_init", "__libc_csu_init", "__libc_csu_fini", "_sub_D_00099_0", "_sub_I_00099_1",
                            "register_tm_clones", "frame_dummy" , "__do_global_dtors_aux"};
int exclusym_nb = 9; // the number of excluded and reserved symbols.
char ** excluded_symbols;

int textnb = -1;//the number of the text section

char * trace_output;//the folder where to store the trace.
char * config ;//the folder where to searrch for the config file
uint8_t precision = 52;//ASCII char for precision number (from 0 to 4, ie. 48 to 52)
/**
 * Help function describing how to use the program
 */
void usage(){
    printf("Usage : ./wrap [options] \"binary\"\n" 
		"\t\tmpirun [mpirun options] ./wrap [options] \"binary\" [binary options]"
        "options :\n"
        "\t-o : activate omp instrumentation \n"
     	"\t-m : activate mpi instrumentation \n"
        "\t-p [number] :\t modifies precision. 0 or 4 resuults in better overhead\n"
        "\t\t0 :\t precision to the second\n"
        "\t\t1 :\t precision to the hundredth of a second (0.01s)\n"
        "\t\t2 :\t precision to the nearest hundred microseconds (100µs)\n"
        "\t\t3 :\t precision to the nearest hundred nanoseconds (100ns)\n"
        "\t\t4 :\t précision to the nanosecond (1ns)\n"
        "\t-r [directory] :\tdirectory where to write the trace (working directory by default)\n"
        "\t-c [config] :\tdirectory where to search for config file, by default : \"./config\"\n");
}

extern int optind;//to know which part of the input is the executable.
/**
 * parses the parameters given to the program to check
 * wether we have what we need.
 * Return 0 if not the case
 * return 1 otherwise.
 */
int parse_input(int argc, char ** argv){
    int opt;
    while ((opt = getopt(argc, argv, "+omp:r:c:")) != -1)
    {
        switch (opt)
		{
			case 'o':
				omp = true;
				break;
			case 'p':
				if (optarg[0]>= 48 && optarg[0]<= 52)
					precision = optarg[0];
				else
					fprintf(stderr,"precision level not recognised. Using level %d", precision);
				break;
			case 'r':
				trace_output = malloc(strlen(optarg));
				strcpy(trace_output,optarg);
				break;
			case 'c':
				config = malloc(strlen(optarg));
				strcpy(config, optarg);
				config = optarg;
				break;
			case 'm':
				mpi = true;
				break;
			default:
				usage();
		}
    }
    if(config == NULL){
        config = malloc(strlen("/config"));
        strcpy(config, "./config");
    }
    if(trace_output == NULL){
        trace_output = malloc(strlen("."));
        strcpy(trace_output, ".");
    }
    if((optind == argc) || argc < 2){
        puts("no binary provided");
        usage();
        return 0;
    }
    return 1;
}

/**
 * Used mostly to report errors in user's config file. If a symbol is submitted but does not exists in the binary
 * it prints a message on the command line and returns false.
 */
bool symbol_exists(char * symbol, int * number, Elf64_Sym * s){
    int st;
    if ((st = symtab_nb(executable)) == -1)
        return NULL;
    //we are searching for all the symbols
    Elf_Scn * symtab_scn = elf_getscn(executable, st); //the section that contains all the symbols
    Elf64_Shdr * symtab_hd = elf64_getshdr(symtab_scn); //the header
    Elf64_Sym * sym = elf_getdata(symtab_scn, NULL)->d_buf; //the data
    //the string table for the section.
    Elf_Scn * str_symtab_scn =  elf_getscn(executable, symtab_hd->sh_link);
    //and its data
    char * str_symtab_str = (char *) elf_getdata(str_symtab_scn, NULL)->d_buf;
    int i =0; bool f = false;
    while(i < (symtab_hd->sh_size /symtab_hd->sh_entsize) && !f )
    {
        if(strcmp(str_symtab_str + sym[i].st_name, symbol) ==0){
            f = true;
            if(s != NULL){
                *number = i;
                *s = sym[i];}
        }
            
        i++;
    }
    if(!f)
        fprintf(stderr, "symbol \"%s\" not found!\n", symbol);
    return f;
}
/**
 * Returns part of the file between two delimiters.
 * Used to explore the config file.
 * char c is the number of the section we want.
 * fd is the config file.
 * If not found returns NULL
 */
char * file_part(char c, FILE * fd){
    char * file = whole_file(config);
    char * delim = "+";
    char * tmp = strtok(file, delim);
    bool found = false;
    do 
    {
        if(tmp[0] == c){
            found = true;
        }
    }while (!found && (tmp = strtok(NULL, delim)) != NULL);
    if(!found)
        return NULL;
    char * ret = malloc(strlen(tmp)+1);
    strcpy(ret, tmp);
    ret[strlen(tmp)] = '\0';
    free(file);
    return ret;
}

/**
 * Returns the size of the include list, and the names of the functions to include.
 * If no symbols to include are found it returns NULL and gives 0 as the size.
 */
struct symbols * include_config(int * size, FILE * fd){
    int nb = 0;
    struct symbols * sym = NULL;
    char * tmp;
    if((tmp = file_part('1', fd)) == NULL){
        *size = 0;
        return NULL;
    }
    
    char * delim = "\n";
    char * tmp2 = strtok(tmp, delim);
    int i = 0; Elf64_Sym s;
    while ((tmp2 = strtok(NULL, delim)) != NULL)//for each function name:
    {
        while (isspace(*tmp2))
        {
            tmp2++;
        }
        if (*tmp2 != '#')
        {
            if(symbol_exists(tmp2, &i, &s)){
                nb++;
                sym= realloc(sym, sizeof(struct symbols) * nb);
                sym[nb-1].i = i;
                sym[nb-1].sym = s;
                sym[nb-1].name = malloc(sizeof(char ) * strlen(tmp2)+1);
                strncpy(sym[nb-1].name , tmp2, strlen(tmp2));
                sym[nb-1].name[strlen(tmp2)] = '\0';
            }
        }
    }
    free(tmp);
    *size = nb;
    return sym;
}
/**
 * adds the names of the excluded symbols in the config file to the list.
 */
void exclude_config(FILE * fd){
    char * tmp;
    if((tmp= file_part('2', fd)) == NULL){
        puts("found nothing");
        return;
    }
    char * delim = "\n";
    char * tmp2 = strtok(tmp, delim);
    while ((tmp2 = strtok(NULL, delim)) != NULL)//for each function name:
    {
        while (isspace(*tmp2))
        {
            tmp2++;
        }
        if (*tmp2 != '#')
        {
            if(symbol_exists(tmp2, NULL, NULL)){
                exclusym_nb++;
                excluded_symbols = realloc(excluded_symbols, exclusym_nb*sizeof(char *));
                excluded_symbols[exclusym_nb-1] = malloc(strlen(tmp2));
                strcpy(excluded_symbols[exclusym_nb-1], tmp2);
            }
        }
    }
    free(tmp);
}


/**
 * returns a pointer to the address of the function defined by its number (nb) in the symtab (sym).
 * this pointer will contain the code of said function.
 */
unsigned char * get_code(Elf64_Sym sym, int nb, Elf64_Shdr * symtab_hd){
    Elf_Scn * textscn = elf_getscn(executable, text_nb(executable));
    Elf64_Shdr * texhdr = elf64_getshdr(textscn);
    unsigned char * code = (unsigned char *) elf_getdata(textscn, NULL)->d_buf;
    int offset = sym.st_value - texhdr->sh_addr;
    return code+offset;
}
/**
 * tells if the instr insn uses rip
 * which is problematic if we are moving the code around.
 */
bool uses_rip(csh handle, cs_insn * insn){
    uint8_t read = 0;uint8_t write = 0;
    cs_regs regs_read, regs_write;
    cs_regs_access(handle, insn, regs_read, &read, regs_write, &write );
    if(read != 0){
        for (size_t i = 0; i < read; i++)
        {
            if(regs_read[i] == 41) // rip
                return true;
        }
    }
    return false;
}

/**
 * Returns the number of bytes of the function from its symbol number
 * calculate the diff bewteen the addresses? 
 */
int function_lenght(Elf64_Sym sym, int nb, Elf64_Shdr * symtab_hd){
    if(sym.st_size)
        return sym.st_size;
    
    //TODO: function_lenght more resilient?
    //dans le cas où c'est la dernière case du tableau
    //il faudrait trouver l'adresse de la fin de la section .text
    //on prend proche supérieure à l'adresse de nb
    //la fin de la section .text à défaut. 
    return 0;
}

/**
 * tells if the jmp points into the zone defined by off and size. (true)
 * addr should contain the jmp  instruction
 * off contains the position of the jump relative to the beginning of the function
 * lenght is the lenght of the instr.
 * size is the total size of the zone, starting from off.
 */
bool points_inside(int off, int lenght, int size, unsigned char * addr, bool * negative){
    int instrsz = 1;
    if(addr[0] == 0x0f)
        instrsz += 1;
    int address = 0;
    if(lenght-instrsz == 1){//8 bit operand size
        int8_t * tmp = (int8_t *) (addr+instrsz);
        address = (int)*tmp+lenght;
    }
    if(lenght-instrsz == 4){//32 bit operand size
        int * tmp = (int *) (addr+instrsz);
        address = *tmp+lenght;
    }//we cant have 16/64 bit jumps neather relative jumps with indirect operands, or jumps poiting to +/-0
    if(address == 0){
        puts("//TODO: error managment in points_inside");
    }
    if(address>0){
        *negative = false;
        return address <= size - off;
    }
    *negative = true;
    return address + off > 0 && address + off <= size;
}
/**
 * This function is called by the "eligible" function
 * Its goal is to check if there is a conditionnal jump that would make the trampoline bigger
 * This is the case if the function contains a loop.
 * code is the code of the function from the beginning
 * fct_l contains the size (bytes/octets) of the function.
 * tl will contain the predicted lenght of the function before any modifications.
 */
void pass_1(csh handle, cs_insn *insn, unsigned char * code, int  fct_l , int * tl){
    bool gotmin = false; *tl = 0;//the size of the jmp at the end
    bool negative = true; int sz = 0;
    while (sz < fct_l)
    {   
        
        if(!cs_disasm(handle, code+sz, 15, 0x0, 1, &insn)){
            *tl = -1;
            return;
        }
        if(!gotmin){
            if(sz < MIN_TRACING_SIZE)
                *tl += insn[0].size;
            if(*tl >= MIN_TRACING_SIZE )
                gotmin = true;
        }
        //if we have a conditionnal jump pointing backwards (into the jump)
        if(is_conditionnal_jump(code+sz) || is_loop(code+sz) || is_jump(code+sz)){
            if(points_inside(sz, insn[0].size, *tl, code+sz, & negative)){
                if(negative && *tl < sz+insn[0].size)
                    *tl = sz+insn[0].size;
                else{
                    int8_t off = (int8_t) code[1];
                    if((code[0] == 0xe0 || code[0] == 0xe1 || code[0] == 0xe2)//if loop 
                        && sz + off + insn[0].size > *tl)//and offset > *tl
                        *tl = sz + off + insn[0].size;
                }
            }   
        }
        sz += insn[0].size;
        cs_free(insn, 1);
    }
}

/**
 * This function is called by the "eligible" function
 * Its goal is to give a precise size for the trampoline function
 * by checking for calls that would increase its size, and jumps out of the trampoline.
 * we must perform two passes because the jumps backwards need to be known before
 * analyzing jumps forward.
 */
void pass_2(csh handle, cs_insn *insn, unsigned char * code, int * ft){
    int sz = 0; int fct_l = *ft; bool n;
    while (sz < fct_l)
    {
        cs_disasm(handle, code+sz, 15, 0x0, 1, &insn);
        //if we have a conditionnal jump pointing backwards (into the jump)
        if(is_conditionnal_jump(code+sz) || is_jump(code+sz) || is_loop(code+sz)){
            if(!points_inside(sz, insn[0].size, fct_l, code+sz,&n))
                *ft += JMP_SIZE;}
        else if(is_call(code+sz)){
            *ft += CALL_SIZE;
        }
        if(uses_rip(handle, insn) && !(is_call(code+sz) || is_jump(code+sz))){//if we have a relative load (not supported in version 1 of this program)
            *ft = -1;
            return;
        }
        sz += insn[0].size;
        cs_free(insn, 1);
    }
}

/**
 * this function is responsible for telling if the funtion is long enough to be instrumented
 * Function is defined by its number (nb) in the symtab (sym). 
 * If it is too small, the function returns false and the value in 
 * tl shall be ignored. Otherwise, tl contains the lenght the trampoline needs
 * to be in order to contain the part of the function overwritten by the hook.
 */
bool eligible(Elf64_Sym sym, int nb, Elf64_Shdr * symtab_hd, int * tl ){

    unsigned char * code = get_code(sym, nb, symtab_hd);
    *tl = MIN_TRACING_SIZE;
    //capstone handle
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return false ;//TODO: error handling
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_OFF);
    cs_insn *insn = NULL;
    //we explore the funtion
    int fl;
    if((fl = function_lenght(sym, nb, symtab_hd)) < MIN_TRACING_SIZE)
        return false;
    pass_1(handle, insn, code, fl, tl); 
    pass_2(handle, insn, code, tl);
    if(*tl == -1)
        return false;
    //printf("%d : %d\n", *tl, sym[nb].st_size);
    *tl += JMP_SIZE; // the jmp at the end
    cs_close(&handle); 
    return true;       
}


/**
 * return the list of all valid symbols in the file, with the size of the list in "size"
 * Checks if the function is long enough to be instrumented
 * checks if it is a function
 * checks if it is also part of the dynamic symbol table. If so, it'll be excluded
 * in order to exclude library funcion calls
 * 
 * will check the Elf executable. To exclude some symbols you might use "names"
 * with the size of the names array as namessize
 * size can be the pointer of namesize.
 */
struct symbols * get_all_symbols(int * size){
    //for now we will just print all of them
    *size = 0;
    //checking we do have the symbol table
    int st;
    if ((st = symtab_nb(executable)) == -1)
        return NULL;
    //we are searching for all the symbols
    Elf_Scn * symtab_scn = elf_getscn(executable, st); //the section that contains all the symbols
    Elf64_Shdr * symtab_hd = elf64_getshdr(symtab_scn); //the header
    Elf64_Sym * sym = elf_getdata(symtab_scn, NULL)->d_buf; //the data
    //the string table for the section.
    Elf_Scn * str_symtab_scn =  elf_getscn(executable, symtab_hd->sh_link);
    //and its data
    char * str_symtab_str = (char *) elf_getdata(str_symtab_scn, NULL)->d_buf;

    struct symbols * funcs = (struct symbols *) malloc(sizeof(struct symbols) * symtab_hd->sh_size / symtab_hd->sh_entsize);//an array for containing all symbols
    
    int i =0;//searching throught all symbols
    while(i < (symtab_hd->sh_size /symtab_hd->sh_entsize))
    {
        if(ELF64_ST_TYPE(sym[i].st_info) == STT_FUNC //its a function
            && sym[i].st_value != 0 //which is statically linked (or its code is in the binary)
            && ELF64_ST_VISIBILITY(sym[i].st_other) == STV_DEFAULT ){ //and part of the default programm
            
            bool ok = true; int j = 0;
            //if it is not into ignored symbols:
            while (ok && j<exclusym_nb)
            {
                if(strcmp(str_symtab_str + sym[i].st_name, excluded_symbols[j]) == 0)
                    ok = false;
                j++;
            }
            if(ok){
                funcs[*size].name = malloc(sizeof(char *) * strlen(str_symtab_str + sym[i].st_name));
                strcpy(funcs[*size].name, str_symtab_str + sym[i].st_name);
                funcs[*size].i = i;
                funcs[*size].sym = sym[i];
                *size = *size + 1;
            }
            
        }
        i++;
    }
    return funcs;
}

/**
 * takes a file descriptor for the config file and returns 1 if correctly parsed
 * 0 if an error occured.
 * After execution of this function, global variables fuction_list and function_number should be set.
*/
int parse_config(FILE * fd){
    struct symbols * syms = NULL; int size =0;
    if(fd == NULL){
        function_list = get_all_symbols(&size);
        function_number = size;
        return 1;
    }
    //détecter des données dans la liste d'inclusion
    syms = include_config(&size, fd);
    if(!size){//Si il n'y en a pas:
        //détecter des données dans la liste d'exclusion
        exclude_config(fd);
        syms = get_all_symbols(&size);
    }
    function_list = syms;
    function_number = size;
    return 1;
}

/**
 * this function will write a trampoline function in tramps.c
 * The trampoline will contain "size"  bytes at minimum
 * It will be written in the "fd" file.
 * the function needs to know the identifier for the trampoline
 */
void write_tramp_c(int size, int fd, int nb){
    char * buf = malloc(40+size * 6);
    //the start of the method.
    sprintf(buf, "void tramp_%d(){__asm__(", nb);
    strcat(buf, "\"");
    for (size_t i = 1; i < size; i++)
    {
        strcat(buf, "nop\\n");
        //buf[i] = 'n'; buf[i+1] = 'o'; buf[i+2] = 'p'; buf[i+3] = '\\'; buf[i+3] = 'n';
    }
    strcat(buf, "nop\");}\n");
    write(fd, buf, strlen(buf));
    free(buf);
}
//unused
char unit(int * nb){
    if (*nb < 1000)
        return 'o';
    *nb = *nb/1000;
    if(*nb < 1000)
        return 'k';
    *nb = *nb/1000;
    if(*nb < 1000)
        return 'M';
    *nb = *nb/1000;
    return 'G';
}
/**
 * Creates the shared library containing all the "trampolines"
 * that is, a really simple library containing dummy functions.
 * Those will be rewrited at runtime to contain the
 * original code that have been overwritten and jump to the 
 * original function.
 */
int create_tramps(int function_number){
	int libfd;
    if((libfd = open("./tramps.c", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU)) < 0){
        fprintf(stderr, "could not create library file");
        return 1;
    }
    int s = 0;
    //TODO : reduce size of symbol
    for(int i = 0; i< function_number; i++){
        write_tramp_c(tramp_lenghts[i], libfd, i);
        s+= tramp_lenghts[i];
	} 
    //close the file
    close(libfd);
    //compile the lib (valgrind says there is a memory leak here, check how to correct it)
    if(system("gcc -shared -fPIC -o /tmp/tramps.so tramps.c") != 0){
        fprintf(stderr, "library compilation failed\n");
        return 1;
    }
    //delete file
    remove("./tramps.c");
    return 0;
}

/**
 * Saves the symbols we are tracing into a temporary file
 * this will be the "parameter" file for the injected library
 */
int save_list(){
    char trace_folder[strlen(trace_output)+11];
    if(trace_output[strlen(trace_output)-1] == '/')
        sprintf(trace_folder, "%strace.out/", trace_output);
    else
        sprintf(trace_folder, "%s/trace.out/", trace_output);
    mkdir(trace_folder, 0775);
    int fd;
    if((fd = open("/tmp/trace.tmp", O_RDWR | O_CREAT | O_TRUNC, S_IRWXU)) >= 0){//create file
        if (write(fd, omp?"1\n":"0\n", 2) == 2){//is omp activated
            if (write(fd, mpi?"1\n":"0\n", 2) == 2){//is mpi activated
				if(write(fd, trace_folder, strlen(trace_folder)) == strlen(trace_folder) && write(fd, "\n", 1)){//where to store
                    if (write(fd, &precision, 1) && write(fd, "\n", 1)){//precision level
                        for (size_t i = 0; i < function_number; i++)
                            if(write(fd,function_list[i].name, strlen(function_list[i].name)) < strlen(function_list[i].name) ||( i <function_number -1 && write(fd, "\n", 1) !=1)){
                                fprintf(stderr, "error while writing parameter file\n");
                                return 1;
                            }
					close(fd);
					char tmp[strlen("cp /tmp/trace.tmp ") + strlen(trace_folder)+5];
					sprintf(tmp, "cp /tmp/trace.tmp %snames", trace_folder);
					//TODO: do it in C
					system(tmp);
					return 0;
    }}}}}
    fprintf(stderr,"could not create symbol file\n");
    return 1;
}
/**
 * This function returns the path of the lib.so file.
 * This file is expected to be in the same directory as the wrapper executable itself.
 */
char * find_lib_path(){
    char * path = "/proc/self/exe";
    int pathsize= 101; int wrotesize;
    char * result = calloc(pathsize, sizeof(char));
    while ((wrotesize = readlink(path, result, pathsize)) == pathsize)
    {
        pathsize += 100;
        result = realloc(result, pathsize);
    }
    //on réajuste la taille de l'allocation mémoire.
    pathsize -= 100 - wrotesize;
    result = realloc(result, pathsize+7);
    result[pathsize] = '\0';
    char *  mod =strrchr(result, '/');
    if(mod == NULL){
        fprintf(stderr, "could not find lib.so, aborting");
        exit(1);
    }
    mod[1] = 'l'; mod[2] = 'i'; mod[3] = 'b'; mod[4] = '.'; mod[5] = 's'; mod[6] = 'o'; mod[7] = '\0';
    return result;
}

void launch_prog(char ** argv, char ** ev, int off){
    //TODO: consider the case where we use a wrapper to launch the program.
    //finding the path for LD_PRELOAD
    
    char * lib = find_lib_path();
    setenv("LD_PRELOAD", lib, 1);//TODO: not overwrite but complement
    extern char** environ;

    free(lib);
    int status = 0;
    if(vfork() == 0){
        if (execvpe(argv[off], argv+off, environ) == -1)
        {
            fprintf(stderr,"error launching program:%s\n",strerror(errno));
			exit(1);
        }
    }else{
        wait(&status);
        printf("retour :%s\n", strerror(status));
    }
}

void free_memory(){
    for (size_t i = 0; i < exclusym_nb; i++)
    {
        free(excluded_symbols[i]);
    }
    free(excluded_symbols);
    for (size_t i = 0; i < function_number; i++)
    {
        free(function_list[i].name);
    }
    free(function_list);
    
}
/**
 * checks if the given symbols are valid, eligible to be instrumented,
 * and computes the sizes of the trampolines associated with the symbols.
 */
void check_symbols(){
    int st;
    if ((st = symtab_nb(executable)) == -1)
        return;
    //we are searching for all the symbols
    Elf_Scn * symtab_scn = elf_getscn(executable, st); //the section that contains all the symbols
    Elf64_Shdr * symtab_hd = elf64_getshdr(symtab_scn); //the header

    tramp_lenghts = (int *) malloc(sizeof(int)* function_number);
    size_t i = 0;
    while( i < function_number)
    {
        int k = 0;
        if (eligible(function_list[i].sym, function_list[i].i,  symtab_hd, &k)){
            tramp_lenghts[i] = k;
        }
        else{
            function_number --;
            for (size_t j = i; j < function_number; j++)
                function_list[j] = function_list[j+1];
            i--;
        }
        i++;
    }
}

int do_work(int argc, char ** argv){
    FILE * config_fd;
	//is the file given an elf file?
	if((executable = get_elf(argv[optind] )) != NULL){
		excluded_symbols = malloc(sizeof(char *)* exclusym_nb);
		for (int i = 0; i < exclusym_nb; i++)
		{
			excluded_symbols[i] = malloc(sizeof(char *)* strlen(reserved_symbols[i]));
			strcpy(excluded_symbols[i], reserved_symbols[i]);
		}
		//checking the config file:;
		if((config_fd = fopen(config, "r")) == NULL)
			fprintf(stderr, "no config file found\n");
		//parsing config file
		if(!parse_config(config_fd)){//failed:  
			fprintf(stderr, "could not read config file\n");
			if(config_fd != NULL)
				fclose(config_fd);
		}
		else{
			check_symbols();
			//creating the .so with all the trampolines:
			if(create_tramps(function_number) == 0){
				//saving the symbol list for the library
				if(save_list() == 0){
					//free the symbol list.
					free_memory();
					//close the elf parser.
					elf_end(executable);
					//close the binary
					close(fdexe);
					return 1;
				}
				else{
					free_memory();
					return 0;
				}
			}
		}
	}
	return 0;
}
/**
	* Uses /proc/[pid]/task/[tid]
 */
/*int get_smallest_child_pid(){
	//get parent pid
	int ppid = getppid();
	//explore /proc/[pid]/task
}*/
/**
 * If we use MPI we are accessing files from multiple processes.
 * The use of MPI_Init is forbidden, and thus all MPI primitives are unusable
 * Then we have to find manners to synchronize all childs without their PID.
 *
 */
int main(int argc, char ** argv, char ** env){
    //just checking the options
    int resp = parse_input(argc, argv);
	if(resp){
		if(mpi){
			//remove the files 
			do_work(argc, argv);
			launch_prog(argv, env, optind);                        
			/*int i = -1;
			MPI_Init(NULL, NULL);
			MPI_Comm_size(MPI_COMM_WORLD, &i);
			printf("com %d\n",i);
			MPI_Comm_rank(MPI_COMM_WORLD, &i);
			int isok = 0;
			if(i == 0)
				isok = do_work(argc, argv);
			//scatter isok
			MPI_Bcast(&isok, 1, MPI_INT, 0, MPI_COMM_WORLD);
			//scatter optinf
			int off = optind;
			printf("before(%d): optin: %d isok : %d\n",i, off, isok );
			MPI_Bcast(&off, 1, MPI_INT, 0, MPI_COMM_WORLD);
			printf("after(%d) : optin: %d\n",i,off);
			if(isok)
				launch_prog(argv, env, off);                        
			if(i == 0)
				remove("./tramps.so");
			MPI_Finalize();*/
			//printf("ppid: %d \n", getppid());
		}else{
			if(do_work(argc, argv))
				//launch the program
				launch_prog(argv, env, optind);                        
			//remove the tramps:
			remove("./tramps.so");
		}
	}
}
