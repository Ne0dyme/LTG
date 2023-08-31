/**
 * Author: Nicolas Ducarton
 * This library is injected into the program we want to trace
 * it modifies its code and takes care of the instrumentation.
 */
#define _GNU_SOURCE
#include <stdio.h>//printf et puts
#include <stdint.h> // int64 uintptr_t
#include <libelf.h>//open elf files
#include <fcntl.h>//open files
#include <dlfcn.h>//dlopen and dlsym
#include <stdlib.h>//malloc, calloc
#include <string.h>//strlen, strcpy, strcat...
#include <stdbool.h>
#include <unistd.h> //write read lseek
#include <sys/mman.h>//mprotect
#include <time.h>//obviously
#include <errno.h>
#include <omp.h>
#include <math.h>
#include <pthread.h>
#include <mpi.h>
#include <readfiles.h>
//the dissasembler
#include "capstone/capstone.h"

//
//i.e the program launches another program as the wrapper did.
//TODO: use assert on every malloc/calloc

extern void hook(int ident);//the asm function. We have its adress thanks to this symbol
extern void omphook(int ident);//the asm function. We have its adress thanks to this symbol
//global values used by the assembly. Aren't used in C but we can import them like that.
extern int last;
extern int * ident;
extern uintptr_t * stack;
extern int * lastab;
extern int threadtabsize;
//the time structures. Each thread has one.
struct timespec * tm;

int bytes_func_ident;
uint8_t precision_level;

//a buffer size of 100 mo
//will be multiplied by the number of omp_threads.
#define BUFFER_SIZE 100000000
#define BUFFER_MARGIN 12 //do not decrease that
struct timespec tots;
struct timespec tote;
//size we overwrite in the origin function.
#define HOOK_SIZE 19

//the buffers containing the tracing data
char * buffer1;
char * buffer2;
char ** restrict actual;
char ** restrict flushing;
//list of file descriptors (each thread has one)
unsigned int * restrict outfd;
long unsigned int buffer_ptr = 0;//number of bytes used in the buffer

long unsigned int * restrict omp_buff_ptr;
//arguments passed to the async flush function
pthread_t * flushthreads;
struct thread_arg{
    char * buf;//the buffer to flush
    long unsigned int size;//its size
    int fd;//where to write
};

//used by dlopen
void * handler;

//used to know what jumps we have to modify in the code for the trampoline.
struct rewrote{
    uint offset;
    uint size;
};
//the max thread possible
int omp_max = 1;
//where to write the trace
char * trace_output;
//our rank
int mpi_rank = 0;
//has mpi_init been called?
bool mpi_initialized = false;

/**
 * Used to asynchronously flush buffers
 */
void * pthread_flush(void * arg){
    struct thread_arg * s =  arg;
    if (write(s->fd, s->buf, s->size) == -1)
    {
        fprintf(stderr, "error writing buffer (address %p, size %lu) to the disk (file descriptor %d): error %d:%s\n", s->buf, s->size, s->fd, errno, strerror(errno));        
        exit(1);
    }
    free(arg);
    return 0;
}

/**
 * writes what the buffer contains to the disk.
 * Used by sequential instrumentation
 */
void flush(){
    char * tmp = actual[0];
    actual[0] = flushing[0];
    flushing[0] = tmp;
    if(flushthreads[0] != -1)
        pthread_join(flushthreads[0], NULL);
    struct thread_arg * t = malloc(sizeof(struct thread_arg));
    t->size = buffer_ptr;
    t->fd = outfd[0];
    t->buf = flushing[0];
    pthread_create(&flushthreads[0], NULL, &pthread_flush, t);
    buffer_ptr = 0;
}

/**
 * writes what the buffer contains to the disk.
 * Used by omp instrumentation
 */
void omp_flush(int numthread){
    char * tmp = actual[numthread];
    actual[numthread] = flushing[numthread];
    flushing[numthread] = tmp;

    if(flushthreads[numthread] != -1)
        pthread_join(flushthreads[numthread], NULL);

    struct thread_arg * t = malloc(sizeof(struct thread_arg));
    t->buf = flushing[numthread]+(uint64_t)((BUFFER_SIZE+BUFFER_MARGIN)*numthread);
    t->size = omp_buff_ptr[numthread];
    t->fd = outfd[numthread];
    pthread_create(&flushthreads[numthread], NULL, &pthread_flush, t);   
    omp_buff_ptr[numthread]= 0;
    
}

/**
 * Used to get the name for the trace file for this file depending on
 * omp : is there shared memory paralellism?
 * mpi : is there distribued memory parallelism?
 * wasinit : has MPI_Init(_threads) been called?
 * rank : rank of MPI process
 * numth : number of omp thread.
 */
char * get_out_filename(bool omp, bool mpi, bool wasinit , int rank, int numth){
	char * name = calloc(strlen(trace_output)+10*2+5, 1);
	strncpy(name, trace_output,strlen(trace_output));
	strcat(name, "out");
	char tmp[11];
	if(mpi){
		int i = 0;
		if(wasinit)
			i = rank;
		else
			i = (int)getpid();
		sprintf(tmp, "_%d", i);
		strcat(name, tmp);
	}
	if(omp){
		sprintf(tmp, "_%d", numth);
		strcat(name, tmp);
	}
	return name;
}
/**
 * flush supposedly called by the deconstructor. In case file descriptors have been closed already, we make sure to open them again.
 */
void final_flush(){//make it open and close every file again.  
    if(omp_max == 1){
        if(flushthreads[0] != -1)
            pthread_join(flushthreads[0], NULL);
		char * trnm = get_out_filename(false, mpi_rank!=-1, mpi_initialized, mpi_rank, 0);
        if((*outfd = open(trnm, O_RDWR ,NULL)) != -1)
            lseek(*outfd,0, SEEK_END);
		else
			printf("could not open file %s\n", trnm);
        flush();
        pthread_join(flushthreads[0], NULL);
        close(*outfd);
    }
    else{
        for(int i = 0; i < omp_max; i++){
            if(flushthreads[i] != -1)
                pthread_join(flushthreads[i], NULL);
			if(omp_buff_ptr[i]>0){
				char * tmp = get_out_filename(true, mpi_rank!=-1, mpi_initialized, mpi_rank,i);
				int error;
				if((error = outfd[i] = open(tmp, O_RDWR ,NULL)) != -1){
					lseek(outfd[i],0, SEEK_END);
					omp_flush(i);
					pthread_join(flushthreads[i], NULL);
					close(outfd[i]);
				}
				else
					printf("error : %s %d \n",strerror(errno), errno);
				free(tmp);
			}
		}
	}
}
/**
 * This function will return the address tramp nb
 * to optimize carefully, will be called by the hook
 */
void * get_tramp(int nb){
	//maximum value for a name is tramp_ (6) + ident (10) + \0 (1) = 17
	char name[32];
	sprintf(name, "tramp_%u", nb);
	//printf("searching for tramp %s\n", name);
	void * tramp;
	if((tramp = dlsym(handler, name)) == NULL){
		puts("tramp not found!");//makes the programm crash.
	}
	return tramp;
}

/**
 * Not called in C. this code will be called each time we enter an
 * instrumented function. The instrumentation in question should be placed here
 */
void in(int id){
	clock_gettime(CLOCK_MONOTONIC, tm);
	//printf("[HOOK] - IN %d, %ld.%ld\n", id, tm.tv_sec, tm.tv_nsec);
	char * tmp = (void *)&id;
	unsigned long int buff = buffer_ptr;
	char * tab = actual[0];
	uint i = 0;
	for (; i < bytes_func_ident; i++)
	{   
		tab[buff]= tmp[i];
		buff ++;
	}
	tmp = (void *) &(tm->tv_sec);
	tab[buff++] = tmp[0];
	tab[buff++] = tmp[1];
	tab[buff++] = tmp[2];
	tab[buff++] = tmp[3];
	tmp = (void *) &(tm->tv_nsec);
	for (i = 0; i < precision_level; i++)
	{
		tab[buff++] = tmp[i];
	}
	buffer_ptr = buff;
	if(buffer_ptr >= BUFFER_SIZE)
		flush();
}
/**
 * Same but is called at exit time.
 */
void out(int id){
	clock_gettime(CLOCK_MONOTONIC, tm);
	//printf("[HOOK] - OUT %d, %ld.%ld\n", id, tm.tv_sec, tm.tv_nsec);
	char * tmp = (void *)&id;
	tmp[bytes_func_ident-1] |= 1 << 7; //set the most significant bit to 1
	char * tab = actual[0];
	unsigned long int buff = buffer_ptr;
	uint i = 0;
	for (; i < bytes_func_ident; i++)
	{   
		actual[0][buff++]= tmp[i];
	}

	tmp = (void *) &(tm->tv_sec);
	tab[buff++] = tmp[0];
	tab[buff++] = tmp[1];
	tab[buff++] = tmp[2];
	tab[buff++] = tmp[3];
	tmp = (void *) &(tm->tv_nsec);
	for (i = 0; i < precision_level; i++)
	{
		tab[buff++] = tmp[i];
	}
	buffer_ptr = buff;
	if(buffer_ptr >= BUFFER_SIZE)
		flush();
}

/**
 * This function is here to check that the omp tread number is not above previous max implementation 
 * (we'd have to) realloc if it was the case.
 */
int check_omp(){
	int i = omp_get_thread_num(); 
	if(i>=omp_max){
		puts("num_thread is above the mumber of cores of this machine");
		exit(1);//make reallocs?
	}
	return i;
}
/**
 * Used by the asm hook
 */
int get_thread_num(){
	return omp_get_thread_num();
}

/**
 * Same as in but for omp programs.
 * It takes a second argument, numthread, in order not to call omp_get_thread_num a second time (to reduce overhead)
 */
void in_omp(int id, int numthread){
	clock_gettime(CLOCK_MONOTONIC, &tm[numthread]);
	//printf("[HOOK] Thread %d - IN %d ( %ld.%ld s)\n",numthread, id,  tm[numthread].tv_sec, tm[numthread].tv_nsec);
	char * tmp = (void *)&id;
	long unsigned int j  = (uint64_t) numthread * (BUFFER_SIZE+BUFFER_MARGIN)+ omp_buff_ptr[numthread];
	char * tab = actual[numthread];
	uint i = 0;
	for (; i < bytes_func_ident; i++)
	{   
		tab[j++]= tmp[i];
	}
	tmp = (void *) &(tm[numthread].tv_sec);
	tab[j++] = tmp[0];
	tab[j++] = tmp[1];
	tab[j++] = tmp[2];
	tab[j++] = tmp[3];
	tmp = (void *) &(tm[numthread].tv_nsec);
	tab[j++] = tmp[0];
	tab[j++] = tmp[1];
	tab[j++] = tmp[2];
	tab[j++] = tmp[3];
	omp_buff_ptr[numthread]+=8+bytes_func_ident;
	if(omp_buff_ptr[numthread] >= BUFFER_SIZE)
		omp_flush(numthread);
}
/**
 * Same but at exit time.
 */
void out_omp(int id, int numthread){
	clock_gettime(CLOCK_MONOTONIC, &tm[numthread]);
	//printf("[HOOK] Thread %d - OUT %d ( %ld.%ld s)\n",numthread, id,  tm[numthread].tv_sec, tm[numthread].tv_nsec);
	char * tmp = (void *)&id;
	tmp[bytes_func_ident-1] |= 1 << 7;
	long unsigned int j  = (uint64_t) numthread * (BUFFER_SIZE+BUFFER_MARGIN) + omp_buff_ptr[numthread];
	char * tab = actual[numthread];
	uint i = 0;
	for (; i < bytes_func_ident; i++)
	{   
		tab[j++]= tmp[i];
	}
	tmp = (void *) &(tm[numthread].tv_sec);
	tab[j++] = tmp[0];
	tab[j++] = tmp[1];
	tab[j++] = tmp[2];
	tab[j++] = tmp[3];
	tmp = (void *) &(tm[numthread].tv_nsec);
	tab[j++] = tmp[0];
	tab[j++] = tmp[1];
	tab[j++] = tmp[2];
	tab[j++] = tmp[3];
	omp_buff_ptr[numthread]+=8+bytes_func_ident;
	if(omp_buff_ptr[numthread] >= BUFFER_SIZE)
		omp_flush(numthread);
}

/**
 * Returns the address of function with symbol "name" from table "sym" 
 * that has header symtabhd, with string table "str_symtab"
 */
uintptr_t get_address(char * name, Elf64_Shdr * symtabhd, Elf64_Sym * sym, char * str_symtab, int * size){
    int i = 0;
    while (i < symtabhd->sh_size /symtabhd->sh_entsize)
    {
        //printf(" -> !%s! !%s!\n", str_symtab + sym[i].st_name, name );
        if(strcmp(str_symtab + sym[i].st_name, name) ==0){
            break;
        }
        i++;
    }
    if(strcmp(str_symtab + sym[i].st_name, name) !=0){//if it's not found:
        printf("Symbol not found! %s\n", name);
        return (uintptr_t)NULL;//TODO: gestion de l'erreur
    }
    *size = sym[i].st_size;
    return (uintptr_t)sym[i].st_value;
}

/**
 * Calls mprotect to make len bytes at address dst in the code section writable
 */
int make_writeable(uintptr_t dst, int len){
    size_t pagesize = sysconf(_SC_PAGESIZE);
    //we will have dst o to write
    uintptr_t end = dst + len + 4;

    //  Calculate start of page for mprotect.
    uintptr_t pagestart = dst & -pagesize;
    //printf("resquested start : %p, real start: %p, end %p, requested len: %d\n", (void *) dst, (void *) pagestart,(void *)   end, len);
    //  Change memory protection.
    if (mprotect((void *) pagestart, end - pagestart,
            PROT_READ | PROT_WRITE | PROT_EXEC))
    {
        perror("mprotect");
        return 1;
    }
    return 0;
}
/**
 * writes code of lenght len to dest
 */
void write_code(unsigned char * code, int len, uintptr_t dest){
    if(!make_writeable(dest, len)){
        unsigned char * dst = (unsigned char *) dest;
        for(int i = 0; i< len; i++){
            dst[i] = code[i];
        }
    }
    //TODO: gestion de l'erreur!
}
//next two function are for debug purposes.
void verify(unsigned char* code, unsigned char * tramp){
    puts("+++++++++++++++++++++++");
    for (size_t i = 0; i < 300; i+= 10)
    {
        printf("%02hhx %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx\n",
        code[i], code[i+1], code[i+2], code[i+3], code[i+4], code[i+5], code[i+6], code[i+7], code[i+8], code[i+9]);
    }
    puts("");
    for (size_t i = 0; i < 300; i+= 10)
    {
        printf("%02hhx %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx\n",
        tramp[i], tramp[i+1], tramp[i+2], tramp[i+3], tramp[i+4], tramp[i+5], tramp[i+6], tramp[i+7], tramp[i+8], tramp[i+9]);
    }
}
void * v(unsigned char* code){
    puts("");
    for (size_t i = 0; i < 50; i+= 5)
    {
        printf("%02hhx %02hhx %02hhx %02hhx %02hhx\n",
        code[i], code[i+1], code[i+2], code[i+3], code[i+4]);
    }
    puts("");
    return code;
}

/**
 * Writes the jump from tramp to "target"
 * Used to write the jump back to the original code in the trampoline.
 */
void write_jump(uintptr_t tramp, uintptr_t target){
    //jmp (%rip)             ff 25 00 00 00 00
    //addr
    unsigned char code[14] = {
        0xff, 0x25, 0x00, 0x00, 0x00, 0x00,
        target, target>>8, target>>16, target>>24,
        target>>32, target>>40, target>>48, target>>56//probably zeroes
    };
    write_code(code, 14, tramp);
}

/**
 * returns the offset of a jump instruction 
 * instr is a string containing the instruction and lenght is the lenght of the instruction.
 */
int32_t getoffset(unsigned char * instr, int lenght){
    int instrsz = 1;
    if(instr[0] == 0x0f)
        instrsz += 1;
    int address = 0;
    if(lenght-instrsz == 1){//8 bit operand size
        int8_t * tmp = (int8_t *) (instr+instrsz);
        address = (int)*tmp+lenght;
    }
    if(lenght-instrsz == 2){//16 bit operand size
        int16_t * tmp = (int16_t *) (instr+instrsz);
        address = (int)*tmp+lenght;
    }
    if(lenght-instrsz == 4){//32 bit operand size
        int * tmp = (int *) (instr+instrsz);
        address = *tmp+lenght;
    }
    return (int32_t) address;
}

/**
 * Tells if a jump instruction lands inside a trampoline.
 * instr is the instruction, size is its size
 * hsize is the total size of the trampoline
 * off is the offset between the start of the tramp and the jump.
 */
bool inside_hook(uint offset, unsigned char * instr, int size, int hsize){
    int hs = hsize>HOOK_SIZE?hsize:HOOK_SIZE;
    int32_t off = getoffset(instr, size);
    return off < 0 && offset + off > 0 && offset + off < hs;
}

/**
 * Tells if the function at adress fct contains a jmp onto the
 * the space overwritten by the hook. If so, returns the offset
 * of this instruction as a int. If not, returns -1
 * size is the size of the function.
 * 
 * if multiple jumps are detected and points inside the hook,
 * or the hook is extended by previous backards jumps, the farthest from the 
 * beginning of the function is returned.
 */
int contains_backards_jump_or_loop(uintptr_t fct, csh handle, cs_insn * insn, int size){
    int n = 0;
    unsigned char * code = (unsigned char *) fct;
    int off_of_bj = -1;
    int size_instr;
    while (n < size && cs_disasm(handle, code+n, HOOK_SIZE, 0x0, 1, &insn)>0)
    {
        size_instr = insn[0].size;
        if(n >= HOOK_SIZE && (is_conditionnal_jump(code+n) || is_jump(code+n))){
            
            if(inside_hook(n, code + n, size_instr, off_of_bj==-1?HOOK_SIZE:off_of_bj)){
                off_of_bj = n + size_instr;
            }
        }//if it's a loop
        if(is_loop(code+n)){
            int off = getoffset(code+n, size_instr);
	    int max = n>n+off?n+size_instr:n+off+size_instr;
            if(max > off_of_bj)
                off_of_bj = max;
        }
        n+=size_instr;
        cs_free(insn, 1);
    }
    return off_of_bj;
}

/**
 * Tells if the jmp instruction "instr" of lenght "lenght" and at "off" bytes from
 * the start of the function of size "size" points inside (false) or outside the function.
 */

bool is_exterior_jump(unsigned char * instr, int lenght, int off, int size){
    int offset_jmp = getoffset(instr, lenght);
    return offset_jmp + off < 0 || offset_jmp + off > size;
}

/**
 * gets an instruction instr describing a relative jump, 
 * the lenght of the instruction as "lenght"
 * 
 * returns a series of instruction describing the same jump but
 * as absolute, and the size of the new instruction in the sz pointer 
 * passed as a parameter
 */
unsigned char * translate_jmp(unsigned char * instr, int lenght, int * sz){
    //take the origin adress, add the offset and the size of the instruction:
    uintptr_t addr = (uintptr_t) instr;
    addr += getoffset(instr, lenght);
    *sz = 14;
    unsigned char * ret = malloc(*sz);
    //jmp (%rip)             ff 25 00 00 00 00
    //addr
    ret[0] = 0xff; ret[1] = 0x25; ret[2] = 0x00; ret[3] = 0x00; ret[4] = 0x00; ret[5] = 0x00; 
    ret[6] = addr; ret[7] = addr>>8; ret[8] = addr>>16; ret[9] = addr>>24; 
    ret[10] = addr>>32; ret[11] = addr>>40; ret[12] = addr>>48; ret[13] = addr>>56;     
    return ret;
}

/**
 * transforms a relative call into an absolute one
 * this is useful if the function we are hooking is 
 * calling another function near it.
 * 
 * off is the offset (argument) of the call
 * addr is the addr of the call instruction.
 * len is used to give the lenght of the newly created call instruction.
 * 
 * Since the tramp is more than 2Gb of memory away, we have to
 * translate this to a 64 bits absolute call.
 */
unsigned char * translate_call(int32_t off, uintptr_t addr, int * len, uintptr_t t){
    int lenght = 19;

    uintptr_t tramp = t + lenght;
    //the adress targeted by the call:
    //addr + 5 is because off is relative to the next instruction
    //+5 reprensents the lenght of the call instruction.
    //we are sure about 5 because we are only re-writing relative immediate calls.
    uintptr_t addr_call = (addr+5) + off;
    //printf("%lx\n", tramp);
    unsigned char * ret = malloc(lenght);
    //PUSHRET not a problem because anyway the call would have done a push.
    //push tramp            0x68 tramp  - 5
    ret[0] = 0x68; ret[1] = tramp; ret[2] = tramp>>8; ret[3] = tramp>>16; ret[4] = tramp>>24;
    //mov dword ptr [rsp+4] tramp>>32   0xc7442404 - 8
    ret[5] = 0xc7; ret[6] = 0x44; ret[7] = 0x24; ret[8] = 0x04;
    ret[9] = tramp>>32; ret[10] = tramp>>40; ret[11] = tramp>>48; ret[12] = tramp>>56;
    //push addr             0x68 addr - 5
    ret[13] = 0x68; ret[14] = addr_call; ret[15] = addr_call>>8;
    ret[16] = addr_call>>16; ret[17] = addr_call>>24;
    //ret                   0xc3 - 1
    ret[18] = 0xC3;

    *len =lenght;
    return ret;
}
/**
 * gets an instruction instr describing a conditionnal jmp
 * the lenght of the instruction as "lenght"
 * 
 * returns a series of instruction describing the same jump but
 * as absolute, and the size of the new instruction in the sz pointer 
 * passed as a parameter
 * 
 * Also transforms 32 bit conditional jumps into 16 bit ones
 */
unsigned char * translate_cond_jmp(unsigned char * instr, int lenght, int * sz){
    *sz = 16;
    unsigned char * tmp = malloc(*sz);
    bool b32 = instr[0] == 0x0f;
    //reverse the condition
    tmp[0] = b32?instr[b32]-0x10:instr[b32];
    tmp[0] = tmp[0]%2==0?tmp[0]+0x01:tmp[0]-0x01;
    //take the absolute adress of the jmp
    uintptr_t addr = (uintptr_t) instr + getoffset(instr, lenght);
    //make the new offset 2 instructions forward
    tmp[1] = 14; //14 for the lenght of the jump.
    //write the absolute jmp after the conditionnal jmp.
    //jmp (%rip)             ff 25 00 00 00 00
    //addr
    tmp[2] = 0xff; tmp[3] = 0x25; tmp[4] = 0x00; tmp[5] = 0x00; tmp[6] = 0x00; tmp[7] = 0x00;
    tmp[8] = addr; tmp[9] = addr>>8; tmp[10] = addr>>16; tmp[11] = addr>>24;
    tmp[12] = addr>>32; tmp[13] = addr>>40; tmp[14] = addr>>48; tmp[15] = addr>>56;
    return tmp;//PUSHRET
}
/**
 * This pass will take the code of the function we overwritten (code),
 * and will write an adapted version into the trampoline (tramp).
 * size is the size of the overwritten function
 * ts is the estimated size of the trampoline (grow up if it contains jumps or loops)
 * 
 * returns the number of rewritten instructions.
 * 
 * Adapted means that every relative call has been converted to absolute call,
 * every jump going outside the part of the function that we overwritten has been
 * transformed to also be absolute.
 * Every such transformation is put inside structure with its address in a tab. 
 * This lets us know where the code is beign extended, and thus enable the 
 * modification of jumps affected inside the trampoline itself.
 * //TODO loops?
 */
int pass_1(unsigned char * code, int size, uintptr_t tramp, csh handle, cs_insn * insn, int ts, int * trs, struct rewrote ** r ){
    int n = 0; unsigned char * tmp; int sz = 0; bool mod; int ws = 0; int ret=0;
    while (n < ts && cs_disasm(handle, code+n, 15, 0x0, 1, &insn) == 1)
    {   mod = false; sz = 0;
        //if there is a jump outside of the predicted size:
        if(is_jump(code+n) && is_exterior_jump(code+n, insn[0].size, n, ts)){
            tmp = translate_jmp(code+n, insn[0].size, &sz);
            mod = true;
        }
        //if there is a conditionnal jump outside of the predicted size:
        if(is_conditionnal_jump(code+n) && is_exterior_jump(code+n, insn[0].size, n, ts)){
            tmp = translate_cond_jmp(code+n, insn[0].size, &sz);
            mod = true;
        }
        //if there is a call outside of the predicted size:
        if(is_call(code+n) && is_exterior_jump(code+n, insn[0].size, n, ts)){
            int32_t * i = (int32_t *)(code+n+1);
            tmp = translate_call(*i, (uintptr_t)(code+n), &sz, tramp+ws);
            mod = true;
        }
        if(mod){//write the code and add the rewrote struct to the list.
            write_code(tmp, sz, tramp + ws);
            *r = realloc(*r, sizeof(struct rewrote)* (ret + 1));
            r[0][ret].offset = ws;
            r[0][ret].size = sz - insn[0].size;
            ret++;
            free(tmp);
            ws += sz;
        }else{//write the legacy code
            write_code(code + n, insn[0].size, tramp + ws );
            ws +=  insn[0].size;
        }
        n += insn[0].size;
        cs_free(insn, 1);
    }
    write_jump(tramp + ws, (uintptr_t) (code+n));
    *trs = ws;
    return ret;
}
/**
 * This function tells if the jump instr at offset bystes from the start of the function
 * with a parameter of param bytes is affected by the re writing of parts of the function
 * because of pass_1
 * rewrote contains the list of those affected parts of the code, len the lenght of the tab.
 * return -1 if the jump is not affected, the lenght that should be added otherwise.
 */
int is_offset_modified(struct rewrote * r, int len, int offset, int param){
    int ret = 0;
    for (size_t i = 0; i < len; i++)
    {
        if(r[i].offset == offset)
            return 0;
        if((offset < r[i].offset && offset + param > r[i].offset )
            || (offset > r[i].offset && offset + param <= r[i].offset+ r[i].size + 2))
                ret += r[i].size;
    }
    return ret;
}

/**
 * This function should be called after pass_1.
 * It is used to make sure all local jmp offset are correct.
 * 
 * code is the code of the trampoline
 * size is the size of said code.
 * struct rewrote is used to know where jumps have been modified.
 * len is the lenght of the rewrote list.
 * 
 */
void pass_2(unsigned char * code, int size, csh handle, cs_insn * insn, struct rewrote * r, int len){
    int n = 0;
    while (n < size && cs_disasm(handle, code+n, 15, 0x0, 1, &insn) == 1)
    {   //if its a jmp (that points inside)
        if((is_jump(code+n) || is_conditionnal_jump(code + n)) && !is_exterior_jump(code+n, insn[0].size, n, size)){
            int tmp = is_offset_modified(r, len, n, getoffset(code+n, insn[0].size));
            if(tmp){//if offset is modified
                bool b32 = insn[0].size>2;
                int inssz = b32?insn[0].size-4:insn[0].size-1;
                if(!b32){
                    int8_t newoff = (int8_t)code[n+inssz];
                    newoff = newoff>0?newoff+tmp:newoff-tmp;
                    code[n+inssz] = (char) newoff;
                }
                else{
                    int32_t newoff = (int32_t)*code+n+inssz;
                    newoff = newoff>0?newoff+tmp:newoff-tmp;
                    code[n+inssz] = (char) newoff; code[n+inssz+1] = (char) newoff>>8;
                    code[n+inssz+2] = (char) newoff>>16; code[n+inssz+3] = (char) newoff>>24; 
                }   
            }
        }
        n += insn[0].size;
        cs_free(insn, 1);
    }
}

/**
 * Writes the code of "tramp_nb" in order restore program's correct behaviour
 * also detect calls instructions in src, and translates them for tramp.
 * also detect jmp, jcc and loop instruction in src, and translates them for tramp
 * 
 * we could use 
 * https://stackoverflow.com/questions/51546206/how-to-tell-length-of-an-x86-64-instruction-opcode-using-cpu-itself
 * makes for extremely light library, but may be long to write.
 * 
 * currently uses capstone, wich is expected to be compiled as an archive
 * in the capstone directory at the root folder.
 */
void write_tramp(uintptr_t src, int size, u_int32_t nb){
    uintptr_t tramp =(uintptr_t) get_tramp(nb);
    //capstone handle
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
		return ;//TODO: error handling
    cs_insn *insn= NULL;
    int ts; 
    unsigned char * code = (unsigned char *)(src);

    if ((ts = contains_backards_jump_or_loop(src, handle, insn, size))  == -1)
        ts = HOOK_SIZE;
    int trs = ts;//the final size of the trampoline
    struct rewrote * list = NULL;
    
    int len = pass_1(code, size, tramp, handle, insn, ts, &trs,&list);
    pass_2((unsigned char *)tramp, trs, handle, insn, list, len);
    free(list);
    if(nb == 458)
        verify(code, (unsigned char *) tramp);
    cs_close(&handle);
}

/**
 * write the necessary instructions to call dest from src.
 * also to push rax and rdi on the stack (so they have to be popped
 * afterwards to avoid a segfault)
 * rdi will be used to give nb to dest.
 */
void write_jump_hook(uintptr_t src, uintptr_t dest, u_int32_t nb){
        //(1) push rax                      - 0x50
        //(3) push rdi                      - 0x57
        //(5) mov edi, nb                   - 0xbf addr
        //(10) mov rax, dest                - 0x48b8 addr
        //(2) jmp rax                       - 0xffe0
        //total = 19...
        unsigned char code[19] = {/*0x50,*/0x90 , 0x57, 0xbf, nb, nb>>8, nb>>16, nb >>24, 0x48, 0xb8, dest, dest>>8, dest>>16, dest>>24, dest>>32, dest>>40, dest>>48, dest>>56, 0xff,0xe0};
        write_code(code, 19, src);
        
        //char code[18] = {0x50, 0xbf, nb, nb>>8, nb>>16, nb >>24, 0x48, 0xb8, dest, dest>>8, dest>>16, dest>>24, dest>>32, dest>>40, dest>>48, dest>>56, 0xff,0xe0};
        //write_code(code, 18, src);
}


/**
 * Makes the necessary changes to the program so that each selected function
 * will call our hook.
 * Also install trampolines so that program behaves normally
 * names is the list of concerned functions, nb the size of the list.
 */
void install_hook(char ** names, int nb, bool omp){
    //we get the handler on the elf object
    Elf * e = get_elf("/proc/self/exe");
    int symtabnb = symtab_nb(e);
    //we get handlers on the sections needed for reading symbols:
    if(symtabnb == -1)
        return;//TODO : implémentation de l'erreur (normalement ça devrait pas arriver)

    Elf_Scn * symtab = elf_getscn(e, symtabnb);
    Elf64_Shdr * symtab_hd = elf64_getshdr(symtab);
    Elf64_Sym * sym = elf_getdata(symtab, NULL)->d_buf;

    Elf_Scn * str_symtab_scn =  elf_getscn(e, symtab_hd->sh_link);
    char * str_symtab_str = (char *) elf_getdata(str_symtab_scn, NULL)->d_buf;
    
    uintptr_t dest = omp?(uintptr_t)omphook:(uintptr_t)hook;
    for(u_int32_t i =0; i < nb; i++){//TODO : pour plus de vitesse on peut paralléliser:
        int size = 0;
        //the adress of the hijacked function:
        uintptr_t src = get_address(names[i], symtab_hd, sym, str_symtab_str, &size);
        //printf("++++++++++++ %s ++++++++++++\n", names[i]); 
        //v((unsigned char *)src);
        write_tramp(src, size, i);
        write_jump_hook(src, dest, i);
        //v((unsigned char *)src);
        //puts("++++++++++++++++++++++++++++");
    }
    elf_end(e);
}
/**
 * Called by our overloaded MPI_Init
 * It is used to rename all output files for the current thread
 * Before the files used pid to identify the process, after it'll be the MPI rank.
 */
void switch_buffers(){
	for(int i = 0; i < omp_max; i++){
		fsync(outfd[i]);//flush data
		close(outfd[i]);
		char * old =  get_out_filename(omp_max > 1, true, false, 0, i);
		char * new = get_out_filename(omp_max > 1, true, mpi_initialized, mpi_rank, i);
		//printf("%s became %s, %d\n",old, new, mpi_rank);	
		rename(old, new);
		if((outfd[i] = open(new, O_WRONLY | O_APPEND)) == -1)//TODO: error handleing
			puts("Could not open output file for MPI process");
	}
}

/**
 * Next two functions are overload of the MPI_Init(_thread) functions.
 * We use this information to know when we can request the rank form th libMPI.
 */
int MPI_Init_thread(int * argc, char ***argv, int required, int * provided){
	int (*orig)(int * argc, char ***argv, int required, int * provided);
	orig = dlsym(RTLD_NEXT, "MPI_Init_thread");
	int ret = (*orig)(argc, argv, required, provided);
	mpi_initialized = true;
	MPI_Comm_rank(MPI_COMM_WORLD, &mpi_rank);
	switch_buffers();
    return ret;
}

int MPI_Init(int *argc, char ***argv){
	int (*orig)(int * argc, char *** argv);
	orig = dlsym(RTLD_NEXT, "MPI_Init");
	int ret = (*orig)(argc, argv);//Maybe a jump would be better?
	mpi_initialized = true;
	int j = 8;
	MPI_Comm_rank(MPI_COMM_WORLD, &j);
	mpi_rank = j;
	switch_buffers();
	return ret;
} 

/**
 * This function is used to create the files used to store the trace
 * As the names of the files changes if omp or mpi are activated
 * they must be passed as parameters.
 */
unsigned int * open_files(bool mpi, bool omp){
	unsigned int * fds = malloc(sizeof(int)*omp_max);
	for(int i = 0; i< omp_max; i++){	
		char * tmp = get_out_filename(omp, mpi, false, 0, i);
		 if((fds[i] = open(tmp, O_RDWR | O_CREAT | O_TRUNC, S_IRWXU)) < 0){
			puts("could not create trace output file");
			free(tmp);
			exit(1);//TODO:error handling
		}
		free(tmp);
	}
	return fds;
}

/**
 * Creates the buffers needed to store the values created by the instrumentation
 * Also open all the file descriptors needed to flush the values to the disk
 * omp is a condition that says if the instrumentation is parallel or sequential.
 */
void init_buffers(bool omp){
    uint64_t sz = omp?(uint64_t)(BUFFER_SIZE+BUFFER_MARGIN)*omp_max:BUFFER_SIZE+BUFFER_MARGIN;
    flushthreads = malloc(sizeof(pthread_t) * omp_max);
	omp_buff_ptr = calloc(omp_max, sizeof(unsigned long int));
    for (size_t i = 0; i < omp_max; i++)
    {
        flushthreads[i] = -1;
    }
    
    buffer1 = calloc(sz, 1);
    buffer2 = calloc(sz, 1);
    if (buffer1 == NULL || buffer2 == NULL){
        fprintf(stderr, "Cannot trace: memory allocated for buffer is too big");
        exit(1);
    }
    actual = malloc(sizeof(int *) * omp_max);
    flushing =  malloc(sizeof(int *) * omp_max);
    for (size_t i = 0; i < omp_max; i++)
    {
        actual[i] = buffer1;
        flushing[i] = buffer2;
    }  
}
/**
 * This function inits the variables used by the assembly code (threadtabsize and lastab)
 * It also sets the max threads possible.
 */
void init_omp(){
    threadtabsize = 400;
    lastab = calloc(1000,8);//8 and not sizeof int because we are using 8 bytes in assembly
	
    omp_max = sysconf(_SC_NPROCESSORS_CONF);
    if(omp_get_max_threads()> omp_max){
        omp_max = omp_get_max_threads();
    }
    //printf("Tracing code as omp with maximum %d threads\n", omp_max);
}

/**
 * Entry point of the library.
 */
__attribute__((constructor))
static void init_lib()
{
    //In case the program is calling other programs: //TODO: just remove the path of the lib.
    unsetenv("LD_PRELOAD");

    /*uintptr_t addr = 0x400000;
    printf("mapped adress: %p\n", mmap((void *)addr, 64, PROT_EXEC | PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_32BIT | MAP_ANONYMOUS, -1 , 0 ));*/

    //we get the handler for the tramp library:
    if((handler = dlopen("/tmp/tramps.so", RTLD_NOW)) == NULL){//absolute or relative?(put it in /tmp...)
        fprintf(stderr, "Cannot trace: unable to find tramps.so");
    }
    //we get the sybols names and number
    int symbol_nb = 0;
    bool omp = false;
    bool mpi =false;
    char ** names;
	precision_level	= 4;
	trace_output = NULL;
	if((names = parse_parameters("/tmp/trace.tmp", &symbol_nb, (int * )&precision_level, &omp, &mpi, &trace_output)) == NULL)
        exit(1);//handle the error
	if(!mpi)
		mpi_rank = -1;
    //printf("number of functions: %d\n", symbol_nb);
    int bits_ident =  32 - __builtin_clz(symbol_nb)+1;//equals to (int)ceil(log2(test)) +1
    bytes_func_ident = bits_ident/8+( bits_ident%8>0);
    //on peut vérifier avec /proc/self/maps qu'on a bien la bonne adresse 0x00400000
    //we install the hook into all concerned symbols:
    if (omp)
        init_omp();
    if (names != NULL){
        install_hook(names, symbol_nb, omp);
        //free names
        init_buffers(omp);
		outfd = open_files(mpi, omp);
        for (int i = 0; i < symbol_nb; i++)
            free(names[i]);

        free(names);
    }
    tm = malloc(sizeof(struct timespec) * omp_max);
	//clock_gettime(CLOCK_MONOTONIC, &tots);
}
void close_files(){
    close(*outfd);
    if(omp_max > 1)
        for (size_t i = 1; i < omp_max; i++)
            close(outfd[i]);
}

__attribute__((destructor))
static void fini()
{
    final_flush();
    close_files();
    free(flushthreads);
    free(trace_output);
    free(tm);
	free(buffer1);free(buffer2);
    free(actual);free(flushing);
    free(omp_buff_ptr);
    free(lastab);
    dlclose(handler);
    //print overall execution time?
    //clock_gettime(CLOCK_MONOTONIC, &tote);
    //const double t = (tote.tv_sec - tots.tv_sec) + (tote.tv_nsec - tots.tv_nsec) / 1000000000.0;
    //printf("Overall program execution time: %lf s\n", t);
    remove("/tmp/trace.tmp");
}
