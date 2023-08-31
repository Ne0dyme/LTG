/**
 * Author : Nicolas Ducarton
 */
#include <stdint.h>
#include <fcntl.h>
#include <stdbool.h>
#include <libelf.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
/**
 * We place here every function that appears in more than one file.
 */

char * whole_file(char * path);
/*********************************************************
 *							 *
 *	     FUNCTIONS TO READ PARAMETER FILE            *
 *							 *
 *********************************************************/
char * get_file_part_with_names(char * file);
char ** get_names(char * file, int * sum); 
bool is_omp(char * file);
bool is_mpi(char * file);
char * get_output(char * file);
uint8_t get_precision(char * file);
char ** parse_parameters(char * path,int * sum, int * precision, bool * omp, bool * mpi, char ** output);
/*********************************************************
 *							 *
 *	     FUNCTIONS TO READ ELF OBJECT FILE           *
 *							 *
 *********************************************************/
Elf * get_elf(char * path);
int symtab_nb(Elf * e);
int text_nb(Elf * e);
/*********************************************************
 *							 *
 *	     FUNCTIONS RELATIVE TO DISSASEMBLY           *
 *							 *
 *********************************************************/
bool is_call(unsigned char * instr);
bool is_conditionnal_jump(unsigned char * instr);
bool is_loop(unsigned char * instr);
bool is_jump(unsigned char * instr);

