/**
 * Author : Nicolas Ducarton
 * This code is common to different parts of the program.
 * Placing it here is usefull to factorize this code.
 */
#include "readfiles.h"


char * whole_file(char * path){
	FILE * fd;
	if((fd = fopen(path, "r")) <= 0){
		fprintf(stderr, "[TRACE] : Could not open file : %s\n", path);
		return NULL;
	}
	fseek(fd, 0, SEEK_END);
    long fsize = ftell(fd);//get the size of file
    fseek(fd, 0, SEEK_SET);//fp to the start
    //malloc the right size for the string
    char *string = malloc(fsize+1);
	//put file into string
    fread(string, fsize, 1, fd);
    return string;
}
/*********************************************************
 *														 *
 *	     FUNCTIONS TO READ PARAMETER FILE            	 *
 *							 							 *
 *********************************************************/
/**
 * returns an allocated char * that contains the part of the parameter
 * file that contains symbols. It also places the file pointer to the
 * end of that part of the file.
 */
char * get_file_part_with_names(char * file){
	char * tmp = strchr(file,  '\n');
    if(tmp != NULL)
         tmp = strchr(tmp+1, '\n');
    if(tmp != NULL)
         tmp = strchr(tmp+1, '\n');
    if(tmp != NULL)
        tmp = strchr(tmp+1, '\n');
    if(tmp != NULL){
        char * ret = strdup(tmp);
		return ret;
    }
	return NULL;
}
/**
 * gets a string and a int pointer as parameters
 * returns all symbols found in file and the total number in the 
 * int pointer.
 */
char ** get_names(char * file, int * sum){
	char ** names = NULL;//the tab containing the file
	//the file with the names
    char * file_names = get_file_part_with_names(file);
    //the first name:
    char * delim = "\n";
    char * n = strtok(file_names, delim);
    int nb = 0;
    do
    {   //allocate more space into the tab
        if((names = realloc(names, sizeof(char *)*(nb+1))) == NULL)
        	return NULL;//TODO : return null or just get the ones we can?
        //allocate space for the name
        names[nb] = malloc(strlen(n)+1);
        strcpy(names[nb], n);
        names[nb][strlen(n)] = '\0';
        nb++;
    	//while we still have more tokens
    } while ((n = strtok(NULL, delim)) != NULL);
    free(file_names);
    *sum = nb;
	return names;
}
/**
 * Tells from file if omp is activated. file is a string that contains the parameter file.
 */
bool is_omp(char * file){
	char tmp[2];
	tmp[0] = file[0];
	tmp[1]= '\0';
	if(!strcmp(tmp, "1"))
		return true;
	return false;
}
/**
 * Tells from file if mpi is activated. file is a string that contains the parameter file.
 */
bool is_mpi(char * file){
	char * ptr = strchr(file,  '\n');
	char tmp[2];
	tmp[0] = ptr[1];
	tmp[1]= '\0';
	if(!strcmp(tmp, "1"))
		return true;
	return false;
}
/**
 * Tells from file where to store the trace. 
 * file is a string that contains the parameter file.
 */
char * get_output(char * file){
    char * tmp = strchr(file, '\n');
	if(tmp != NULL)
		tmp = strchr(tmp+1, '\n');
	if(tmp != NULL){
		char * tmp2 = strchr(tmp+1, '\n');
		if(tmp2 != NULL){
			char * ret = strndup(tmp+1, tmp2-tmp-1);
			return ret;
		}
	}
	return NULL;
}
/**
 * Used to get precision level from parameter file.
 */
uint8_t get_precision(char * file){
	char * tmp = strchr(file, '\n');
	if(tmp != NULL)
		tmp = strchr(tmp+1, '\n');
	if(tmp != NULL)
		tmp = strchr(tmp+1, '\n');
	if(tmp != NULL){
		char * tmp2 = strchr(tmp+1, '\n');
		if(tmp2 != NULL){
			char * ret = strndup(tmp+1, tmp2-tmp-1);
			int r = atoi(ret);
			if(r>=0 && r < 5 )
				return r;
		}
	}
	return 4;
}
/**
 * Gets all parameters from parameter file. 
 * returns the number of symbols and the symbols in the name pointer.
 * omp and mpi are set if we use those paradigms.
 */
char ** parse_parameters(char * path,int * sum, int * precision, bool * omp, bool * mpi, char ** output){
	char ** names = NULL;
	//get the file in a string
	char *string = whole_file(path);
    *omp = is_omp(string);
    *mpi = is_mpi(string);
    *output = get_output(string);
    names = get_names(string, sum);
    *precision = get_precision(string);
    free(string);
    return names;
}
/*********************************************************
 *							 							 *
 *	     FUNCTIONS TO READ ELF OBJECT FILE               *
 *							 							 *
 *********************************************************/
/**
 * Opens the elf file and verifies that it is an object.
 * returns the elf handler.
 */
Elf * get_elf(char * path){
	Elf * e = NULL;
	int fdexe;
	//checking libelf has a specified version
	if(elf_version(EV_CURRENT) ==  EV_NONE){
		fprintf(stderr ,"Elf version not found\nThere might be an error with libelf");
		return false;
	}
	//open file
	if((fdexe = open(path, O_RDONLY , 0)) < 0){
		fprintf(stderr,"Cannot open %s file \n", path);
		return false;
	}
	//open file within libelf
	if ((e = elf_begin(fdexe, ELF_C_READ , NULL)) == NULL){
		fprintf(stderr,"Elf begin failed : %s\n", elf_errmsg(-1));
		return false;
	}
	//check we have a regular elf executable
	if(elf_kind(e) != ELF_K_ELF){
		fprintf(stderr,"Provided file isn't elf format.\n");
		return NULL;
	}
	return e;
}
/**
 * returns the number of the section containing the symbol table in the
 * Elf file e.
 */	
int symtab_nb(Elf * e){
	Elf_Scn *scn = NULL;
	Elf64_Shdr *shdr64 = NULL;
	int scn_symtab_nb = 0;
	scn = elf_nextscn(e, NULL);//pointer for the first section.
	do{
		shdr64 = elf64_getshdr(scn);//header for this section
		int tmp = elf_ndxscn(scn);//number of the section
		if (shdr64->sh_type == SHT_SYMTAB)
			//we have the number of the section that contains the symbol table.
			scn_symtab_nb = tmp;
	}while ((scn = elf_nextscn(e, scn)) != NULL && !scn_symtab_nb);

	//we check that we have what we need.
	if( scn_symtab_nb == 0){
		fprintf(stderr,"did not find section .symtab. This program does not support stripped executables.");
		return -1;
	}
	return scn_symtab_nb;
}
/**
 * returns the number of the text symbol table  (-1 if not found)
 */
int text_nb(Elf * e){
	int textnb;
	//we get the string table containing section names
	size_t * str = malloc(sizeof(size_t));
	elf_getshdrstrndx(e, str);
	Elf_Scn *strsc = elf_getscn(e,*str);
	free(str);

	Elf_Scn *scn = NULL;
	Elf64_Shdr *shdr64 = NULL;
	char * strsctex = (char *) elf_getdata(strsc, NULL)->d_buf;
	scn = elf_nextscn(e, NULL);//pointer for the first section.
	do{
		shdr64 = elf64_getshdr(scn);//header for this section
		if (shdr64->sh_type == SHT_PROGBITS){//it contains data loaded onto memory
			if(strcmp(strsctex + shdr64->sh_name, ".text") == 0 )
				textnb = elf_ndxscn(scn);
		}
	}while ((scn = elf_nextscn(e, scn)) != NULL && textnb <=0);
	return textnb;
}

/*********************************************************
 *														 *
 *	     FUNCTIONS RELATIVE TO DISSASEMBLY          	 *
 *														 *
 *********************************************************/
bool is_call(unsigned char * instr){
	return instr[0] == 0xe8;
}

bool is_conditionnal_jump(unsigned char * instr){
	return instr[0] == 0xe3 || (instr[0] >= 0x70 && instr[0] <= 0x7f) ||
    (instr[0] == 0x0f && (instr[1] >= 0x80 && instr[1] <= 0x8f));
}

bool is_loop(unsigned char * instr){
	return instr[0] == 0xe0 || instr[0] == 0xe1 || instr[0] == 0xe2;
}

bool is_jump(unsigned char * instr){
	return instr[0] == 0xe9 || instr[0] == 0xeb;
}
