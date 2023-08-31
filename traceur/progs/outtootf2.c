/**
 * Author : Nicolas Ducarton
 * Takes a generic trace from the tool as input and makes it into an OTF2 trace
 */
#define _XOPEN_SOURCE 700
#include <string.h>//strcmp, strchr
#include <ftw.h>
#include <stdio.h> //frpintf,stderr
#include <fcntl.h>//open files
#include <stdlib.h> //malloc
#include <unistd.h> //write
#include <errno.h>
#include <otf2/otf2.h>
#include <time.h>
#include "readfiles.h"

OTF2_Archive* archive;
OTF2_EvtWriter** evt_writer;
OTF2_GlobalDefWriter* global_def_writer;
int nbsymbol;
int nullstring;
int norm;
int prec;

static OTF2_FlushType
pre_flush( void*            userData,
           OTF2_FileType    fileType,
           OTF2_LocationRef location,
           void*            callerData,
           bool             final )
{
    return OTF2_FLUSH;
}

static OTF2_FlushCallbacks flush_callbacks =
{
    .otf2_pre_flush  = pre_flush,
    .otf2_post_flush = NULL
};

/**
 * This function will initialize necessary data structure in order to write the otf2 trace.
 */
void  init_OTF2(char * outdir, char * name, int nbprocs, int * nbthread){
	int total_threads = 0;
	for(int i  = 0; i < nbprocs; i++)
		total_threads += nbthread[i]; 
    evt_writer = malloc(sizeof(OTF2_EvtWriter *) * total_threads);
    archive = OTF2_Archive_Open(outdir,
                                name,
                                OTF2_FILEMODE_WRITE,
                                1024 * 1024 /* event chunk size */,
                                4 * 1024 * 1024 /* def chunk size */,
                                OTF2_SUBSTRATE_POSIX,
                                OTF2_COMPRESSION_NONE );
    if(archive == NULL)
        puts("could not initialize OTF2");
    OTF2_Archive_SetFlushCallbacks( archive, &flush_callbacks, NULL );
    OTF2_Archive_SetSerialCollectiveCallbacks( archive );//valid with MPI?
    OTF2_Archive_OpenEvtFiles( archive );
    for(int i = 0; i< total_threads; i++) 
        evt_writer[i] = OTF2_Archive_GetEvtWriter( archive, i);
    global_def_writer = OTF2_Archive_GetGlobalDefWriter( archive );
}

void end_OTF2(int nbprocs, int *nbthread){
	int total_threads = 0;
	for(int i  = 0; i < nbprocs; i++)
		total_threads += nbthread[i]; 	
    for (int i = 0; i < total_threads; i++)
        OTF2_Archive_CloseEvtWriter( archive, evt_writer[i] );
    OTF2_Archive_CloseEvtFiles( archive );
    OTF2_GlobalDefWriter_WriteSystemTreeNode( global_def_writer,
                                              0 /* id */,
                                              nullstring /* name */,
                                              0 /* class */,
                                              OTF2_UNDEFINED_SYSTEM_TREE_NODE /* parent */ );
	int locationID= 0;
	for(int i = nbsymbol; i < nbprocs+nbsymbol; i++){
		OTF2_GlobalDefWriter_WriteLocationGroup( global_def_writer,
												 i-nbsymbol /* id */,
												 i /* name */,
												 OTF2_LOCATION_GROUP_TYPE_PROCESS,
												 0 /* system tree */);

	    for(int j = nbsymbol+nbprocs; j < nbsymbol+nbprocs+nbthread[i-nbsymbol]; j++ ){
			OTF2_GlobalDefWriter_WriteLocation( global_def_writer,
											locationID++ /* id */,
											j /* name */,
											OTF2_LOCATION_TYPE_CPU_THREAD,
											2 /* # events */,
											i-nbsymbol /* location group */ );
		}
	}
    OTF2_Archive_Close( archive );
    free(evt_writer);
}

int remove_file(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    int rv = remove(fpath);

    if (rv)
        puts("could not remove previous trace");
    return rv;
}

/**
 * destroys the files where we want to create our new trace.
 * we need that because otherwise otf2 is unhappy.
 */
void remove_previous_trace(char * dir){
    nftw(dir, remove_file, 64, FTW_DEPTH | FTW_PHYS);
}

/**
 * This function will create otf2 "strings"
 * the first strings will associate a function name and its id.
 * Then we have an empty string for the definitions we don't want to set.
 * At the end we have te thefinitions for each thread.
 */
void create_strings(char ** names, int nbprocs, int *nbthread){
	int maxthreads = 0;
	for(int i = 0; i < nbsymbol; i++)
		OTF2_GlobalDefWriter_WriteString( global_def_writer, i, names[i] );

	for (int i = 0; i < nbprocs; i++){
		char buf[20];
		sprintf(buf, "Process %d", i);
        OTF2_GlobalDefWriter_WriteString( global_def_writer, i+nbsymbol, buf);
		if(maxthreads < nbthread[i])
			maxthreads = nbthread[i];
	}

    for (int  i = 0; i < maxthreads ; i++)
    {
        char buf[20];
        sprintf(buf, "Thread %d", i);
		OTF2_GlobalDefWriter_WriteString( global_def_writer, nbsymbol+nbprocs+i, buf);
    }
    nullstring = nbsymbol+nbprocs+maxthreads;
    OTF2_GlobalDefWriter_WriteString(global_def_writer, nullstring, "" );
}

/**
 * This method will create otf2 "regions".
 * Each region corresponds to a function. It defines its name
 * the id of the region is the id of the corresponding function.
 */
void create_regions(){
    for(int i = 0; i< nbsymbol; i++)
        OTF2_GlobalDefWriter_WriteRegion( global_def_writer,
                                    i /* id */,
                                    i /* region name  */,
                                    nullstring /* alternative name */,
                                    nullstring /* description */,
                                    OTF2_REGION_ROLE_FUNCTION,
                                    OTF2_PARADIGM_USER,
                                    OTF2_REGION_FLAG_NONE,
                                    0 /* source file */,
                                    0 /* begin lno */,
                                    0 /* end lno */ );

}
/**
 * Translate 3 32 bit integers to an otf2 event.
 * The three integers must be passed in the line pointer.
 */
void translate_line(int id, int ids, int  sec, int nsec, u_int64_t n1, u_int64_t n2, int generalthreadid){
    int dec = ids*8;
    bool b = id >> (dec-1);
    //reset the most significant bit.
    dec = 33-dec;
    id = id<<(dec);id = id>>(dec);
    uint64_t t= (sec-n1)*1000000000 + (nsec - n2);
    if(!b){
        OTF2_EvtWriter_Enter( evt_writer[generalthreadid],
                NULL,
                t,
                id /* region */ );
    }
    else{
        OTF2_EvtWriter_Leave( evt_writer[generalthreadid],
                NULL,
                t,
                id /* region */ );
    }
}

void printoutput(int id, int ids, int sec, int nsec, int proc, int th){
    bool b = id >> (ids*8-1);
    //reset the most significant bit.
    id = id<<(33-ids*8);id = id>>(33-ids*8);
    if(!b)
        printf("PROC %d thread %u: IN - %u:\t %d,%d s\n",proc, th, id, sec, nsec);
    else
        printf("PROC %d thread %u: OUT - %u:\t %d,%d s\n", proc, th, id, sec, nsec);
}
void free_names(char ** names){
    for (int i = 0; i < nbsymbol; i++)
        free(names[i]);
    free(names);
}

int nbf = 0;
char ** mpi_names;
int * omp_per_mpi;

int incr (const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    if(typeflag ==FTW_F && sb->st_size > 0 && strstr(fpath, "out_") != NULL) 
        nbf++;
    return 0;
}

bool gmpi;
bool gomp;
int nbmpi = 0;

void treat_first_token(char * tok){
	if(gmpi){
		bool found = false;
		for(int i = 0; i < nbmpi; i++){
			if(strcmp(tok, mpi_names[i]) == 0){
				if(gomp){				
					omp_per_mpi[i]++;
				}
				else{
					puts("error in files : found multiple files for mpi process");	
				}
				found = true;
			}
		}
		if(!found){
			mpi_names[nbmpi++] = strdup(tok);
			omp_per_mpi[nbmpi-1] = 1;
		}
	}
	else{
		omp_per_mpi[0]++;
	}
}

int check_files (const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    if(typeflag ==FTW_F && sb->st_size > 0 && strstr(fpath, "out_") != NULL){
		char * tmp = strdup(fpath); 
		tmp = strtok(tmp , "_");
		tmp = strtok(NULL, "_");
		treat_first_token(tmp);
	}
	return 0;
}



/**
 * Used to check wether a call to MPI_Init was made in the trace.
 * This changes the names of the output files.
 * Basically it searches for a file named out_0 (MPI) or out_0_0 (MPI + OpenMP)
 * We assume we are not tracing the scheduler so a pid of 0 is not possible.
 * Then if the file exists it means MPI was initialized.
 */
bool was_init(){
	char file[strlen(".trace.out/out_0")+2];
	strcpy(file, ".trace.out/out_0");
	if(access(file, F_OK))
		return true;
	strcat(file, "_0");
	if(access(file, F_OK))
		return true;
	return false;
}

//TODO: add parameter search for input and ouptut
int * open_files(bool omp, bool mpi, int ** nbt, int * nbp ){
	int * outfd;
	if(!omp && !mpi){
        char * file = "./trace.out/out";
        outfd = malloc(4);
        //we open the out file
        if((outfd[0] = open(file, O_RDONLY, 0)) < 0){
            fprintf(stderr, "could not open file %s", file);
            return NULL;
        }
		*nbp = 1;
		*nbt = malloc(sizeof(int));
		*nbt[0]= 1;
        return outfd;
	}

    nftw("./trace.out", incr, 64, FTW_PHYS);
    mpi_names = malloc(sizeof(char *)* nbf);
	omp_per_mpi = calloc(nbf, sizeof(unsigned int));
	outfd = malloc(sizeof(int)* nbf);
    nftw("./trace.out", check_files, 64, FTW_PHYS);

	char tmp[strlen("./trace.out") +26];
	int tabind = 0;
    for(int i = 0; i < (nbmpi>0?nbmpi:1); i++)
		for(int j = 0; j<(omp_per_mpi[i]>0?omp_per_mpi[i]:1); j++){
			if(mpi && omp)
				sprintf(tmp, "%s/out_%s_%d", "./trace.out", mpi_names[i], j);
			else
				sprintf(tmp, "%s/out_%d", "./trace.out", mpi?i:j);
			printf("opening : %s\n",tmp);	
			if((outfd[tabind++] = open(tmp, O_RDONLY)) == -1 )
				puts("error opening trace files to convert");
		}
	*nbt = omp_per_mpi;
	*nbp = nbmpi>0?nbmpi:1;
    return outfd;
}

u_int64_t readfile(int fdout, int numproc, int numthread, int thid, int starts, int startns, u_int8_t eventsize){
    char buff[eventsize*300];
    int count = 0;
    int i;
    count = read(fdout, buff, eventsize*300);
    u_int32_t mask =  4294967295 >> (32 - ((eventsize - (4+prec))*8));
    //u_int32_t maskns =  4294967295 << (32 - ((prec)*8));//delete that
    u_int32_t * tmp = (void *) buff + eventsize -(4+ prec);
    u_int32_t n1 = starts?starts:*tmp;
    tmp = (void *) buff + eventsize - prec;
    u_int32_t n2 = startns?startns:*tmp;// & maskns;
    u_int32_t id; void * off;
    int soff = eventsize-(8);
    do{
        for(i = 0; i< count; i+= eventsize ){
            off = buff + i;
            tmp = off;
            id = *tmp & mask;
            u_int32_t nstmp = *((int*)(off+soff+4));// & maskns;
            //printoutput(id, soff, *((int*) (off+soff)),nstmp, numproc, numthread);
            translate_line(id, soff,  *((int*) (off+soff)),nstmp, n1, n2, thid);
        }
    }while ((count = read(fdout, buff, eventsize*300) ) > 0);//TODO: async to improve trace generation time
    lseek(fdout, -(4+prec), SEEK_END);
    read(fdout, buff, 4+prec);
    tmp = (void *) buff;
    u_int64_t te = (u_int32_t)*tmp;
    tmp = (void *)buff+4;
    u_int64_t ts = (u_int64_t)n1;
    te *= 1000000000;
    ts *= 1000000000;
    te += *tmp; //&maskns;
    ts += n2;
    u_int64_t lenght = te - ts;
    //printf("len %lu , ss %u, sn %u, es %u en %u\n s %lu e %lu\n", lenght, n1, n2 , buff[0], buff[1], ts, te);
    //printf("lene %lu\n",ts);
    //printf("lens     %lu\n",te);
    return lenght;
}

void check_minimum(int * fd, int nb, int * sec, int * nsec, u_int8_t eventsize){
	char buff[eventsize];
    *sec = -1; *nsec = -1;
    int32_t * tmpsec,* tmpnsec;
    u_int32_t mask =  4294967295 >> (32 - ((prec)*8));
    for(int i = 0; i< nb; i++){
        lseek(fd[i], 0, SEEK_SET);
        read(fd[i], buff, eventsize);
        tmpsec = (void *) buff+eventsize-(4+prec);
        tmpnsec = (void *) buff+eventsize-prec; 
        int fnsec = *tmpsec & mask;
        if(*tmpsec<*sec || *sec == -1 ) {
            *sec = *tmpsec;
            *nsec = fnsec;
        }
        if(*tmpsec == *sec && *tmpnsec<*nsec)
            *nsec = fnsec;
        lseek(fd[i], 0, SEEK_SET);  
    }
}

u_int64_t readfiles(int * fd, int nbp, int * nbt, int nbo){
	int total = 0;
	for(int i = 0; i< nbp; i++)
		total += nbt[i];
    u_int64_t * lenghtab = malloc(sizeof(u_int64_t) * total);
    int starts = 0; int startns = 0;
    check_minimum(fd, total, &starts, &startns, nbo);
    //#pragma omp parallel for//TODO: better paralelization.
    for(int i = 0; i< total; i++)
		lenghtab[i] = readfile(fd[i], 0, 0, i, starts, startns, nbo);
    u_int64_t max = 0;

    for (int i = 0; i < total; i++)
        if(lenghtab[i]> max)
            max = lenghtab[i];

    free(lenghtab);
    return max;
}

void translate_out(char * dir, char * out){
    bool omp = false;
	bool mpi = false;
	nbsymbol = 0;
	prec = 4;
	char * output = NULL;
    char ** names = parse_parameters("trace.out/names", &nbsymbol, &prec, &omp, &mpi, &output);
	free(output);
	gmpi = mpi; gomp = omp;
    int * nbthreads = NULL;
	int nbprocs = 0;
	int * files = open_files(omp, mpi, &nbthreads, &nbprocs);
    printf("creating trace with %d processes\n", nbprocs);
	for(int i = 0; i< nbprocs; i++)
		printf("\tprocess %d has %d threads\n", i, nbthreads[i]);
    init_OTF2(dir, out, nbprocs, nbthreads);
    create_strings(names, nbprocs, nbthreads);
    create_regions();
    
    u_int64_t lenght;
    u_int8_t nbbits = 32 - __builtin_clz(nbsymbol)+1;
    u_int8_t nbo = nbbits/8+(nbbits%8>0);
    if (omp || mpi){
        lenght = readfiles(files, nbprocs, nbthreads, nbo+4+prec);
    }else{
        lenght = readfile(files[0], 0, 0, 0, 0,0, nbo+4+prec);
    }
    OTF2_GlobalDefWriter_WriteClockProperties( global_def_writer,
                                            1000000000 /* ns */,
                                            0 /* epoch */,
                                            lenght /* length */  );
    free_names(names);
    end_OTF2(nbprocs, nbthreads);
	free(nbthreads);
}

int main(int argc, char ** argv){
    char * file = "trace";
    char * dir = "outotf";

    struct timespec tots;
    struct timespec tote;

    remove_previous_trace(dir);    
    clock_gettime(CLOCK_MONOTONIC, &tots);
    translate_out(dir, file);
    clock_gettime(CLOCK_MONOTONIC, &tote);

    const double t = (tote.tv_sec - tots.tv_sec) + (tote.tv_nsec - tots.tv_nsec) / 1000000000.0;
    printf("time: %g s\n", t);

    return EXIT_SUCCESS;


}
