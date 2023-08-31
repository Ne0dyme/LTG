/**
 *fichier de test pour faire de petites traces omp, comportement récursif, appel systèmes, mpi.
 *pthreads en option
 *mpi+openMP?
*/
#include <mpi.h>
#include <unistd.h>
#include <stdlib.h> 
#include <stdio.h>
#include <string.h>
#include <omp.h>

#define SIZE 2000
int nb = 0; int  N = 0;
int j;
void init(int seed, double ** A , double ** B, double ** C){
    srand(seed);
    *A = (double *)malloc(sizeof(double)* SIZE * SIZE);
    *B = (double *)malloc(sizeof(double)* SIZE * SIZE);
    *C = (double *)malloc(sizeof(double)* SIZE * SIZE);
    int m,n;
    for(n = 0; n< SIZE; n++ ){
        for (m = 0; m < SIZE; m++)
        {
            A[0][n * SIZE + m] = rand() %101;
            B[0][n * SIZE + m] = rand() %101;
        }
    }
}
void reset(double * C){
    for (int n = 0; n < SIZE; n++)
        for (int m = 0; m < SIZE; m++)
        {
            C[n * SIZE + m] = 0;
        }
        
    
}
void ddot(double * A , double * B , double * C, int n, int m ){
	for (int k = 0; k < SIZE; k++)
		C[ n * SIZE + m] += A[n * SIZE + k] * B[ k * SIZE + m];
}

void mpi(double * A , double * B , double * C ){
    for(int n = nb*(SIZE/N); n< (nb+1)*(SIZE/N)&& n<SIZE; n++)
		#pragma omp parallel for
		for (int m = 0; m < SIZE; m++)
			ddot(A, B, C, n, m);
}
double sum(double * C){
    double sum = 0;
    for(int n = nb*(SIZE/N); n< (nb+1)*(SIZE/N); n++)
        for (int j = 0; j < SIZE; j++)
            sum += C[n * SIZE + j];
    return sum;
}

int main(int argc, char ** argv){
    double * A = NULL;
    double * B = NULL;
    double * C = NULL;
    MPI_Comm comm = MPI_COMM_WORLD;
    int garbage = 0;
	MPI_Init_thread(&argc, &argv, MPI_THREAD_FUNNELED, &garbage);
    MPI_Comm_rank(comm, &nb);
    MPI_Comm_size(comm, &N);
    int seed = 0;
    if(argc > 1){
        seed = atoi(argv[1]);
    }
    if (nb == 0)
        printf("seed : %d\n", seed);
	printf("omp max :%d\n",omp_get_max_threads());	
    init(seed, &A, &B, &C);    
	puts("init done"); 
    MPI_Barrier(comm);
    
    mpi(A, B, C);
    
    MPI_Barrier(comm);

    double r = sum(C);
    double rec = 0;
    //printf("indv sum %d\n", sum);
    MPI_Reduce(&r, &rec, 1, MPI_DOUBLE, MPI_SUM, 0, comm);

    if(nb==0)
        printf("result: %f\n", rec/(SIZE*SIZE));
    //reset();
    //mpiX();
    MPI_Finalize();
}
