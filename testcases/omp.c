/**
 *fichier de test pour faire de petites traces OpenMP
*/
#include <unistd.h>
#include <stdlib.h> 
#include <stdio.h>
#include <string.h>
#include <omp.h>
#include <time.h>
#include <fcntl.h>//open files
#include <pthread.h>
#include <inttypes.h>

#define SIZE 1000    
void init(int seed, double * A, double * B,double * C){
    srand(seed);
    int m,n;
    for(n = 0; n< SIZE; n++ ){
        for (m = 0; m < SIZE; m++)
        {
            A[n * SIZE + m] = rand() %101;
            B[n * SIZE + m] = rand() %101;
            C[n * SIZE + m] = 0;
            
        }
    }
    //puts("init: done");
}
void ddot(double * A, double * B, double *C, int n, int m, int size ){
	for(int k = 0; k< size; k++)
        C[ n * size + m] += A[n * size + k] * B[ k * size + m];    

}
void omp(double * A, double * B, double * C){
    #pragma omp parallel for schedule(static)
    for(int n = 0; n< SIZE; n++)
        for (int m = 0; m < SIZE; m++)
			ddot(A,B, C, n, m, SIZE);           
}

double mean(double * A, double * B, double * C){
    double sum = 0;
    for (int i = 0; i < SIZE; i++)
        for (int j = 0; j < SIZE; j++)
            sum += C[i * SIZE + j];
    return sum/(SIZE*SIZE);
}

int main(int argc, char ** argv){
    double * A = NULL;
    double * B = NULL;
    double * C = NULL;
    A = (double *)malloc(sizeof(double)* SIZE * SIZE);
    B = (double *)malloc(sizeof(double)* SIZE * SIZE);
    C = (double *)malloc(sizeof(double)* SIZE * SIZE);
    int seed = 0;
    if(argc > 1){
        seed = atoi(argv[1]);
    }
    init(seed,A,B, C);
    
    omp(A,B,C);
    printf("result: %f\n", mean(A,B,C));
    free (A);
    free (B);
    free (C);
    return 0;
}
