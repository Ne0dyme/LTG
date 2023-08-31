/**
 *fichier de test pour faire de petites traces séquentielles
*/


#include <unistd.h>
#include <stdlib.h> 
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>

struct timespec tots;
struct timespec tote;
uint * results;
#define SIZE 2000
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
void reset(double * C){
    for (int n = 0; n < SIZE; n++)
        for (int m = 0; m < SIZE; m++)
        {
            C[n * SIZE + m] = 0;
        }
        
    
}
void ddot(double * A,double * B,double *C, int k, int n, int size ){
    for (int m = 0; m < SIZE; m++)
        C[ n * size + m] += A[n * size + k] * B[ k * size + m];
}


void seq(double * A, double * B, double * C){
    for(int n = 0; n< SIZE; n++)
        for (int k = 0; k < SIZE; k++){
            //clock_gettime(CLOCK_MONOTONIC, &tots);
                ddot(A,B, C, k, n, SIZE);
            //clock_gettime(CLOCK_MONOTONIC, &tote);
            //uint64_t end = tote.tv_nsec + tote.tv_sec *1000000000;
            //uint64_t start = tots.tv_nsec + tots.tv_sec *1000000000;
            //uint t = end - start ;
            //results[n]= t;
        }
}
void printresults(){
    for(int n = 0; n< SIZE -1; n++)
        printf("%u,", results[n]);
    printf("%u",  results[SIZE-1]);
    fflush(stdout);
}
double mean(double * A, double * B, double * C){
    double sum = 0;
    for (int i = 0; i < SIZE; i++)
        for (int j = 0; j < SIZE; j++)
            sum += C[i * SIZE + j];
    return sum/(SIZE*SIZE);
}
int main(int argc, char ** argv){
    //clock_gettime(CLOCK_MONOTONIC, &tots);
    double * A = NULL;
    double * B = NULL;
    double * C = NULL;
    A = (double *)malloc(sizeof(double)* SIZE * SIZE);
    B = (double *)malloc(sizeof(double)* SIZE * SIZE);
    C = (double *)malloc(sizeof(double)* SIZE * SIZE);
    results = calloc(SIZE,sizeof(uint));
    int seed = 0;
    if(argc > 1){
        seed = atoi(argv[1]);
    }
    //printf("seed : %d\n", seed);
    init(seed, A, B, C);
    
    //reset(C);
    seq(A, B, C);
    
    printf("result: %f\n", mean(A,B,C));
    //printresults();
    free(results);
    free(A);
    free(B);
    free(C);
    //clock_gettime(CLOCK_MONOTONIC, &tote);
    //const double t = (tote.tv_sec - tots.tv_sec) + (tote.tv_nsec - tots.tv_nsec) / 1000000000.0;
    //printf("time: %g s\n", t);
    return 0;
}
