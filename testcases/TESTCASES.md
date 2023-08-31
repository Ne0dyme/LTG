# Testcases
Under the directory `testcases` you should find some simple example code.
Here is explained how to get a trace for each example code there is.
All files represent a matrix-matrix product. Neither is really optimized.
## Sequential
The first step is to compile the code. This is fairly simple:
`$  gcc seq.c -o example`
If you haven't already, compile the tool and add it to your path:
`$  cd ../traceur/build && make all`
``$  export PATH=$PATH:`realpath ./`  ``
Then come back to the `testcases` folder:
`cd ../../testcases`.

Next, launch the program using the tool:
`$ wrap example`
If you find this too long, simply reduce SIZE in the file `seq.c` and recompile to have smaller matrices.
The last step before seeing a trace is the conversion from our output to the otf2 format:
`$ outtootf`
Then we can just open the trace, for example with vampir:
`$ vampir outotf/trace.otf2`

As you can see, tracing our program produced multiple large files. The size of the files depend on the number of function calls. You should be aware that program execution can fail if you have a disk space quota. 
If this is the case you can tell the wrapper to save the file in a different location, for example in a different filesystem:

`$ wrap -r "your path" example`

## OpenMP
Like before, compile the code:
`gcc omp.c -o example -fopenmp`
Our tool has no option to be compiled without OMP support. If you compiled it before you can use it directly:
`OMP_NUM_THREADS=8 wrap -o example`
`-o` is used to tell the tool you are actually using an OpenMP.
You can see now there is muptiple `out_X` files under `trace.out`, one for each CPU thread. If your number of OpenMP thread is greater than your number of CPU threads, and you do not set the global variable accordingly, this is not supported and the program might (will) crash. If you use fewer threads, some files might be empty, and they will be disregarded in subsequent steps.

Next you can create the OTF2 trace:

`outtootf`
It should tell you how many threads you have used. 
## MPI
MPI support is under development, but you can still create traces with the tool. Don't expect it to work flawlessly thought. You might get errors related to file writing.
Compile:
`mpicc mpi.c -o example`
Run:
`mpirun -np 4 wrap -m example`
Convert:
`outtootf`
If you wish to use MPI and OpenMP simultaneously, there is also a testcase for that:
Compile:
`mpicc ompi.c -o example -fopenmp`
Run:
`OMP_NUM_THREADS=4 mpirun -np 4 wrap -m -o example`
Convert:
`outtootf`
## Only one function or all exept one
If you wish to trace only the ddot function from the testcases for example, you will have to create a `config` file.
It should contain the following lines:
```
+1
ddot
```
You can add any function you wish under ddot if you want them in the trace too.
If you want to trace the program but you don't care about the ddot function, or you feel that tracing it might lead to a big overhead, you can make the config file like so:
```
+2
ddot
```
you can also add any function you do not want on the trace under ddot.
## Inlining issue
If you trace optimized code, there is chances that smaller functions get included in functions calling them.
If this is the case, you won't be able to trace them without deactivating inlining, which would have a negative impact on performance.
If a function is inlined chances are that it is too small to be instrumented (they have to be at least 19 bytes) and/or it is called many times and would have a big impact on overhead (especially if the function is faster than the instrumentation, which is typically around 200-250ns per function call).

