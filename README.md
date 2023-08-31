# Lightweight Trace Generator 
The goal of this tool is to enable you to easily observe how your program behaves, without needing any recompilation, source code annotations, or binary modifications.
It is limited to x86_64 architectures under Linux, and has been tested with C, C++ and Frotran 90 code compiled with GNU compilers. It is designed to be compatible with any language/compiler that produces an ELF binary.
It supports HPC paradigms such as MPI and OpenMP (simultaneously). It does not support POSIX threads.
The output of the tool is an **OTF2** trace, which can be viewed with specialized tools like [ViTE](https://solverstack.gitlabpages.inria.fr/vite/index.html) or [Vampir](https://vampir.eu/).
# Building & dependencies
## Dependencies
Minimizing dependencies is one of the project's goal. But there is still some prerequisites required to build the project:
To build, you'll need to have the following installed:

* `libc`
* `libelf`
* `gcc > 8.1`
* `OpenMP`
* `MPI`
* `libotf2` (optionnal). 

If you don't have OTF2, you will be able to create traces, but not to convert them to OTF2.
This is useful especially if you are working on two machines, and the one you are using to run your project is missing the dependency.
The trace generator is using capstone in order to disassemble the traced program, but it is compiled under the "capstone" directory and statically linked when building.
## Building
The project is built via a Makefile that is found under "traceur/build".
If you are using a custom build of OTF3, you can give its path to make by using the command line argument `OTF2_PATH=` followed by the directory where it is installed.
The Makefile expects to have `include` and `lib`  subdirectories inside the path.
The compiled files are created inside the build directory. You can move them somewhere else (but leave them together) or add the directory to your `PATH` as you wish.

``export PATH=$PATH:`realpath ./`  ``

# Creating your first trace
If you wish to directly try it, there are some examples given under the `testcases` subdirectory.
## Options for the wrapper
The wrapper `wrap` is the file you'll interact with. It's main goal is to start your program while injecting a custom library in it using the `LD_PRELOAD` environment variable.

To start your program while tracing it you need to place the tracer before the name of your program on the command line:

`$ ./my_program --option1 toto --option2 tata`

becomes

`$ wrap ./my_program --option1 toto --option2 tata`

This works for sequential code but if you intend to use MPI you'll need to inform the wrapper via the `-m` option:

`$ mpirun -np 8 my_program --option1 toto --option2 tata`

becomes

`$ mpirun -np 8 wrap -m ./my_program --option1 toto --option2 tata`

You also need to inform the wrapper if you are using OpenMP with `-o`.

Below is a list of options with arguments and explanations:

|OPTION   | ARGUMENT    |EXPLANATION                  |
|---------|-------------|-----------------------------|
|-o		  |None			|Activate omp instrumentation |
|-m       |None         |Activate mpi instrumentation |
|-r       |A path		|Directory where to write the trace (working directory by default) |
|-c       |A path		|Directory where to search for config file, by default : "./config"|

## Configuration file
If you wish to trace only a few functions of your program or all functions except a few, it is possible thanks to a configuration file.

Its format is fairly simple, you just have to paste function names (without brackets) in it at the right place. Function names are separated by line breaks (one function name on each line).

```
+1 functions you want to include
function_name_1
function_name_2
+2 functions you want to exclude
function_name_3
function_name_4
```

You cannot simultaneously include and exclude functions. By default, all functions are included, if you give some names under the +1 delimiter, only the included functions will be traced.
If you give something under +1, the functions under +2 are ignored.

If you wish to trace every function except specific ones, the function names you do not want in the trace should be placed under +2
In the above example, the tool will only trace `function_name_1` and `function_name_2`.
 `function_name_3` and `function_name_4` are ignored.
## Getting an OTF2 trace
Once your program is terminated, you should be left with a directory named `trace.out/`.
It contains files you cannot (yet) read.
To get an OTF2 trace, simply run `outtootf` on the parent directory of `trace.out/`.
This should create a `outotf` directory. This contains your OTF2 trace. You can now delete `trace.out/`, as it can take a lot of disk space.
To read the trace you should open `outotf/trace.otf2` with a tool of your choice.
# Functions that cannot be traced
You cannot trace function smaller than 19 bytes (~4/5 instructions).
You cannot trace functions that use a global variable in it's first 19 bytes or in a loop beginning at the start of the function.
