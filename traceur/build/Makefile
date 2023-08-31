MPICC = mpicc #MAKE SURE IT IS USING GCC
CC = gcc #DO NOT CHANGE THAT
capstone_path = $(realpath ../capstone)
CFLAGS = -Wall
LDFLAGS = -lelf -ldl  -L$(capstone_path)/lib64 -I$(capstone_path)/include -l:libcapstone.a
OTF2_PATH = "none"
libname = lib.so
wrappername = wrap
common_path = $(realpath ./)
INCLUDECOMMON =  -I../libs -L$(common_path) -l:libreadfiles.a

all: lib wrapper otf

utility:
	gcc -c -o libreadfiles.o -O3 -fPIC ../libs/readfiles.c -lelf
	ar rcs libreadfiles.a libreadfiles.o
wrapper: utility
	$(MPICC) $(CFLAGS) -g ../progs/wrapper.c -o $(wrappername) $(INCLUDECOMMON) $(LDFLAGS) 

lib: utility
	$(MPICC) $(CFLAGS) -g -fPIC -shared ../libs/hook.s ../libs/hook.c -o $(libname) $(LDFLAGS) -fopenmp -lm -pthread $(INCLUDECOMMON)
otf: utility
	@if [ $(OTF2_PATH) = "none" ]; then\
		echo "no path specified for OTF2 (OTF2_PATH=...), assuming it is in LD_LIBRARY_PATH";\
		$(CC) $(CFLAGS) -g -O3  -o outtootf ../progs/outtootf2.c -lotf2 -fopenmp -lelf $(INCLUDECOMMON);\
		echo "done";\
	else\
		echo "making outtootf2:";\
		$(CC) $(CFLAGS) -g -O3  -o outtootf ../progs/outtootf2.c -I$(OTF2_PATH)/include -L$(OTF2_PATH)/lib -lotf2 -fopenmp -lelf $(INCLUDECOMMON);\
		echo "done";\
	fi
clean:
	rm -rf ./*.a ./*.o ./*.so ./$(wrappername) ./outtootf ./trace.out 
