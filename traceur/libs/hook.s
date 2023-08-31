#Author : Nicolas Ducarton
#This file handles the rediirections from the traced program when it is running.
    .data
    .globl last
    .type	last, @object
    .size	last, 8
last:
	.zero	8

    .globl threadtabsize
    .type  threadtabsize, @object
    .size  threadtabsize, 8
threadtabsize:
    .zero 8

    .globl lastab
    .type  lastab, @object
    .size  lastab, 8
lastab:
    .zero 8
    # global variables we need. TODO: modify the size dynamically? or add a check.
    .comm ident,80000,4
    .comm stack,160000,8 # if we have more than 12 threads it crashes
    # C function that we have to call
    .globl in
    .globl out
    .globl in_omp
    .globl out_omp
    .globl get_tramp
    .globl check_omp
    .globl get_thread_num
    .type in, @function
    .type out, @function
    .type get_tramp, @function
    .type check_omp, @function
    .type get_thread_num, @function
    # make global variables visible for out C function.
    .globl ident
    .globl stack
    .globl hook
    .globl omphook
    .text
    # TODO: optimize this function the best we can.
hook:
    
    #  we get the adress of the calling function
    movq 0x8(%rsp),%rax # later we will have to pop rsp+8
    # we push the registers we want to save on the stack.
    # parameters:
    push %rsi
    push %rdx
    push %rcx
    push %r8
    push %r9
    push %r10
    push %r11
    movq %xmm0,-0x8(%rsp);movq %xmm1,-0x10(%rsp);
    movq %xmm2,-0x18(%rsp);movq %xmm3,-0x20(%rsp);
    movq %xmm4,-0x28(%rsp);movq %xmm5,-0x30(%rsp);
    movq %xmm6,-0x38(%rsp);movq %xmm7,-0x40(%rsp);
    sub  $0x40,%rsp
    # technically we should save mmx0 to 7 and st 0 to 7
    
    # we save the value of the calling function:
    movq last@GOTPCREL(%rip),%rdx
    movq (%rdx),%rsi
    addq $1,%rsi
    movq %rsi,(%rdx)


    movq ident@GOTPCREL(%rip),%r8
    movl %edi,(%r8,%rsi,4)

    movq stack@GOTPCREL(%rip),%rcx
    movq  %rax,(%rcx,%rsi,8)

    push %rdi

    # we do our instrumentation:  
    call in  
    
    pop %rdi
    # we search for our trampoline:(not sure we have to get the values again)
    call get_tramp

    add $0x40,%rsp
    # we pop our values and we return to the tramp
    movq -0x8(%rsp),%xmm0;movq -0x10(%rsp),%xmm1;
    movq -0x18(%rsp),%xmm2;movq -0x20(%rsp),%xmm3;
    movq -0x28(%rsp),%xmm4;movq -0x30(%rsp),%xmm5;
    movq -0x38(%rsp),%xmm6;movq -0x40(%rsp),%xmm7;
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rcx
    pop %rdx
    pop %rsi
    pop %rdi
    add $8,%rsp
    # call to the tramp
    call *%rax

    push %rax
    push %rdi
    push %rsi
    push %rdx
    push %rcx
    push %r8
    push %r9
    push %r10
    push %r11
    movq %xmm0,-0x8(%rsp);movq %xmm1,-0x10(%rsp);
    movq %xmm2,-0x18(%rsp);movq %xmm3,-0x20(%rsp);
    movq %xmm4,-0x28(%rsp);movq %xmm5,-0x30(%rsp);
    movq %xmm6,-0x38(%rsp);movq %xmm7,-0x40(%rsp);
    sub  $0x40,%rsp
    
    # get the stack value
    movq last@GOTPCREL(%rip),%rax
    movq (%rax),%rdx

    # identifier for function
    movq ident@GOTPCREL(%rip),%rcx
    movl (%rcx,%rdx,4),%edi

    # value of return address
    movq stack@GOTPCREL(%rip),%r8
    movq (%r8,%rdx,8),%r8
    push %r8

    subq $1,%rdx
    movq %rdx,(%rax)

    # we do our instrumentation:  
    call out
    # add  $8,%rsp

    add $0x48,%rsp
    movq -0x8(%rsp),%xmm0;movq -0x10(%rsp),%xmm1;
    movq -0x18(%rsp),%xmm2;movq -0x20(%rsp),%xmm3;
    movq -0x28(%rsp),%xmm4;movq -0x30(%rsp),%xmm5;
    movq -0x38(%rsp),%xmm6;movq -0x40(%rsp),%xmm7;
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rcx
    pop %rdx
    pop %rsi
    pop %rdi
    pop %rax

    # store rax
    movq %rax,-0x10(%rsp)
    mov -0x90(%rsp),%rax
    push %rax
    
    # restore rax
    movq -0x8(%rsp),%rax

    ret
    
omphook:
    
    #  we get the adress of the calling function
    movq 0x8(%rsp),%rax # later we will have to pop rsp+8
    # we push the registers we want to save on the stack.
    # parameters:
    push %rsi
    push %rdx
    push %rcx
    push %r8
    push %r9
    push %r10
    push %r11
    movq %xmm0,-0x8(%rsp);movq %xmm1,-0x10(%rsp);
    movq %xmm2,-0x18(%rsp);movq %xmm3,-0x20(%rsp);
    movq %xmm4,-0x28(%rsp);movq %xmm5,-0x30(%rsp);
    movq %xmm6,-0x38(%rsp);movq %xmm7,-0x40(%rsp);
    sub  $0x40,%rsp
    # technically we should save mmx0 to 7 and st 0 to 7
    push %rdi
    push %rax
    call check_omp
    movq %rax, %rsi
    
    # get the value of the stack size for the thread.
    movq lastab@GOTPCREL(%rip),%rcx
    movq (%rcx),%rcx
    # increment it
    movq (%rcx,%rax,8), %rdi
    add $1,%rdi
    movq %rdi,(%rcx,%rax,8)
    # get the index of the values we want to use.
    movq threadtabsize@GOTPCREL(%rip),%r8
    movq (%r8),%r8
    mul %r8 # size of tab per thread * n° of the thread.
    add %rdi, %rax # base of our index + stack size.

    pop %r8

    # save the return address of the function
    movq stack@GOTPCREL(%rip),%r10
    movq  %r8,(%r10,%rax,8)

    movq (%rsp),%rdi
    # save the identifier of the function
    movq ident@GOTPCREL(%rip),%r9
    movl %edi,(%r9,%rax,4)

    # we do our instrumentation:    
    call in_omp

    pop %rdi
    call get_tramp

    add $0x40,%rsp
    # we pop our values and we return to the tramp
    movq -0x8(%rsp),%xmm0;movq -0x10(%rsp),%xmm1;
    movq -0x18(%rsp),%xmm2;movq -0x20(%rsp),%xmm3;
    movq -0x28(%rsp),%xmm4;movq -0x30(%rsp),%xmm5;
    movq -0x38(%rsp),%xmm6;movq -0x40(%rsp),%xmm7;
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rcx
    pop %rdx
    pop %rsi
    pop %rdi
    add $8,%rsp
     
    # call to the tramp
    call *%rax

    push %rax
    push %rdi
    push %rsi
    push %rdx
    push %rcx
    push %r8
    push %r9
    push %r10
    push %r11
    movq %xmm0,-0x8(%rsp);movq %xmm1,-0x10(%rsp);
    movq %xmm2,-0x18(%rsp);movq %xmm3,-0x20(%rsp);
    movq %xmm4,-0x28(%rsp);movq %xmm5,-0x30(%rsp);
    movq %xmm6,-0x38(%rsp);movq %xmm7,-0x40(%rsp);
    sub  $0x40,%rsp

    call get_thread_num
    movq %rax, %r8

    movq lastab@GOTPCREL(%rip),%r9
    movq (%r9),%r9
    movq (%r9,%r8,8), %rcx

    # get the index of the values we want to use.
    movq threadtabsize@GOTPCREL(%rip),%r10
    movq (%r10),%r10
    mul %r10 # size of tab per thread * n° of the thread. #TODO: mulx not mul (preserve EFLAGS)
    add %rcx, %rax # base of our index + stack size.

    # sub 1 to stack size.
    sub $1,%rcx
    movq %rcx,(%r9,%r8,8)

    
    movq ident@GOTPCREL(%rip),%rcx
    movl (%rcx,%rax,4),%edi

    mov %r8, %rsi

    movq stack@GOTPCREL(%rip),%rcx
    movq (%rcx,%rax,8),%rax

    push %rax

    call out_omp

    add $0x48,%rsp
    movq -0x8(%rsp),%xmm0;movq -0x10(%rsp),%xmm1;
    movq -0x18(%rsp),%xmm2;movq -0x20(%rsp),%xmm3;
    movq -0x28(%rsp),%xmm4;movq -0x30(%rsp),%xmm5;
    movq -0x38(%rsp),%xmm6;movq -0x40(%rsp),%xmm7;
    pop %r11
    pop %r10
    pop %r9
    pop %r8
    pop %rcx
    pop %rdx
    pop %rsi
    pop %rdi
    pop %rax
    
    mov %rax, -0x10(%rsp)
    mov -0x90(%rsp),%rax
    push %rax
    mov -0x8(%rsp),%rax

    ret
