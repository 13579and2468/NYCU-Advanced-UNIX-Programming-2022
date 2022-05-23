global __myrt:function
__myrt:
    mov     rax, 15
    syscall
    ret

global setjmp:function
setjmp:
    mov     [rdi], rbx
    lea     rsi, [rsp-0x8]
    mov     [rdi+0x8], rsi
    mov     [rdi+0x10], rbp
    mov     [rdi+0x18], r12
    mov     [rdi+0x20], r13
    mov     [rdi+0x28], r14
    mov     [rdi+0x30], r15
    mov     rax, [rsp]
    mov     [rdi+0x38], rax
    lea     rdx, [rdi+0x40]
    mov     rsi, 0
    mov     rdi, 1
    mov     r10, 8
    mov     rax, 14
    syscall
    mov     rax, 0
    ret

global longjmp:function
longjmp:
    push rdi
    push rsi
    lea     rsi, [rdi+0x40]
    mov     rdx, 0
    mov     rdi, 2
    mov     r10, 8
    mov     rax, 14
    syscall
    pop rsi
    pop rdi
    mov     rbx, [rdi]
    mov     rsp, [rdi+0x8]
    mov     rbp, [rdi+0x10]
    mov     r12, [rdi+0x18]
    mov     r13, [rdi+0x20]
    mov     r14, [rdi+0x28]
    mov     r15, [rdi+0x30]
    mov     rax, rsi
    jmp     [rdi+0x38]