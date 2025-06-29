extern errno

section .data
seed dq 0

section .text
global time
global srand
global grand
global rand
global sigemptyset
global sigfillset
global sigaddset
global sigdelset
global sigismember
global sigprocmask
global setjmp
global longjmp

time:
    mov rax, 201
    syscall
    cmp rax, 0
    jge .return
    neg rax
    mov [rel errno wrt ..gotpcrel], rax
    mov rax, -1
.return:
    ret

srand:
    mov eax, edi
    sub eax, 1
    mov [rel seed], rax
    ret

grand:
    mov rax, [rel seed]
    ret

rand:
    mov rax, [rel seed]
    mov rdx, 6364136223846793005
    mul rdx
    add rax, 1
    mov [rel seed], rax
    shr rax, 33
    ret

sigemptyset:
    mov rax, 0
    mov [rdi], rax
    ret

sigfillset:
    mov rax, 0xFFFFFFFF
    mov [rdi], rax
    ret

sigaddset:
    cmp esi, 1
    jl .error
    cmp esi, 32
    jg .error
    mov eax, 1
    mov ecx, esi
    sub ecx, 1
    shl eax, cl
    or [rdi], eax
    mov rax, 0
    ret
.error:
    mov rax, 22
    mov [rel errno wrt ..gotpcrel], rax
    mov rax, -1
    ret

sigdelset:
    cmp esi, 1
    jl .error
    cmp esi, 32
    jg .error
    mov eax, 1
    mov ecx, esi
    sub ecx, 1
    shl eax, cl
    not eax
    and [rdi], eax
    mov rax, 0
    ret
.error:
    mov rax, 22
    mov [rel errno wrt ..gotpcrel], rax
    mov rax, -1
    ret

sigismember:
    cmp esi, 1
    jl .error
    cmp esi, 32
    jg .error
    mov eax, 1
    mov ecx, esi
    sub ecx, 1
    shl eax, cl
    and eax, [rdi]
    shr eax, cl
    ret
.error:
    mov rax, 22
    mov [rel errno wrt ..gotpcrel], rax
    mov rax, -1
    ret

sigprocmask:
    mov rax, 14
    mov r10, 8
    syscall
    cmp rax, 0
    jge .return
    neg rax
    mov [rel errno wrt ..gotpcrel], rax
    mov rax, -1
.return:
    ret

setjmp:
    mov [rdi], rbx
    mov [rdi + 8], rbp
    mov [rdi + 16], rsp
    mov [rdi + 24], r12
    mov [rdi + 32], r13
    mov [rdi + 40], r14
    mov [rdi + 48], r15

    mov rax, [rsp]
    mov [rdi + 56], rax 

    xor     rax, rax           
    mov     rsi, 0             
    lea     rdx, [rdi+64]      
    mov     r10, 8             
    mov     rax, 14            
    syscall

    xor     rax, rax           
    ret

longjmp:
    mov rbx, [rdi]
    mov rbp, [rdi + 8]
    mov rsp, [rdi + 16]
    mov r12, [rdi + 24]
    mov r13, [rdi + 32]
    mov r14, [rdi + 40]
    mov r15, [rdi + 48]
    mov rax, [rdi + 56]

    push rax
    sub rsp, 16
    mov [rsp], rdi
    lea rsi, [rdi + 64]
    
    mov edi, 2
    xor edx, edx
    mov rax, 14
    mov r10, 8
    syscall
    
    mov rdi, [rsp]
    add rsp, 16
    cmp rax, 0
    jge .return
    neg rax
    mov [rel errno wrt ..gotpcrel], rax
    mov rax, -1
    ret
.return:
    mov eax, esi
    test eax, eax
    jnz .set_return
    mov eax, 1
.set_return
    ret