#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <dlfcn.h>

#define JUMP_TARGET 512

int64_t handler(int64_t, int64_t, int64_t, int64_t, int64_t, int64_t, int64_t);

void rewrite_exe_seg_syscall() {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        perror("fopen /proc/self/maps");
        return;
    }

    uintptr_t handler_addr = (uintptr_t)(void *)handler;
    unsigned char call_rax_op[] = {0xFF, 0xD0}; // call *%rax

    char line_buf[512];
    while (fgets(line_buf, sizeof(line_buf), fp)) {
        uintptr_t start, end;
        char perms[5];
        if (sscanf(line_buf, "%lx-%lx %4s", &start, &end, perms) == 3) {
            if (perms[0] == 'r' && perms[2] == 'x') {
                if (strstr(line_buf, "[vdso]") || strstr(line_buf, "[vsyscall]") || strstr(line_buf, "libzpoline")) {
                    continue;
                }
                size_t len = end - start;
                if (mprotect((void *)start, len, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
                    perror("mprotect");
                    continue;
                }

                uint8_t *ptr = (uint8_t *)start;
                for (size_t i = 0; i < len - 1; ++i) {
                    if (ptr[i] == 0x0f && ptr[i + 1] == 0x05) { //syscall
                        // ptr[i] = 0xFF; 
                        // ptr[i + 1] = 0xD0;
                        memcpy((void*)ptr + i, call_rax_op, sizeof(call_rax_op));
                    }
                }
            }
        }
    }

    fclose(fp);
}



// __attribute__((noinline))
__attribute__((visibility("default")))
int64_t handler(int64_t rdi, int64_t rsi, int64_t rdx, int64_t r10, int64_t r8,  int64_t r9, int64_t rax)
{
    if (rax == SYS_write && rdi == STDOUT_FILENO) {
        char *buf = (char *)rsi;
        size_t len = (size_t)rdx;
        for (size_t i = 0; i < len; ++i) {
            switch (buf[i]) {
                case '0': buf[i] = 'o'; break;
                case '1': buf[i] = 'i'; break;
                case '2': buf[i] = 'z'; break;
                case '3': buf[i] = 'e'; break;
                case '4': buf[i] = 'a'; break;
                case '5': buf[i] = 's'; break;
                case '6': buf[i] = 'g'; break;
                case '7': buf[i] = 't'; break;
                default: break;
            }
        }
    }

    register int64_t _rdi asm("rdi") = rdi;
    register int64_t _rsi asm("rsi") = rsi;
    register int64_t _rdx asm("rdx") = rdx;
    register int64_t _r10 asm("r10") = r10;
    register int64_t _r8  asm("r8")  = r8;
    register int64_t _r9  asm("r9")  = r9;
    register int64_t _rax asm("rax") = rax;

    asm volatile (
        "syscall"
        : "+r"(_rdi), "+r"(_rsi), "+r"(_rdx),
          "+r"(_r10), "+r"(_r8), "+r"(_r9),
          "+a"(_rax)
        :
        : "rcx", "r11", "memory"
    ); //trigger_syscall

    return _rax;
}


__attribute__((constructor))
void setup_trampoline() {
    if (getenv("ZDEBUG")) {
        asm("int3");
    }

    void *addr = mmap((void *)0x0, 1024,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        return;
    }

    memset(addr, 0x90, JUMP_TARGET);  // NOP padding before trampoline

    // Define trampoline code
    uint8_t trampoline_code[] = {
        0x4C, 0x89, 0xD1,                         // mov %rcx, %r10
        0x50,                                     // push %rax
        0x48, 0xB8,                               // movabs $handler_addr, %rax
        0, 0, 0, 0, 0, 0, 0, 0,                   // handler addr
        0xFF, 0xD0,                               // call *%rax
        0x48, 0x83, 0xC4, 0x08,                   // add $8, %rsp
        0xC3                                      // ret
    };
    

    uint8_t *trampoline = (uint8_t *)addr + JUMP_TARGET;
    memcpy(trampoline, trampoline_code, sizeof(trampoline_code));

    void *real_handler = dlsym(RTLD_DEFAULT, "handler");
    uintptr_t handler_addr = (uintptr_t)real_handler;

    // 在 movabs 指令後面 (0x06) 寫入 handler 地址
    memcpy(trampoline + 0x06, &handler_addr, sizeof(handler_addr));

    // if (getenv("ZDEBUG")) {
    //     asm("int3");
    // }

    rewrite_exe_seg_syscall(); 
}

