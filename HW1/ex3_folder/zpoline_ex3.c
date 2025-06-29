#define _GNU_SOURCE
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdio.h>

#define JUMP_TARGET 512

typedef int64_t (*syscall_hook_fn_t)(int64_t rdi, int64_t rsi, int64_t rdx, int64_t r10,
                                     int64_t r8, int64_t r9, int64_t rax_syscall_num);

typedef void (*hook_init_fn_ptr_t)(const syscall_hook_fn_t trigger_syscall,
                                   syscall_hook_fn_t *hooked_syscall);

__attribute__((visibility("default")))
int64_t handler(int64_t rdi, int64_t rsi, int64_t rdx, int64_t r10, int64_t r8,  int64_t r9, int64_t rax_syscall_num);


static int64_t trigger_actual_syscall(int64_t rdi, int64_t rsi, int64_t rdx, int64_t r10, int64_t r8,  int64_t r9, int64_t rax)
{   
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

static syscall_hook_fn_t g_current_syscall_handler = trigger_actual_syscall;
static __thread int tls_in_hook_guard = 0;


__attribute__((visibility("default")))
__attribute__((force_align_arg_pointer))
int64_t handler(int64_t rdi_val, int64_t rsi_val, int64_t rdx_val,
                              int64_t r10_val,
                              int64_t r8_val, int64_t r9_val,
                              int64_t rax_syscall_num_val) {
    if (tls_in_hook_guard) {
        return trigger_actual_syscall(rdi_val, rsi_val, rdx_val, r10_val, r8_val, r9_val, rax_syscall_num_val);
    }
    else{
        tls_in_hook_guard = 1;
        int64_t result = g_current_syscall_handler(rdi_val, rsi_val, rdx_val, r10_val, r8_val, r9_val, rax_syscall_num_val);
        tls_in_hook_guard = 0;
        return result;
    }
}

void rewrite_exe_seg_syscall_internal() {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        return;
    }
    unsigned char call_rax_op[] = {0xFF, 0xD0};
    char line_buf[512];
    while (fgets(line_buf, sizeof(line_buf), fp)) {
        uintptr_t start, end;
        char perms[5];
        if (sscanf(line_buf, "%lx-%lx %4s", &start, &end, perms) == 3) {
            if (perms[0] == 'r' && perms[2] == 'x') {
                if (strstr(line_buf, "[vdso]") || strstr(line_buf, "[vsyscall]") ||
                    strstr(line_buf, "libzpoline.so")) {
                    continue;
                }
                size_t len = end - start;
                if (mprotect((void *)start, len, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
                    continue;
                }
                uint8_t *ptr = (uint8_t *)start;
                for (size_t i = 0; i < len - 1; ++i) {
                    if (ptr[i] == 0x0f && ptr[i + 1] == 0x05) {
                        memcpy((void*)(ptr + i), call_rax_op, sizeof(call_rax_op));
                    }
                }
            }
        }
    }
    fclose(fp);
}

__attribute__((constructor))
void zpoline_constructor_main() {
    void *trampoline_mmap_addr = mmap((void *)0x00, 1024,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);

    if (trampoline_mmap_addr == MAP_FAILED) {
        return;
    }
    memset(trampoline_mmap_addr, 0x90, JUMP_TARGET);

    uint8_t trampoline_code[] = {
        0x4C, 0x89, 0xD1,
        0x50,
        0x48, 0xB8, 0,0,0,0,0,0,0,0,
        0xFF, 0xD0,
        0x48, 0x83, 0xC4, 0x08,
        0xC3
    };
    uint8_t *trampoline_target_location = (uint8_t *)trampoline_mmap_addr + JUMP_TARGET;
    memcpy(trampoline_target_location, trampoline_code, sizeof(trampoline_code));

    uintptr_t c_entry_handler_addr = (uintptr_t)(void *)handler;
    memcpy(trampoline_target_location + 6, &c_entry_handler_addr, sizeof(c_entry_handler_addr));

    rewrite_exe_seg_syscall_internal(); // Execute rewrite first

    const char *hook_library_name = getenv("LIBZPHOOK");
    if (hook_library_name && strlen(hook_library_name) > 0) {
        void *hook_lib_handle = dlmopen(LM_ID_NEWLM, hook_library_name, RTLD_LAZY | RTLD_LOCAL);
        if (hook_lib_handle) {
            hook_init_fn_ptr_t init_func_from_hook = (hook_init_fn_ptr_t)dlsym(hook_lib_handle, "__hook_init");
            if (dlerror() == NULL && init_func_from_hook != NULL) {
                init_func_from_hook(trigger_actual_syscall, &g_current_syscall_handler);
            } else {
                // dlclose(hook_lib_handle); // Optional cleanup on dlsym failure
            }
        }
    }

    
}