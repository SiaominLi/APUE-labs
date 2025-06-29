#define _GNU_SOURCE
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

#define TRAMPOLINE_SIZE 1024

void __attribute__((constructor)) init_trampoline(void) {
    void *addr = (void *)0x0;
    size_t size = TRAMPOLINE_SIZE;

    // mmap 0x0
    void *mem = mmap(addr, size, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (mem == MAP_FAILED) {
        fprintf(stderr, "mmap failed: %s\n", strerror(errno));
        return;
    }

    // 填入 512 個 nop
    memset(mem, 0x90, 512);

    // 編寫 trampoline（使用 write 系統呼叫印出訊息）
    unsigned char trampoline_code[] = {
        0x48, 0xc7, 0xc0, 0x01, 0x00, 0x00, 0x00,       // mov rax, 1        ; syscall number (write)
        0x48, 0xc7, 0xc7, 0x02, 0x00, 0x00, 0x00,       // mov rdi, 2        ; fd = 2 (stderr)
        0x48, 0xbe,                                     // mov rsi, imm64    ; msg ptr
          /* 8 bytes for pointer */ 0, 0, 0, 0, 0, 0, 0, 0,
        0x48, 0xc7, 0xc2, 0x18, 0x00, 0x00, 0x00,       // mov rdx, 24       ; message length
        0x0f, 0x05,                                     // syscall
        0xc3                    
    };

    // 將 trampoline 寫入 offset 512
    memcpy((unsigned char *)mem + 512, trampoline_code, sizeof(trampoline_code));

    // 將訊息字串放到 trampoline 結尾
    const char *msg = "Hello from trampoline!\n";
    size_t msg_offset = 512 + sizeof(trampoline_code);
    strcpy((char *)mem + msg_offset, msg);

    // 將 msg 的位址寫入 trampoline_code 第三段的 RSI（偏移為 16）
    uint64_t msg_addr = (uint64_t)((unsigned char *)mem + msg_offset);
    memcpy((unsigned char *)mem + 512 + 16, &msg_addr, sizeof(msg_addr));

    if (mprotect(mem, size, PROT_READ | PROT_EXEC) == -1) {
        fprintf(stderr, "mprotect failed: %s\n", strerror(errno));
        munmap(mem, size);
        return;
    }

    void (*trampoline_func)(void) = (void (*)(void))((unsigned char *)mem + 512);
}
