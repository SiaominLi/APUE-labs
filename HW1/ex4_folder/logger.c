#define _GNU_SOURCE // For AT_FDCWD if not otherwise available, and SYS_xxx defines
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h> // For O_CREAT, AT_FDCWD
#include <sys/syscall.h> // For SYS_xxx constants (e.g., SYS_openat)
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <stddef.h>
// No need for dlsym here for RTLD_NEXT based hooking

// Typedef from libzpoline.so's interface
typedef int64_t (*syscall_hook_fn_t)(int64_t rdi, int64_t rsi, int64_t rdx, int64_t r10,
                                     int64_t r8, int64_t r9, int64_t rax_syscall_num);

// Pointer to the original syscall function provided by libzpoline.so
static syscall_hook_fn_t original_syscall_trigger = NULL;

// Helper function to escape non-printable characters (from your code)
static void escape_buffer(const void *buf, size_t len_read, char *escaped, size_t escaped_size, int is_write_or_read) {
    size_t pos = 0;
    if (pos < escaped_size) escaped[pos++] = '"';

    size_t effective_len = (is_write_or_read && len_read == (size_t)-1) ? 0 : len_read; // If read/write failed, effective_len is 0
    size_t max_log_len = effective_len > 32 ? 32 : effective_len;

    for (size_t i = 0; i < max_log_len && pos < escaped_size - 5; i++) { // -5 for \xhh and null
        unsigned char c = ((const unsigned char *)buf)[i];
        if (c == '\t' && pos + 2 < escaped_size) {
            escaped[pos++] = '\\'; escaped[pos++] = 't';
        } else if (c == '\n' && pos + 2 < escaped_size) {
            escaped[pos++] = '\\'; escaped[pos++] = 'n';
        } else if (c == '\r' && pos + 2 < escaped_size) {
            escaped[pos++] = '\\'; escaped[pos++] = 'r';
        } else if ((c < 32 || c >= 127) && pos + 4 < escaped_size) {
            pos += snprintf(escaped + pos, escaped_size - pos, "\\x%02x", c);
        } else if (pos < escaped_size) {
            escaped[pos++] = c;
        } else {
            break; // Not enough space
        }
    }

    if (effective_len > 32 && pos + 3 < escaped_size) { // for ...
        escaped[pos++] = '.';
        escaped[pos++] = '.';
        escaped[pos++] = '.';
    }
    if (pos < escaped_size) escaped[pos++] = '"';
    if (pos < escaped_size) escaped[pos] = '\0';
    else if (escaped_size > 0) escaped[escaped_size -1] = '\0'; // Ensure null termination if truncated
}


// The main syscall handler function for logger.so
static int64_t logger_syscall_handler(int64_t rdi, int64_t rsi, int64_t rdx,
                                      int64_t r10, int64_t r8, int64_t r9,
                                      int64_t rax_syscall_num) {
    if (!original_syscall_trigger) {
        // Should not happen if __hook_init was called correctly
        // Perform direct syscall to avoid issues if we can't use the trigger
        int64_t direct_ret;
        asm volatile("syscall" : "=a"(direct_ret) : "a"(rax_syscall_num), "D"(rdi), "S"(rsi), "d"(rdx), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
        return direct_ret;
    }

    int64_t return_value;

    // Handle execve: log BEFORE calling the original syscall
    if (rax_syscall_num == SYS_execve) {
        const char *filename = (const char *)rdi;
        // execve does not return on success, so logging "after" is not possible in the same way
        fprintf(stderr, "[logger] execve(\"%s\", %p, %p)\n",
                filename ? filename : "(null)",
                (void *)rsi,  // argv_ptr
                (void *)rdx); // envp_ptr
        // Proceed to call the original execve
        return_value = original_syscall_trigger(rdi, rsi, rdx, r10, r8, r9, rax_syscall_num);
        // If execve returns, it's an error. The return_value will be -1.
        // No further logging for execve after call as per spec (it implies success if no return)
        return return_value;
    }

    // For other syscalls, call the original syscall first
    return_value = original_syscall_trigger(rdi, rsi, rdx, r10, r8, r9, rax_syscall_num);

    // Now log based on the syscall number and its result
    switch (rax_syscall_num) {
        case SYS_openat: {
            // rdi: dirfd, rsi: pathname, rdx: flags, r10: mode
            int dirfd_val = (int)rdi;
            const char *pathname = (const char *)rsi;
            int flags = (int)rdx;
            mode_t mode = (mode_t)r10; // mode is relevant if O_CREAT is in flags

            char dirfd_str[32];
            if (dirfd_val == AT_FDCWD) {
                snprintf(dirfd_str, sizeof(dirfd_str), "AT_FDCWD");
            } else {
                snprintf(dirfd_str, sizeof(dirfd_str), "%d", dirfd_val);
            }
            // Ensure mode is 0 if O_CREAT is not set, as it might be garbage otherwise
            if (!(flags & O_CREAT)) {
                mode = 0;
            }
            fprintf(stderr, "[logger] openat(%s, \"%s\", 0x%x, %#o) = %ld\n",
                    dirfd_str,
                    pathname ? pathname : "(null)",
                    flags,
                    mode,
                    return_value);
            break;
        }
        case SYS_read: {
            // rdi: fd, rsi: buf_ptr, rdx: count
            int fd = (int)rdi;
            void *buf_ptr = (void *)rsi;
            size_t original_count = (size_t)rdx;
            char escaped_content[100]; // Sufficient for "...", \xhh etc. for 32 bytes + quotes

            // Only try to read from buf_ptr if return_value > 0
            if (return_value > 0) {
                 escape_buffer(buf_ptr, (size_t)return_value, escaped_content, sizeof(escaped_content), 1);
            } else {
                 snprintf(escaped_content, sizeof(escaped_content), "\"\""); // Empty string if read failed or read 0 bytes
            }

            fprintf(stderr, "[logger] read(%d, %s, %zu) = %ld\n",
                    fd,
                    escaped_content,
                    original_count,
                    return_value);
            break;
        }
        case SYS_write: {
            // rdi: fd, rsi: buf_ptr, rdx: count
            int fd = (int)rdi;
            const void *buf_ptr = (const void *)rsi;
            size_t original_count = (size_t)rdx;
            char escaped_content[100];

            // For write, we log the buffer passed, up to original_count or 32 bytes
            // The actual number of bytes written is return_value.
            // The spec says "logs the buffer that was written", implying content of 'buf_ptr'.
            // The length to escape should be original_count, truncated to 32 for logging.
            escape_buffer(buf_ptr, original_count, escaped_content, sizeof(escaped_content), 1);

            fprintf(stderr, "[logger] write(%d, %s, %zu) = %ld\n",
                    fd,
                    escaped_content,
                    original_count,
                    return_value);
            break;
        }
        case SYS_connect: {
            int sockfd = (int)rdi;
            const struct sockaddr *addr_ptr = (const struct sockaddr *)rsi;
            socklen_t addrlen_val = (socklen_t)rdx;
            char address_str[256] = "\"UNKNOWN\""; 

            if (addr_ptr && addrlen_val > 0) {
                char temp_addr_str[200];
                if (addr_ptr->sa_family == AF_INET && addrlen_val >= sizeof(struct sockaddr_in)) {
                    struct sockaddr_in *in_addr = (struct sockaddr_in *)addr_ptr;
                    char ip_buf[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &in_addr->sin_addr, ip_buf, sizeof(ip_buf));
                    snprintf(temp_addr_str, sizeof(temp_addr_str), "%s:%d", ip_buf, ntohs(in_addr->sin_port));
                    snprintf(address_str, sizeof(address_str), "\"%s\"", temp_addr_str);
                } else if (addr_ptr->sa_family == AF_INET6 && addrlen_val >= sizeof(struct sockaddr_in6)) {
                    struct sockaddr_in6 *in6_addr = (struct sockaddr_in6 *)addr_ptr;
                    char ip_buf[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &in6_addr->sin6_addr, ip_buf, sizeof(ip_buf));
                    snprintf(temp_addr_str, sizeof(temp_addr_str), "%s:%d", ip_buf, ntohs(in6_addr->sin6_port));
                    snprintf(address_str, sizeof(address_str), "\"%s\"", temp_addr_str);
                } else if (addr_ptr->sa_family == AF_UNIX && addrlen_val > offsetof(struct sockaddr_un, sun_path)) { // Check addrlen against start of sun_path
                    struct sockaddr_un *un_addr = (struct sockaddr_un *)addr_ptr;
                    // Calculate max length of path within the provided addrlen
                    // Corrected use of offsetof:
                    size_t max_path_len = addrlen_val - offsetof(struct sockaddr_un, sun_path); 
                    
                    char path_buf[sizeof(un_addr->sun_path) +1] = {0}; // Buffer for path
                    
                    // Copy path, ensuring not to read beyond what addrlen provides for sun_path
                    // and not beyond the actual size of sun_path array.
                    size_t copy_len = max_path_len < sizeof(un_addr->sun_path) ? max_path_len : sizeof(un_addr->sun_path) -1;
                    // If max_path_len is 0 (e.g. abstract socket with just null byte name), strncpy might do nothing or be tricky.
                    // A common way for unnamed abstract sockets: addrlen = offsetof(struct sockaddr_un, sun_path)
                    // For path based, addrlen > offsetof(struct sockaddr_un, sun_path)
                    if (copy_len > 0) { // only copy if there's actually path data based on addrlen
                        strncpy(path_buf, un_addr->sun_path, copy_len);
                        path_buf[copy_len] = '\0'; // Ensure null termination as strncpy might not if src is longer
                    } else if (max_path_len == 0 && un_addr->sun_path[0] == '\0') {
                        // This could be an abstract socket with an empty name (just the leading null byte)
                        // The spec just says "UNIX:SOCKET_PATH". For an empty path, it would be "UNIX:"
                        // However, typically paths are non-empty. If it's an abstract socket with non-printable
                        // chars, escape_buffer would be needed if we were to print its name directly.
                        // For simplicity and sticking to spec, if path is empty, it will print "UNIX:"
                        path_buf[0] = '\0';
                    }


                    snprintf(temp_addr_str, sizeof(temp_addr_str), "UNIX:%s", path_buf);
                    snprintf(address_str, sizeof(address_str), "\"%s\"", temp_addr_str);
                }
            }
            fprintf(stderr, "[logger] connect(%d, %s, %u) = %ld\n",
                    sockfd,
                    address_str,
                    addrlen_val,
                    return_value);
            break;
        }
        default:
            break;
    }
    return return_value;
}

// This is the function libzpoline.so will look for
void __hook_init(const syscall_hook_fn_t trigger_syscall_fn,
                 syscall_hook_fn_t *hooked_syscall_ptr) {
    original_syscall_trigger = trigger_syscall_fn;
    *hooked_syscall_ptr = logger_syscall_handler;
}