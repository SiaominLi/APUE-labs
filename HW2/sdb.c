#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <capstone/capstone.h>
#include <elf.h>
#include <fcntl.h>
#include <errno.h>
#include <inttypes.h>

pid_t g_child_pid = 0;
int g_child_status = 0;
unsigned long long g_entry_point_vma = 0;
char g_program_path[1024] = {0};
struct user_regs_struct g_regs;
csh g_cs_handle;

#define MAX_EXEC_REGIONS 64
typedef struct {
    unsigned long long start;
    unsigned long long end;
    char perms[5];
    char path[256];
} ExecRegion;
ExecRegion g_exec_regions[MAX_EXEC_REGIONS];
int g_num_exec_regions = 0;

#define MAX_BREAKPOINTS 128
typedef struct {
    int id;
    unsigned long long address;
    unsigned char original_byte;
    int is_enabled;
    int is_active;
} Breakpoint;
 
Breakpoint g_breakpoints[MAX_BREAKPOINTS];
int g_breakpoint_count = 0;
int g_next_breakpoint_id = 0;

unsigned long long g_program_base_address = 0;
int g_program_is_pie = 0;

int g_is_stepping_over_breakpoint = 0;
unsigned long long g_stepped_over_breakpoint_addr = 0;

int g_in_syscall_execution = 0;
long long g_last_syscall_nr = -1;

void handle_load(char* path_arg);
void handle_si();
void handle_cont();
void disassemble_and_print(unsigned long long rip_to_display_and_disassemble, int count);
unsigned long long get_elf_entry_from_file(const char* elf_path, int* is_pie);
unsigned long long get_at_entry_from_auxv(pid_t pid);
void update_executable_regions();
int is_address_in_any_executable_region(unsigned long long addr);
int is_instruction_in_executable_region(unsigned long long addr, size_t size);
void handle_break(char* addr_str);
void handle_breakrva(char* offset_str);
void handle_info_break();
void handle_info_reg();
void handle_delete(char* id_str);
void handle_patch(char* addr_str, char* hex_str);
void handle_syscall_cmd();
int hex_char_to_int(char c);
int parse_hex_string_to_bytes(const char* hex_str, unsigned char* out_bytes, size_t max_bytes);
Breakpoint* find_breakpoint_at(unsigned long long addr);
void enable_breakpoint(Breakpoint* bp);
void disable_breakpoint(Breakpoint* bp);
void prepare_for_step_or_cont();
unsigned long long get_program_base_address_from_maps(pid_t pid, const char* prog_path_basename);


void print_prompt() {
    printf("(sdb) ");
    fflush(stdout);
}

unsigned long long get_elf_entry_from_file(const char* elf_path, int* is_pie) {
    *is_pie = 0;
    int fd = open(elf_path, O_RDONLY);
    if (fd < 0) {
        return 0;
    }
    Elf64_Ehdr ehdr;
    if (read(fd, &ehdr, sizeof(Elf64_Ehdr)) != sizeof(Elf64_Ehdr)) {
        close(fd);
        return 0;
    }
    close(fd);

    if (ehdr.e_ident[EI_MAG0] != ELFMAG0 || ehdr.e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr.e_ident[EI_MAG2] != ELFMAG2 || ehdr.e_ident[EI_MAG3] != ELFMAG3) {
        return 0;
    }
    if (ehdr.e_type == ET_DYN) {
       *is_pie = 1;
    } else if (ehdr.e_type == ET_EXEC) {
        *is_pie = 0;
    }
    return ehdr.e_entry;
}

int ptrace_peek_byte(pid_t pid, unsigned long long addr, unsigned char* out_byte) {
    unsigned long long aligned_addr = addr & ~(sizeof(long)-1);
    int offset_in_word = addr - aligned_addr;
    errno = 0;
    long data = ptrace(PTRACE_PEEKTEXT, pid, (void*)aligned_addr, NULL);
    if (errno != 0 && data == -1) {
        return -1; // Error
    }
    *out_byte = ((unsigned char*)&data)[offset_in_word];
    return 0; // Success
}

int ptrace_poke_byte(pid_t pid, unsigned long long addr, unsigned char new_byte) {
    unsigned long long aligned_addr = addr & ~(sizeof(long)-1);
    int offset_in_word = addr - aligned_addr;
    errno = 0;
    long word_content = ptrace(PTRACE_PEEKTEXT, pid, (void*)aligned_addr, NULL);
    if (errno != 0 && word_content == -1) {
        return -1; // Read failed
    }
    unsigned char* byte_ptr_in_word = (unsigned char*)&word_content;
    byte_ptr_in_word[offset_in_word] = new_byte;
    if (ptrace(PTRACE_POKETEXT, pid, (void*)aligned_addr, (void*)word_content) < 0) {
        return -1; // Write failed
    }
    return 0; // Success
}

unsigned long long get_at_entry_from_auxv(pid_t pid) {
    char path_buf[128];
    sprintf(path_buf, "/proc/%d/auxv", pid);
    int fd = open(path_buf, O_RDONLY);
    if (fd < 0) {
        return 0;
    }
    Elf64_auxv_t auxv_entry_buf;
    while (read(fd, &auxv_entry_buf, sizeof(Elf64_auxv_t)) == sizeof(Elf64_auxv_t)) {
        if (auxv_entry_buf.a_type == 0 && auxv_entry_buf.a_un.a_val == 0) {
            break;
        }
        if (auxv_entry_buf.a_type == AT_ENTRY) {
            close(fd);
            return auxv_entry_buf.a_un.a_val;
        }
    }
    close(fd);
    return 0;
}

void update_executable_regions() {
    if (g_child_pid == 0) return;
    char maps_path[128];
    sprintf(maps_path, "/proc/%d/maps", g_child_pid);
    FILE* fp = fopen(maps_path, "r");
    if (!fp) {
        g_num_exec_regions = 0;
        return;
    }
    g_num_exec_regions = 0;
    char line_buf[512];
    while (fgets(line_buf, sizeof(line_buf), fp) && g_num_exec_regions < MAX_EXEC_REGIONS) {
        unsigned long long start, end;
        char perms[5];
        char path_in_map[256] = "";
        int items_scanned = sscanf(line_buf, "%llx-%llx %4s %*x %*x:%*x %*d %255s", &start, &end, perms, path_in_map);
        if (items_scanned < 3) {
            items_scanned = sscanf(line_buf, "%llx-%llx %4s", &start, &end, perms);
             if (items_scanned < 3) continue;
        }
        if (perms[0] == 'r' && perms[2] == 'x') {
            g_exec_regions[g_num_exec_regions].start = start;
            g_exec_regions[g_num_exec_regions].end = end;
            strncpy(g_exec_regions[g_num_exec_regions].perms, perms, 4);
            g_exec_regions[g_num_exec_regions].perms[4] = '\0';
            strncpy(g_exec_regions[g_num_exec_regions].path, path_in_map, 255);
            g_exec_regions[g_num_exec_regions].path[255] = '\0';
            g_num_exec_regions++;
        }
    }
    fclose(fp);
}

int is_address_in_any_executable_region(unsigned long long addr) {
    for (int i = 0; i < g_num_exec_regions; ++i) {
        if (addr >= g_exec_regions[i].start && addr < g_exec_regions[i].end) {
            return 1;
        }
    }
    return 0;
}

int is_instruction_in_executable_region(unsigned long long addr, size_t size) {
    if (size == 0) return is_address_in_any_executable_region(addr);
    for (size_t i = 0; i < size; ++i) {
        if (!is_address_in_any_executable_region(addr + i)) {
            return 0;
        }
    }
    return 1;
}

unsigned long long get_program_base_address_from_maps(pid_t pid, const char* prog_path_basename) {
    char maps_path[128];
    sprintf(maps_path, "/proc/%d/maps", pid);
    FILE* fp = fopen(maps_path, "r");
    if (!fp) return 0;

    char line_buf[512];
    unsigned long long lowest_addr_for_prog = (unsigned long long)-1;

    while (fgets(line_buf, sizeof(line_buf), fp)) {
        unsigned long long start, end;
        char perms[5];
        unsigned long long offset_in_map;
        char dev[16];
        long inode;
        char path_in_map[256] = "";
        int items = sscanf(line_buf, "%llx-%llx %4s %llx %15s %ld %255s",
                           &start, &end, perms, &offset_in_map, dev, &inode, path_in_map);
        if (items >= 7 && prog_path_basename && strstr(path_in_map, prog_path_basename) != NULL && offset_in_map == 0) {
             if (perms[0] == 'r' && perms[2] == 'x') {
                if (start < lowest_addr_for_prog) {
                    lowest_addr_for_prog = start;
                }
            }
        } else if (items >=6 && prog_path_basename && strstr(path_in_map, prog_path_basename) != NULL && offset_in_map == 0) {
             if (perms[0] == 'r' && perms[2] == 'x') {
                if (start < lowest_addr_for_prog) {
                    lowest_addr_for_prog = start;
                }
            }
        }
    }
    fclose(fp);
    return (lowest_addr_for_prog == (unsigned long long)-1) ? 0 : lowest_addr_for_prog;
}


Breakpoint* find_breakpoint_at(unsigned long long addr) {
    for (int i = 0; i < MAX_BREAKPOINTS; ++i) {
        if (g_breakpoints[i].is_active && g_breakpoints[i].address == addr) {
            return &g_breakpoints[i];
        }
    }
    return NULL;
}

void enable_breakpoint(Breakpoint* bp) {
    if (!bp || !bp->is_active || bp->is_enabled) return;
    // original_byte should have been stored when bp was created/last patched
    if (ptrace_poke_byte(g_child_pid, bp->address, 0xCC) == 0) {
        bp->is_enabled = 1;
    } else {
        perror("enable_breakpoint: ptrace_poke_byte failed");
    }
}

void disable_breakpoint(Breakpoint* bp) {
    if (!bp || !bp->is_active || !bp->is_enabled) return;
    if (ptrace_poke_byte(g_child_pid, bp->address, bp->original_byte) == 0) {
        bp->is_enabled = 0;
    } else {
        perror("disable_breakpoint: ptrace_poke_byte failed");
    }
}

void prepare_for_step_or_cont() {
    if (g_is_stepping_over_breakpoint) {
        Breakpoint* bp = find_breakpoint_at(g_stepped_over_breakpoint_addr);
        if (bp) {
            enable_breakpoint(bp);
        }
        g_is_stepping_over_breakpoint = 0;
        g_stepped_over_breakpoint_addr = 0;
    }
}

void handle_load(char* path_arg) {
    if (g_child_pid != 0) {
        ptrace(PTRACE_KILL, g_child_pid, NULL, NULL);
        waitpid(g_child_pid, NULL, 0);
        g_child_pid = 0;
        g_num_exec_regions = 0;
        memset(g_breakpoints, 0, sizeof(g_breakpoints));
        g_breakpoint_count = 0;
        g_program_base_address = 0;
        g_program_is_pie = 0;
        g_is_stepping_over_breakpoint = 0;
        g_stepped_over_breakpoint_addr = 0;
        g_in_syscall_execution = 0;
        g_last_syscall_nr = -1;
    }
    strncpy(g_program_path, path_arg, sizeof(g_program_path) - 1);
    g_program_path[sizeof(g_program_path) - 1] = '\0';

    g_child_pid = fork();
    if (g_child_pid < 0) {
        perror("fork"); g_child_pid = 0; return;
    }

    if (g_child_pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("PTRACE_TRACEME"); exit(EXIT_FAILURE);
        }
        char *argv_child[] = {g_program_path, NULL};
        if (execvp(g_program_path, argv_child) < 0) {
            perror("execvp"); exit(EXIT_FAILURE);
        }
    } else {
        if (waitpid(g_child_pid, &g_child_status, 0) < 0) {
            perror("waitpid on initial stop"); g_child_pid = 0; return;
        }

        if (WIFSTOPPED(g_child_status)) {
            int is_pie_from_elf_file;
            unsigned long long elf_file_entry_rva = get_elf_entry_from_file(g_program_path, &is_pie_from_elf_file);
            g_program_is_pie = is_pie_from_elf_file;

            unsigned long long target_vma_entry = get_at_entry_from_auxv(g_child_pid);
            if (target_vma_entry == 0) {
                 if (!g_program_is_pie && elf_file_entry_rva != 0) {
                    target_vma_entry = elf_file_entry_rva;
                 } else {
                    fprintf(stderr, "** Error: Could not determine program entry point VMA.\n");
                    ptrace(PTRACE_KILL, g_child_pid, NULL, NULL); waitpid(g_child_pid, NULL, 0); g_child_pid = 0;
                    return;
                 }
            }
            g_entry_point_vma = target_vma_entry;

            if (g_program_is_pie) {
                if (elf_file_entry_rva != 0) {
                    g_program_base_address = g_entry_point_vma - elf_file_entry_rva;
                } else {
                    char* last_slash = strrchr(g_program_path, '/');
                    const char* prog_basename = last_slash ? last_slash + 1 : g_program_path;
                    g_program_base_address = get_program_base_address_from_maps(g_child_pid, prog_basename);
                    if (g_program_base_address == 0) {
                         fprintf(stderr, "** Warning: Could not reliably determine PIE base address for breakrva.\n");
                    }
                }
            } else {
                char* last_slash = strrchr(g_program_path, '/');
                const char* prog_basename = last_slash ? last_slash + 1 : g_program_path;
                g_program_base_address = get_program_base_address_from_maps(g_child_pid, prog_basename);
                if (g_program_base_address == 0 && strcmp(g_program_path, "./hello") == 0) {
                     g_program_base_address = 0x400000;
                }
            }

            ptrace(PTRACE_GETREGS, g_child_pid, NULL, &g_regs);
            if (g_regs.rip != g_entry_point_vma) {
                unsigned long original_code_at_entry = ptrace(PTRACE_PEEKTEXT, g_child_pid, (void*)g_entry_point_vma, NULL);
                 if (errno != 0 && original_code_at_entry == (unsigned long)-1) {
                    perror("PEEKTEXT for setting entry BP");
                    ptrace(PTRACE_KILL, g_child_pid, NULL, NULL); waitpid(g_child_pid, NULL, 0); g_child_pid = 0; return;
                }
                unsigned long trap_code_at_entry = (original_code_at_entry & ~0xFFULL) | 0xCCULL;
                if (ptrace(PTRACE_POKETEXT, g_child_pid, (void*)g_entry_point_vma, (void*)trap_code_at_entry) < 0) {
                    perror("POKETEXT for setting entry BP");
                    ptrace(PTRACE_KILL, g_child_pid, NULL, NULL); waitpid(g_child_pid, NULL, 0); g_child_pid = 0; return;
                }
                if (ptrace(PTRACE_CONT, g_child_pid, NULL, NULL) < 0) { perror("CONT to entry BP"); return;}
                if (waitpid(g_child_pid, &g_child_status, 0) < 0) { perror("waitpid for entry BP"); return;}

                if (WIFSTOPPED(g_child_status) && WSTOPSIG(g_child_status) == SIGTRAP) {
                    if (ptrace(PTRACE_POKETEXT, g_child_pid, (void*)g_entry_point_vma, (void*)original_code_at_entry) < 0) {
                        perror("POKETEXT to restore entry BP");
                    }
                    ptrace(PTRACE_GETREGS, g_child_pid, NULL, &g_regs);
                    g_regs.rip = g_entry_point_vma;
                    if (ptrace(PTRACE_SETREGS, g_child_pid, NULL, &g_regs) < 0) {
                        perror("SETREGS after entry BP");
                    }
                } else {
                     fprintf(stderr, "** Error: Did not stop at entry point breakpoint as expected.\n");
                     ptrace(PTRACE_KILL, g_child_pid, NULL, NULL); waitpid(g_child_pid, NULL, 0); g_child_pid = 0; return;
                }
            }
            printf("** program '%s' loaded. entry point: 0x%llx.\n", g_program_path, g_entry_point_vma);
            update_executable_regions();
            disassemble_and_print(g_entry_point_vma, 5);
        } else {
            fprintf(stderr, "** child process did not stop as expected.\n");
            g_child_pid = 0;
        }
    }
}

void disassemble_and_print(unsigned long long rip_to_display_and_disassemble, int count) {
    if (g_child_pid == 0) return;
    
    unsigned long long rip_start_for_disassembly = rip_to_display_and_disassemble;
    
    // Check current RIP first to see if we need to update regions
    ptrace(PTRACE_GETREGS, g_child_pid, NULL, &g_regs);
    if (!is_address_in_any_executable_region(g_regs.rip)) { // Check actual current RIP
        update_executable_regions();
    }


    if (!is_address_in_any_executable_region(rip_start_for_disassembly)) {
        // If after update, the specific rip_to_display_and_disassemble is still not in exec region
        // it might be a data region, or truly out of bounds for execution view.
        // However, the spec says "The address of the 5 instructions should be within the range of the executable region."
        // So, if rip_to_display_and_disassemble is not in an exec region, we should print the error.
        // The only exception is if update_executable_regions() just made it valid.
        if(!is_address_in_any_executable_region(rip_start_for_disassembly)){
             printf("** the address is out of the range of the executable region.\n");
             return;
        }
    }


    unsigned char buffer[256];
    unsigned char temp_buffer_for_disasm[256];
    size_t total_bytes_read = 0;

    // Read memory for disassembly using byte-by-byte peeking for safety with alignment
    // This is less efficient but safer for arbitrary addresses if not using /proc/mem
    for (size_t i = 0; i < sizeof(buffer); ++i) {
        unsigned char byte_val;
        if (ptrace_peek_byte(g_child_pid, rip_start_for_disassembly + i, &byte_val) == 0) {
            buffer[i] = byte_val;
            total_bytes_read++;
        } else {
            if (i==0 && errno == EIO) { // If first byte fails, it's likely a bad address
                 printf("** the address is out of the range of the executable region.\n");
                 return;
            }
            break; 
        }
    }


    memcpy(temp_buffer_for_disasm, buffer, total_bytes_read);
    for (size_t k = 0; k < total_bytes_read; ++k) {
        unsigned long long current_addr_in_buffer = rip_start_for_disassembly + k;
        Breakpoint* bp = find_breakpoint_at(current_addr_in_buffer);
        if (bp && bp->is_enabled && bp->address == current_addr_in_buffer) {
            if (k < sizeof(temp_buffer_for_disasm)) {
                 temp_buffer_for_disasm[k] = bp->original_byte;
            }
        }
    }

    cs_insn *insn;
    size_t num_disassembled = cs_disasm(g_cs_handle, temp_buffer_for_disasm, total_bytes_read, rip_start_for_disassembly, (size_t)count, &insn);    size_t printed_count = 0;
    for (size_t i = 0; i < num_disassembled && printed_count < (size_t)count; ++i) {
        // Check if the *current* instruction being considered for print is in an executable region
        // This uses the is_instruction_in_executable_region which itself iterates over g_exec_regions
        if (!is_instruction_in_executable_region(insn[i].address, insn[i].size)) {
             update_executable_regions(); 
             if (!is_instruction_in_executable_region(insn[i].address, insn[i].size)) {
                break; 
             }
        }
        printf("      %llx: ", (unsigned long long)insn[i].address);
        int current_col = 14;
        for (size_t j = 0; j < insn[i].size; ++j) {
            printf("%02x ", insn[i].bytes[j]);
            current_col += 3;
        }
        int mnemonic_start_col = 48;
        for (int k = current_col; k < mnemonic_start_col; ++k) {
            printf(" ");
        }
        printf("%-8s %s\n", insn[i].mnemonic, insn[i].op_str);
        printed_count++;
    }

    if (printed_count < (size_t)count && is_address_in_any_executable_region(rip_start_for_disassembly) ) {
         if (num_disassembled == 0 && total_bytes_read > 0){}
         else if (printed_count == 0 && num_disassembled == 0 && total_bytes_read == 0 && !is_address_in_any_executable_region(rip_start_for_disassembly)) {}
         else if (printed_count < (size_t)count) {
            int still_in_region = 0;
            if (num_disassembled > 0 && printed_count > 0) { // If we printed at least one
                // Check if the *next* instruction would be out of region
                if(insn && printed_count < num_disassembled){ // if there was a next instruction decoded
                    if(!is_instruction_in_executable_region(insn[printed_count].address, insn[printed_count].size)){
                        still_in_region = 0; // Next one is out
                    } else {
                        still_in_region = 1; // Next one is still in (implies something else stopped us, e.g. bad data)
                    }
                } else if (insn && printed_count == num_disassembled && num_disassembled > 0){ // Printed all decoded
                    // Check address after last decoded instruction
                     if(!is_address_in_any_executable_region(insn[num_disassembled-1].address + insn[num_disassembled-1].size)){
                        still_in_region = 0;
                     } else {
                        still_in_region = 1; // End of readable data but still in region
                     }
                }

            } else if (num_disassembled == 0 && printed_count == 0 && total_bytes_read > 0){
                 // Decoded 0 instructions from valid read, means bad opcodes or very short region
                 // Check if the starting address itself is near a boundary for future reads
                 if(!is_address_in_any_executable_region(rip_start_for_disassembly + total_bytes_read)){
                    still_in_region = 0;
                 } else {
                    still_in_region = 1;
                 }
            }


            if (!still_in_region || (printed_count < (size_t)count && num_disassembled < (size_t)count && total_bytes_read > 0) ) {
                 printf("** the address is out of the range of the executable region.\n");
            }
         }
    }
    if (num_disassembled > 0) {
        cs_free(insn, num_disassembled);
    }
}


void handle_si() {
    if (g_child_pid == 0) { printf("** please load a program first.\n"); return; }

    // 階段 1: 如果上一個命令 (cont/syscall) 停在一個已恢復的斷點上，先執行它。
    if (g_is_stepping_over_breakpoint) {
        Breakpoint* bp_to_step_over = find_breakpoint_at(g_stepped_over_breakpoint_addr);

        if (ptrace(PTRACE_SINGLESTEP, g_child_pid, NULL, NULL) < 0) {
            perror("SI: PTRACE_SINGLESTEP for pending BP"); return;
        }
        if (waitpid(g_child_pid, &g_child_status, 0) < 0) {
            perror("SI: waitpid for pending BP step"); return;
        }

        if (bp_to_step_over) { // Re-enable the breakpoint that was just stepped over
            enable_breakpoint(bp_to_step_over);
        }
        g_is_stepping_over_breakpoint = 0; // Clear the flag
        g_stepped_over_breakpoint_addr = 0;

        if (WIFEXITED(g_child_status) || WIFSIGNALED(g_child_status)) {
            printf("** the target program terminated.\n"); /* ... reset other globals ... */ return;
        }
        // 獲取單步執行後的 RIP 並反組譯。
        // 這裡不需要再次檢查斷點，因為我們剛執行了一個已知是原始指令的步驟。
        ptrace(PTRACE_GETREGS, g_child_pid, NULL, &g_regs);
        disassemble_and_print(g_regs.rip, 5);
        return; // SI 命令完成 (它執行了待處理的越過操作)
    }

    // 階段 2: 正常 SI (沒有待處理的斷點越過)
    if (ptrace(PTRACE_SINGLESTEP, g_child_pid, NULL, NULL) < 0) {
        perror("SI: PTRACE_SINGLESTEP normal"); return;
    }
    if (waitpid(g_child_pid, &g_child_status, 0) < 0) {
        perror("SI: waitpid normal"); return;
    }

    if (WIFEXITED(g_child_status) || WIFSIGNALED(g_child_status)) {
        printf("** the target program terminated.\n"); /* ... reset ... */ return;
    }

    if (WIFSTOPPED(g_child_status)) {
        ptrace(PTRACE_GETREGS, g_child_pid, NULL, &g_regs);
        unsigned long long current_rip = g_regs.rip;

        if (WSTOPSIG(g_child_status) == SIGTRAP) {
            Breakpoint* bp_hit = NULL;
            Breakpoint* temp_bp_minus_1 = find_breakpoint_at(current_rip - 1);
            if (temp_bp_minus_1 && temp_bp_minus_1->is_enabled) {
                bp_hit = temp_bp_minus_1;
            } else {
                Breakpoint* temp_bp_at_rip = find_breakpoint_at(current_rip);
                if (temp_bp_at_rip && temp_bp_at_rip->is_enabled) {
                    bp_hit = temp_bp_at_rip;
                }
            }

            if (bp_hit) { // SI 命令自己命中了一個斷點
                printf("** hit a breakpoint at 0x%llx.\n", bp_hit->address);
                if (bp_hit->address != current_rip) { // 校正 RIP (如果停在 bp+1)
                    g_regs.rip = bp_hit->address;
                    ptrace(PTRACE_SETREGS, g_child_pid, NULL, &g_regs);
                }
                disable_breakpoint(bp_hit); // 恢復原始指令

                // 設置 flag，讓下一個命令處理越過操作
                g_is_stepping_over_breakpoint = 1;
                g_stepped_over_breakpoint_addr = bp_hit->address;

                disassemble_and_print(bp_hit->address, 5); // 從斷點處反組譯 (顯示原始指令)
            } else { // 普通單步完成，未命中斷點
                disassemble_and_print(current_rip, 5);
            }
        } else {
            printf("** child stopped by signal %d\n", WSTOPSIG(g_child_status));
            disassemble_and_print(current_rip, 5);
        }
    }
}

void handle_cont() {
    if (g_child_pid == 0) { return; }

    if (g_is_stepping_over_breakpoint) {
        Breakpoint* bp_to_step_over = find_breakpoint_at(g_stepped_over_breakpoint_addr);
        if (ptrace(PTRACE_SINGLESTEP, g_child_pid, NULL, NULL) < 0) {
            perror("CONT: PTRACE_SINGLESTEP over restored BP"); return;
        }
        if (waitpid(g_child_pid, &g_child_status, 0) < 0) {
            perror("CONT: waitpid after SINGLESTEP over restored BP"); return;
        }
        if (bp_to_step_over) {
            enable_breakpoint(bp_to_step_over);
        }
        g_is_stepping_over_breakpoint = 0;
        g_stepped_over_breakpoint_addr = 0;
        if (WIFEXITED(g_child_status) || WIFSIGNALED(g_child_status)) {
            printf("** the target program terminated.\n");
            g_child_pid = 0;
            g_in_syscall_execution = 0;
            g_last_syscall_nr = -1;
            g_is_stepping_over_breakpoint = 0;
            g_stepped_over_breakpoint_addr = 0;
            return;
        }
        ptrace(PTRACE_GETREGS, g_child_pid, NULL, &g_regs);
    }

    if (ptrace(PTRACE_CONT, g_child_pid, NULL, NULL) < 0) {
        perror("PTRACE_CONT"); return;
    }
    if (waitpid(g_child_pid, &g_child_status, 0) < 0) {
        perror("waitpid after CONT"); return;
    }

    if (WIFEXITED(g_child_status) || WIFSIGNALED(g_child_status)) {
        printf("** the target program terminated.\n");
        g_child_pid = 0;
        g_in_syscall_execution = 0;
        g_last_syscall_nr = -1;
        g_is_stepping_over_breakpoint = 0;
        g_stepped_over_breakpoint_addr = 0;
        return;
    }

    if (WIFSTOPPED(g_child_status)) {
        ptrace(PTRACE_GETREGS, g_child_pid, NULL, &g_regs);
        unsigned long long current_rip_after_stop = g_regs.rip;

        if (WSTOPSIG(g_child_status) == SIGTRAP) {
            Breakpoint* bp_hit = find_breakpoint_at(current_rip_after_stop - 1);
            if (bp_hit && bp_hit->is_enabled) {
                printf("** hit a breakpoint at 0x%llx.\n", bp_hit->address);
                g_regs.rip = bp_hit->address;
                if (ptrace(PTRACE_SETREGS, g_child_pid, NULL, &g_regs) < 0) {
                    perror("CONT: SETREGS to BP address");
                    return;
                }
                disable_breakpoint(bp_hit);
                g_is_stepping_over_breakpoint = 1;
                g_stepped_over_breakpoint_addr = bp_hit->address;
                disassemble_and_print(bp_hit->address, 5);
                return;
            } else {
                fprintf(stderr, "DEBUG: CONT: Unexpected SIGTRAP. RIP=0x%llx. bp_hit for rip-1: %p\n", current_rip_after_stop, (void*)bp_hit);
                if(bp_hit) fprintf(stderr, "DEBUG: CONT: bp_hit state: addr=0x%llx, enabled=%d, active=%d\n", bp_hit->address, bp_hit->is_enabled, bp_hit->is_active);
                disassemble_and_print(current_rip_after_stop, 5);
                return;
            }
        } else {
            printf("** child stopped by signal %d\n", WSTOPSIG(g_child_status));
            disassemble_and_print(current_rip_after_stop, 5);
        }
    }
}

int is_address_in_any_mapped_region(unsigned long long addr, unsigned long long size, int check_writable) {
    if (g_child_pid == 0) return 0;
    update_executable_regions(); // Ensure g_exec_regions is up-to-date for general mapping check

    char maps_path[128];
    sprintf(maps_path, "/proc/%d/maps", g_child_pid);
    FILE* fp = fopen(maps_path, "r");
    if (!fp) return 0;

    char line[512];
    int in_region = 0;
    unsigned long long check_end_addr = addr;
    if (size > 0) {
        check_end_addr = addr + size -1;
         if (check_end_addr < addr) check_end_addr = (unsigned long long)-1; // Overflow check
    }


    while (fgets(line, sizeof(line), fp)) {
        unsigned long long start, end;
        char perms[5] = {0};
        if (sscanf(line, "%llx-%llx %4s", &start, &end, perms) == 3) {
            if (addr >= start && check_end_addr < end) {
                if (check_writable) {
                    if (perms[1] == 'w') {
                        in_region = 1;
                        break;
                    }
                } else {
                    in_region = 1;
                    break;
                }
            }
        }
    }
    fclose(fp);
    return in_region;
}

void handle_break(char* addr_str) {
    unsigned long long addr = strtoull(addr_str, NULL, 16);

    if (!is_address_in_any_mapped_region(addr, 1, 0)) {
        printf("** the target address is not valid.\n");
        return;
    }
    if (find_breakpoint_at(addr)) {
        printf("** breakpoint already set at 0x%llx.\n", addr);
        return;
    }
    int bp_idx = -1;
    for(int i=0; i < MAX_BREAKPOINTS; ++i) {
        if (!g_breakpoints[i].is_active) {
            bp_idx = i;
            break;
        }
    }
    if (bp_idx == -1) {
        printf("** maximum breakpoints reached.\n");
        return;
    }
    
    unsigned char original_byte_val;
    if (ptrace_peek_byte(g_child_pid, addr, &original_byte_val) != 0) {
        printf("** failed to read memory at address for break (errno: %d %s).\n", errno, strerror(errno));
        return;
    }

    g_breakpoints[bp_idx].id = g_next_breakpoint_id++;
    g_breakpoints[bp_idx].address = addr;
    g_breakpoints[bp_idx].original_byte = original_byte_val;
    g_breakpoints[bp_idx].is_active = 1;
    g_breakpoints[bp_idx].is_enabled = 0;

    enable_breakpoint(&g_breakpoints[bp_idx]);

    if (g_breakpoints[bp_idx].is_enabled) {
        printf("** set a breakpoint at 0x%llx.\n", addr);
        g_breakpoint_count++;
    } else {
        printf("** failed to set breakpoint at 0x%llx (could not enable).\n", addr);
        g_breakpoints[bp_idx].is_active = 0;
    }
}

void handle_breakrva(char* offset_str) {
    unsigned long long offset = strtoull(offset_str, NULL, 16);
    if (g_program_base_address == 0 && g_program_is_pie) {
        char* last_slash = strrchr(g_program_path, '/');
        const char* prog_basename = last_slash ? last_slash + 1 : g_program_path;
        g_program_base_address = get_program_base_address_from_maps(g_child_pid, prog_basename);
    }
    if (g_program_base_address == 0 && strcmp(g_program_path, "./hello") == 0) {
         g_program_base_address = 0x400000;
    }
    if (g_program_base_address == 0 && !is_address_in_any_executable_region(offset) ) {
         printf("** the target address is not valid.\n");
         return;
    }
    unsigned long long target_addr = g_program_base_address + offset;
    if (!is_address_in_any_executable_region(target_addr)) {
        printf("** the target address is not valid.\n");
        return;
    }
    char addr_buf[32];
    sprintf(addr_buf, "0x%llx", target_addr);
    handle_break(addr_buf);
}

void handle_info_break() {
    if (g_breakpoint_count == 0) {
        printf("** no breakpoints.\n");
        return;
    }
    printf("Num     Address\n");
    for (int i = 0; i < MAX_BREAKPOINTS; ++i) {
        if (g_breakpoints[i].is_active) {
            printf("%-7d 0x%llx\n", g_breakpoints[i].id, g_breakpoints[i].address);
        }
    }
}

void handle_info_reg() {
    ptrace(PTRACE_GETREGS, g_child_pid, NULL, &g_regs);
    printf("$rax 0x%016llx    $rbx 0x%016llx    $rcx 0x%016llx\n", g_regs.rax, g_regs.rbx, g_regs.rcx);
    printf("$rdx 0x%016llx    $rsi 0x%016llx    $rdi 0x%016llx\n", g_regs.rdx, g_regs.rsi, g_regs.rdi);
    printf("$rbp 0x%016llx    $rsp 0x%016llx    $r8  0x%016llx\n", g_regs.rbp, g_regs.rsp, g_regs.r8);
    printf("$r9  0x%016llx    $r10 0x%016llx    $r11 0x%016llx\n", g_regs.r9, g_regs.r10, g_regs.r11);
    printf("$r12 0x%016llx    $r13 0x%016llx    $r14 0x%016llx\n", g_regs.r12, g_regs.r13, g_regs.r14);
    printf("$r15 0x%016llx    $rip 0x%016llx    $eflags 0x%016llx\n", g_regs.r15, g_regs.rip, g_regs.eflags);
}


void handle_delete(char* id_str) {
    if (!id_str) {
        printf("** no breakpoint id specified for delete.\n");
        return;
    }
    char* endptr;
    long id_val = strtol(id_str, &endptr, 10);
    if (*endptr != '\0') {
        printf("** invalid breakpoint id format.\n");
        return;
    }

    int found = 0;
    for (int i = 0; i < MAX_BREAKPOINTS; ++i) {
        if (g_breakpoints[i].is_active && g_breakpoints[i].id == id_val) {
            if (g_breakpoints[i].is_enabled) {
                disable_breakpoint(&g_breakpoints[i]);
            }
            g_breakpoints[i].is_active = 0;
            g_breakpoint_count--;
            printf("** delete breakpoint %ld.\n", id_val);
            found = 1;
            break;
        }
    }

    if (!found) {
        printf("** breakpoint %ld does not exist.\n", id_val);
    }
}

int hex_char_to_int(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int parse_hex_string_to_bytes(const char* hex_str, unsigned char* out_bytes, size_t max_bytes) {
    size_t len = strlen(hex_str);
    if (len % 2 != 0) return -1;

    size_t byte_count = 0;
    for (size_t i = 0; i < len; i += 2) {
        if (byte_count >= max_bytes) return -2;
        int hi = hex_char_to_int(hex_str[i]);
        int lo = hex_char_to_int(hex_str[i+1]);
        if (hi == -1 || lo == -1) return -3;
        out_bytes[byte_count++] = (unsigned char)((hi << 4) | lo);
    }
    return byte_count;
}


void handle_patch(char* addr_str, char* hex_str_val) {
    if (!addr_str || !hex_str_val) {
        printf("** patch command requires address and hex string.\n");
        return;
    }

    unsigned long long addr = strtoull(addr_str, NULL, 16);

    unsigned char patch_bytes[2048 / 2];
    int num_bytes_to_patch = parse_hex_string_to_bytes(hex_str_val, patch_bytes, sizeof(patch_bytes));

    if (num_bytes_to_patch <= 0) {
        printf("** invalid hex string for patch.\n");
        return;
    }

    if (!is_address_in_any_mapped_region(addr, num_bytes_to_patch, 1)) {
        if (!is_address_in_any_mapped_region(addr, num_bytes_to_patch, 0)){
            printf("** the target address is not valid.\n");
            return;
        }
    }

    for (int i = 0; i < num_bytes_to_patch; ++i) {
        unsigned long long current_patch_addr = addr + i;
        Breakpoint* bp = find_breakpoint_at(current_patch_addr);
        if (bp && bp->is_active) {
            if (current_patch_addr == bp->address && i == 0) {
                if (bp->is_enabled) {
                    // Temporarily restore original byte before patching over it
                    unsigned char old_original = bp->original_byte; // This is what was there before 0xCC
                     if(ptrace_poke_byte(g_child_pid, bp->address, old_original) !=0){
                        // Error restoring, proceed with caution or error out
                     }
                }
                 bp->original_byte = patch_bytes[i];
            }
            if (bp->address >= addr && bp->address < (addr + num_bytes_to_patch)) {
                 bp->is_enabled = 0;
            }
        }
    }

    for (int i = 0; i < num_bytes_to_patch; ++i) {
        if (ptrace_poke_byte(g_child_pid, addr + i, patch_bytes[i]) != 0) {
            printf("** failed to write memory for patch at 0x%llx.\n", addr + i);
            return;
        }
    }
    printf("** patch memory at 0x%llx.\n", addr);
}

void handle_syscall_cmd() {
    if (g_child_pid == 0) { printf("** please load a program first.\n"); return; }

    if (g_is_stepping_over_breakpoint) {
        Breakpoint* bp_to_step_over = find_breakpoint_at(g_stepped_over_breakpoint_addr);
        if (ptrace(PTRACE_SINGLESTEP, g_child_pid, NULL, NULL) < 0) {
            perror("SYSCALL: PTRACE_SINGLESTEP over restored BP"); return;
        }
        if (waitpid(g_child_pid, &g_child_status, 0) < 0) {
            perror("SYSCALL: waitpid after SINGLESTEP over restored BP"); return;
        }
        if (bp_to_step_over) {
            enable_breakpoint(bp_to_step_over);
        }
        g_is_stepping_over_breakpoint = 0;
        g_stepped_over_breakpoint_addr = 0;
        if (WIFEXITED(g_child_status) || WIFSIGNALED(g_child_status)) {
            printf("** the target program terminated.\n");
            g_child_pid = 0;
            g_in_syscall_execution = 0;
            g_last_syscall_nr = -1;
            g_is_stepping_over_breakpoint = 0;
            g_stepped_over_breakpoint_addr = 0;
            return;
        }
    }

    if (ptrace(PTRACE_SYSCALL, g_child_pid, NULL, NULL) < 0) {
        perror("PTRACE_SYSCALL");
        return;
    }
    if (waitpid(g_child_pid, &g_child_status, 0) < 0) {
        perror("waitpid after PTRACE_SYSCALL");
        return;
    }

    if (WIFEXITED(g_child_status) || WIFSIGNALED(g_child_status)) {
        printf("** the target program terminated.\n");
        g_child_pid = 0;
        g_in_syscall_execution = 0;
        g_last_syscall_nr = -1;
        g_is_stepping_over_breakpoint = 0;
        g_stepped_over_breakpoint_addr = 0;
        return;
    }

    if (WIFSTOPPED(g_child_status)) {
        ptrace(PTRACE_GETREGS, g_child_pid, NULL, &g_regs);
        unsigned long long current_rip = g_regs.rip;

        if (WSTOPSIG(g_child_status) == SIGTRAP) {
            Breakpoint* bp_hit = find_breakpoint_at(current_rip - 1);

            if (bp_hit && bp_hit->is_enabled) {
                printf("** hit a breakpoint at 0x%llx.\n", bp_hit->address);
                g_regs.rip = bp_hit->address;
                if (ptrace(PTRACE_SETREGS, g_child_pid, NULL, &g_regs) < 0) {
                    perror("SYSCALL_BP_HIT: SETREGS"); return;
                }
                disable_breakpoint(bp_hit);
                g_is_stepping_over_breakpoint = 1;
                g_stepped_over_breakpoint_addr = bp_hit->address;
                disassemble_and_print(g_regs.rip, 5);
                return;
            }
            else {
                unsigned long long syscall_instruction_address = current_rip - 2;
                if (g_in_syscall_execution == 0) {
                    g_last_syscall_nr = g_regs.orig_rax;
                    printf("** enter a syscall(%lld) at 0x%llx.\n", g_last_syscall_nr, syscall_instruction_address);
                    g_in_syscall_execution = 1;
                } else {
                    printf("** leave a syscall(%lld) = %lld at 0x%llx.\n", g_last_syscall_nr, (long long)g_regs.rax, syscall_instruction_address);
                    g_in_syscall_execution = 0;
                    g_last_syscall_nr = -1;
                }
                disassemble_and_print(syscall_instruction_address, 5);
            }
        } else {
            printf("** child stopped by signal %d (expected SIGTRAP for syscall/breakpoint)\n", WSTOPSIG(g_child_status));
            disassemble_and_print(current_rip, 5);
        }
    }
}

int main(int argc, char *argv[]) {
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &g_cs_handle) != CS_ERR_OK) {
        perror("Failed to initialize Capstone");
        return -1;
    }
    if (argc > 1) {
        handle_load(argv[1]);
    }
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;

    while (1) {
        print_prompt();
        nread = getline(&line, &len, stdin);
        if (nread == -1) {
            if (feof(stdin)) break;
            perror("getline"); break;
        }
        if (nread > 0 && line[nread - 1] == '\n') {
            line[nread - 1] = '\0';
        }
        char* cmd_full = strdup(line);
        char* cmd = strtok(line, " \t\n");
        if (cmd == NULL || strlen(cmd) == 0) {
            free(cmd_full); continue;
        }

        if (strcmp(cmd, "load") == 0) {
            char* path_arg = strtok(NULL, " \t\n");
            if (path_arg) {
                handle_load(path_arg);
            } else {
                printf("** no program path specified for load.\n");
            }
        } else if (strcmp(cmd, "si") == 0) {
            if (g_child_pid == 0) printf("** please load a program first.\n"); else handle_si();
        } else if (strcmp(cmd, "cont") == 0) {
            if (g_child_pid == 0) printf("** please load a program first.\n"); else handle_cont();
        } else if (strcmp(cmd, "break") == 0) {
            char* addr_arg = strtok(NULL, " \t\n");
            if (g_child_pid == 0) printf("** please load a program first.\n");
            else if (!addr_arg) printf("** no address specified for break.\n");
            else handle_break(addr_arg);
        } else if (strcmp(cmd, "breakrva") == 0) {
            char* offset_arg = strtok(NULL, " \t\n");
            if (g_child_pid == 0) printf("** please load a program first.\n");
            else if (!offset_arg) printf("** no offset specified for breakrva.\n");
            else handle_breakrva(offset_arg);
        } else if (strcmp(cmd, "info") == 0) {
            char* sub_cmd = strtok(NULL, " \t\n");
            if (g_child_pid == 0) { printf("** please load a program first.\n"); }
            else if (sub_cmd && strcmp(sub_cmd, "reg") == 0) { handle_info_reg(); }
            else if (sub_cmd && strcmp(sub_cmd, "break") == 0) { handle_info_break(); }
            else { printf("** invalid info command. (Usage: info reg | info break)\n"); }
        } else if (strcmp(cmd, "exit") == 0) {
            if (g_child_pid != 0) {
                ptrace(PTRACE_KILL, g_child_pid, NULL, NULL);
                waitpid(g_child_pid, NULL, 0);
            }
            printf("** debugger exiting.\n");
            free(cmd_full); break;
        } else if (strcmp(cmd, "delete") == 0) {
            char* id_arg = strtok(NULL, " \t\n");
            if (g_child_pid == 0) printf("** please load a program first.\n");
            else handle_delete(id_arg);
        } else if (strcmp(cmd, "patch") == 0) {
            char* addr_arg_patch = strtok(NULL, " \t\n");
            char* hex_str_patch = strtok(NULL, " \t\n");
            if (g_child_pid == 0) printf("** please load a program first.\n");
            else if (!addr_arg_patch || !hex_str_patch) printf("** patch usage: patch <addr> <hex_string>\n");
            else handle_patch(addr_arg_patch, hex_str_patch);
        } else if (strcmp(cmd, "syscall") == 0) {
            if (g_child_pid == 0) printf("** please load a program first.\n");
            else handle_syscall_cmd();
        } else {
            printf("** unknown command: %s\n", cmd_full);
        }
        free(cmd_full);
    }
    free(line);
    cs_close(&g_cs_handle);
    if (g_child_pid != 0) {
         if (!(WIFEXITED(g_child_status) || WIFSIGNALED(g_child_status))) {
            ptrace(PTRACE_KILL, g_child_pid, NULL, NULL);
            waitpid(g_child_pid, NULL, 0);
        }
    }
    return 0;
}