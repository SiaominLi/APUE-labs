#!/usr/bin/env python3
# -*- coding: utf-8 -*-
## Lab sample file for the AUP course by Chun-Ying Huang

## 313552025 Hsiao-Min Li

import sys
import base64
import zlib
from pwn import *
from solpow import solve_pow
from itertools import permutations

def recvmsg(r):
    """ Recieve from Server in Base64"""
    msg = r.recvline().strip()
    msg = base64.b64decode(msg)
    mlen = int.from_bytes(msg[:4], 'big')
    if len(msg) - 4 != mlen:
        print("Received invalid message length")
        return None
    return zlib.decompress(msg[4:]).decode()

def sendmsg(r, msg):
    """ Encoding to Base64 and Sending """
    zm = zlib.compress(msg.encode())
    mlen = len(zm)
    encoded_msg = base64.b64encode(mlen.to_bytes(4, 'little') + zm)
    formatting_msg = b'>>>' + encoded_msg + b'<<<\r\n'
    r.send(formatting_msg)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        ## Remote Server
        r = remote('up.zoolab.org', 10155)
        solve_pow(r)
    else:
        ## Local
        r = process('./guess.dist.py', shell=False)

    # print("*** Starting the guessing game ***")

    print("server msg initial:", recvmsg(r))

    
    while 1:
        resp_enter = recvmsg(r)
        print(f"server msg: {resp_enter}") # recv "enter your input"
        
        guess = input().strip()
        sendmsg(r, guess)
        
        response = recvmsg(r).encode()
        encode_respA = int.from_bytes(response[:4], 'big')
        encode_respB = int.from_bytes(response[5:9], 'big')
        print("server response:", f"{encode_respA}A {encode_respB}B")
        
        resp_pic = recvmsg(r)
        print(f"server msg: {resp_pic}") # recv "pic"
        
        if encode_respA == 4:
            break

    r.close()
# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
