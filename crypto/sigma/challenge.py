#!/usr/bin/env python3

from secret import flag # type: str

def Str2Bin(s):
    return ''.join(bin(ord(i))[2:].zfill(8) for i in s)

flag = [x for x in Str2Bin(flag)]

def Public_Key():
    M = [2]
    x = 2
    for i in range(len(Str2Bin(flag))):
        x = 2 * x + 1
        M.append(x)
    return M

M = Public_Key()

def Encrypt(flag, M):
    S = 0
    for x, m in zip(flag, M):
        S += int(x) * m
    return S

S = Encrypt(flag,M)
print(f"S: {S}")
