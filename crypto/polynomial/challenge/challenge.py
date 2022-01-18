#!/usr/bin/env python3

from Crypto.Util.number import bytes_to_long,long_to_bytes,isPrime
import numpy as np
from secret import flag # type: bytes

Coef = [x for x in flag]

def Poly(value):
    P =[pow(value,i,2**16+1) for i in range(len(Coef))]
    P = np.dot(P,Coef)
    return P%(2**16 + 1)

def Challenge():
    print("Welcome to our server ! ")
    print("You can send us any integer value and we will send you another integer using our polynomial")
    while True:
        try:
            value = input("> ")
            if value == 'quit':
                quit()
            value = int(value)
            enc = Poly(value)
            print(">> ", end="")
            print(enc)
        except ValueError:
            print("Invalid input. ")

if __name__ == "__main__":
    Challenge()
