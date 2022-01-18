#!/usr/bin/env python3

from Crypto.Util.number import getStrongPrime, inverse
from json import loads, dumps
import hashlib, sys, os, signal, random
from secret import FLAG # type: str

p = getStrongPrime(1024)
secret = random.randint(1, p - 1)

def get_signature(code):
    y = int(hashlib.sha256(code.encode()).hexdigest(), 16)
    r = ((y ** 5 + y + 1) * (secret ** 3 - 1)) % p
    s = ((y **3 - y ** 2 + 1) * (secret **2 + secret + 1) ) % p
    return {'s': hex(s), 'r': hex(r), 'p': hex(p)}

class Signer:
    def __init__(self):
        print("WELCOME to our signing service, connect as root and get the flag")

    def start(self):
        try:
            while True:
                print("\n1- Connect to the data center")
                print("2- Get a digital signature")
                print("3- Quit")
                c = input("> ")

                if c == '1':
                    root_word = loads(input("\nEnter the root word : "))
                    if root_word == get_signature("shellmates"):
                        print(f"Here is your flag : {FLAG}")
                    else:
                        print("For the root only .")
                        sys.exit()

                elif c == '2':
                    word = os.urandom(16).hex()
                    print(f"\nWord: {word}")
                    print(f"Your ticket : {dumps(get_signature(word))}")

                elif c == '3':
                    print("Goodbye :)")
                    sys.exit()

        except Exception:
            print("System error.")
            sys.exit()


signal.alarm(360)
if __name__ == "__main__":
    challenge = Signer()
    challenge.start()
