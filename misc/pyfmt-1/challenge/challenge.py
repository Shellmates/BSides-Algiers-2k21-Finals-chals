#!/usr/bin/env python3

from flag import FLAG

class CTF:
    def __init__(self, name):
        self.name = name
        self.flag = FLAG
    def __repr__(self):
        return f"{self.__class__.__name__}({self.name})".format(self=self)

if __name__ == "__main__":
    print(CTF(input("Name: ")))
