# pyfmt-1

## Write-up

* Challenge source :  

```python
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
```

* At first glance, it looks like the program doesn't have any funny business going on, so no way we can get the flag

* But if anyone with sharp eyes can spot the problem here :  

```python
f"{self.__class__.__name__}({self.name})".format(self=self)
```

The string is getting formatted twice !

* Suppose we pass `test` as the name, this is what would actually happen :
  - `f"{self.__class__.__name__}({self.name})"` first gets formatted to `CTF(test)` (because it's an f-string)
  - `format(self=self)` is called on `CTF(test)` string

* This means that, on the second string formatting using `format(self=self)`, we can make the **value** of our input name get formatted

* So passing `{self.flag}` will actually return the flag as such :  

```txt
CTF(b'shellmates{3v3n_PyTHON_Ha$_fORMAt_$tr1nG_bUg$!!!}')
```

* You can find an automated solve script [here](./solve.py)

## Flag

`shellmates{3v3n_PyTHON_Ha$_fORMAt_$tr1nG_bUg$!!!}`
