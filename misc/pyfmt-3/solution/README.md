# pyfmt-3

## Write-up

* Challenge source :  

```python
#!/usr/bin/env python3

from flag import FLAG

class CTF:
    def __init__(self, name, width):
        self.name = name
        self.width = width
    def __repr__(self):
        return f"{self.__class__.__name__}({{self.name:{self.width}}})".format(self=self)

if __name__ == "__main__":
    print(CTF(input("Name: "), input("Width: ")))
```

* As you can see, a `width` attribute has been added to the class and name is rendered like so : `{{self.name:{self.width}}}`

* So now we can only inject format string payloads in `width` (`self.name` is escaped with double `{}`)

* Now since `{self.width}` is on the modifier side of the format string, we're going to be more constrained with what we can do

* If `self.width` has a numeric value the output `name` will be right padded with spaces to fit in `width` characters

* If you paid attention in the previous `pyfmt` challenges, the flag is actually a `bytes` object

* And the particularity with `bytes` objects in pyhton is that accessing a character by index returns the integer byte value (0-255), which is exactly what we want for `width` !

* Now the plan is to determine, for each character of the flag, its byte value by counting the length of the padded `name` string

* You can find an automated solve script [here](./solve.py)

## Flag

`shellmates{wo0o0w_Y0U_M4$T3r3D_pYthon_fOrmAt_STr1nG$!!}`
