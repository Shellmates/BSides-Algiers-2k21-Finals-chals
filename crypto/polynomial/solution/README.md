# Polynomial

## Write-up

Using lagrange interpolation but in a finite field:

```python
from pwn import *
from sage.all import *

F = GF(2**16 +1)
conn = remote("crypto.ctf.shellmates.club", 1802)
conn.recvline()
conn.recvline()

def printvect(v):
    return "".join(chr(x) for x in v[::-1])
#an estimation for the flag length
for l in range (30,50):
    conn.recvline()
    conn.send(str(1)+'\n')
    v=[]
    M=Matrix(F,[[((x+1) **i) %((2**16 + 1)) for i in range(l)] for x in range(l)])
    for p in range(1,l+1):
        conn.send(str(p) +'\n')
        v.append(int(conn.recvuntil('\n').decode()[20:]))
    V=vector(F,v)
    if ("shellmates{" and "}") in printvect(M.solve_right(V)) :
        print(printvect(M.solve_right(V)))
        break
```

## Flag

`shellmates{___Lagrange__w4s__4__G3n1us___}`
