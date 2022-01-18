# Sigma

## Write-up

It suffices to notice that M is a super increasing sequence, then the knapsack problem will be so easy to solve from "Introduction to mathematical cryptography" (365-372):

```python
def binTostr(a):
    return ''.join(chr(int(a[i:i+8],2)) for i in range(0,len(a),8))

def Decrypt(S):
    sol = ""
    for m in M[::-1]:
        if S>=m:
            sol+="1"
            S-=m
        else:
            sol+="0"
    return sol

print(binTostr(Decrypt(S)[::-1]))
```

## Flag

`shellmates{Kn4p54ck_Cryp70_Sys73m}`
