# Signer

## Write-up

We have that `x^5+x+1 = (x^3-x^2+1)(x^2+x+1)` and `(x^3 -1) = (x-1)(x^2+x+1)`, so `r*(s^-1) =( (y^2+y+1) * (secret -1)` and `y = int(hashlib.sha256("shellmates".encode()).hexdigest(), 16)`.  

Now we can easily find the secret: `secret = r*(s*(y^2+y+1))^-1 + 1`

```python
def get_secret(signature):
    r,s,p = signature["r"],signature["s"],signature["p"]
    y = int(hashlib.sha256("shellmates".encode()).hexdigest(), 16)
    secret  =( r*inverse(s*(y**2+y+1)),p) + 1 )% p
    return secret
```

After doing that we can connect as root and get the flag.

## Flag

`shellmates{4lg3br4_15_5o_co0o0l}`
