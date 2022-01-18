## Overview

The challenge is a web API using a python implementation of the TFHE scheme, and more specifically TRLWE ciphertexts, which can encrypt polynomials.
The service offers three different endpoints, one to get one the encrypted flag, encrypt a vector of polynomial coefficients, and decrypt a ciphertext previously returned by the API (except for the flag). To note that the same secret-key is being used by the service, but it's being rotated after a certain period.

## Solution

While the API does check for the flag during decryption, this is an homomorphic scheme, and the attacker can just add or substract a polynomial to the encrypted flag, so that it's not detected as the correct flag during decryption, then do the inverse operation locally after getting the server's response. A python implementation of the solution can be found under `get_flag.py`.

## What to get out of the challenge

While the solution is easy conceptually, it requires the attacker to learn how the scheme works (at least encoding and the addition operation) to be able to implement it, and that's the most important part of CTFs, learning something new :D

