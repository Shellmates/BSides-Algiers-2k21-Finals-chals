# Cold Boot 1

## Write-up

POTENTIAL AES ROUND KEYS DETECTED
---------------------------------
K[ 0] =    47 ?? ?? ca    e6 ?? 55 ??    ?? 83 ?? a6    ?? 34 ?? a0
K[ 1] =    5e ed e? 5b    b8 0c b0 a?    ?5 8f 73 0?    ?? bb 5? af
K[ 2] =    b6 ?4 ?c ed    0e ?? 2c 4?    db ?7 5? ?b    a2 ?? 04 e4
K[ 3] =    7c 2? ?5 d7    72 fe d9 9?    ?9 a9 8? d8    0b ?? 82 3c
K[ 4] =    1a 35 ?e fc    68 cb ?7 6f    c1 ?? ?? b7    ca 2? c3 8b
K[ 5] =    ?6 ?b 23 8?    ae d0 e? e7    ?? b2 a5 50    a? 95 66 ?b
K[ 6] =    ?c 2? 9a 8e    62 f? ?e 69    ?d 4a ?b 3?    a8 df ?d e2
K[ 7] =    12 5? ?2 4c    70 aa 7c ?5    7d e0 a7 1c    d5 3f 1a fe
K[ 8] =    e7 ?? ?? 4f    9? 5a c5 ?a    ea ba 62 76    3? 85 ?8 8?
K[ 9] =    6b 4c 7d 3?    f? 16 b? 50    16 ac da ?6    2? ?9 a? ae
K[10] =    f? ?6 99 9f    ?4 6? 21 cf    ?2 c? f? ?9    3b e5 59 ??

The goal here is to recover the missing bytes ??
We need to understand how AES key schedule works : https://en.wikipedia.org/wiki/AES_key_schedule

In AES-128, the key is splitted into 4 blocks of 4 bytes and then we derive a key in each round. In total we have 10 rounds.
We exclude the 1st round which is the real master key and that's our needed key.

Reading the wikipedia page is somehow more complicated than just watching the picture: 
https://upload.wikimedia.org/wikipedia/commons/thumb/b/be/AES-Key_Schedule_128-bit_key.svg/1024px-AES-Key_Schedule_128-bit_key.svg.png

Analysing the picture, we quickly understand that in most cases each column is the XOR of the column above it and the one before it.
Except for the 1st column which is the result of another operation which we will see later.

So we will start from the last column to the 1st one.
For example the last column of K1 which is :  "?? bb 5? af" is the result of the XOR operation of the column before it 
"?5 8f 73 0?" and the last column of K0 which is above it "?? 34 ?? a0". 
In short : XOR ("?5 8f 73 0?" ^ "?? 34 ?? a0") = "?? bb 5? af"

We will try to find each byte of K0 going from the last one to the first one :

- ?? ^ 73 = 5? -> 
            5? ^ 5? = 04 ->                      we will go down in order to determine the missing byte of K1
                      04 ^ 8? = 82 -> 86
                 5? ^ d9 = 86 -> 5f              we determined the missing byte of K1 
            5? ^ 5f = 04 -> 5b                   
  ?? ^ 73 = 5b -> 28                             now, we determine the missing byte of K0

K[ 0] =    47 ?? ?? ca    e6 ?? 55 ??    ?? 83 ?? a6    ?? 34 28 a0


- ?? ^ ?5 = ?? ->
            ?? ^ db = a2 -> 79 
       ?5 ^ 0e = db -> d5
  ?? ^ d5 = 79  -> ac

K[ 0] =    47 ?? ?? ca    e6 ?? 55 ??    ?? 83 ?? a6    ac 34 28 a0

- ?? ^ b0 = 73 -> c3

K[ 0] =    47 ?? ?? ca    e6 ?? 55 ??    ?? 83 c3 a6    ac 34 28 a0

- ?? ^ b8 = d5 -> 6d

K[ 0] =    47 ?? ?? ca    e6 ?? 55 ??    6d 83 c3 a6    ac 34 28 a0

- ?? ^ 5b = a? ->
            a? ^ a6 = 0f -> a9
  ?? ^ 5b = a9 -> f2

K[ 0] =    47 ?? ?? ca    e6 ?? 55 f2    6d 83 c3 a6    ac 34 28 a0

- ?? ^ ed = 0c -> e1

K[ 0] =    47 ?? ?? ca    e6 e1 55 f2    6d 83 c3 a6    ac 34 28 a0

Now, we arrive to the 1st column of K[1] which is the result of 3 operations applied to the last column of K[0] :

1- Rotate the column by 1 shift to the left
2- Subtitute the bytes using the Sbox table : https://en.wikipedia.org/wiki/Rijndael_S-box 
3- The round constant RCON[i] for round i of the key expansion is the 32-bit word : RCON[i]=[RCi,00,00,00]

https://crypto.stackexchange.com/questions/2418/how-to-use-rcon-in-key-expansion-of-128-bit-advanced-encryption-standard
RCON[1]=[01,00,00,00] 

The result of these operations is XORed then with 1st column of K[0] 

- RotWord(ac 34 28 a0) = 34 28 a0 ac
  SubWord(34 28 a0 ac) = 18 34 e0 91 
  RCON[1][18 34 e0 91] = 19 34 e0 91 
                       ^ 47 ?? ?? ca  -> 47 d9 0? ca
                       = 5e ed e? 5b

K[ 0] =    47 d9 ?? ca    e6 e1 55 f2    6d 83 c3 a6    ac 34 28 a0

-                              e? ^ 55 = b0 -> e5
                               e5 ^ e0 = ?? -> 05

K[ 0] =    47 d9 05 ca    e6 e1 55 f2    6d 83 c3 a6    ac 34 28 a0

The key is : 47 d9 05 ca    e6 e1 55 f2    6d 83 c3 a6    ac 34 28 a0

## Flag

md5(47d905cae6e155f26d83c3a6ac3428a0) = 1a9828ffb1cc9103c72fee534aec1bf1

`shellmates{1a9828ffb1cc9103c72fee534aec1bf1}`
