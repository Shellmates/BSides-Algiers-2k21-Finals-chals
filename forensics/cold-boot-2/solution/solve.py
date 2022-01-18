#!/usr/bin/env python3

import string

N = "bc15d387b3d55c96ba7a525627749abe3c739972d5dec3e3ab1cc726560883561ef03b6a0db5c4b1c064d1a6513a69ec21cbc4e8f4721ce24412d198b5a01b144c026b408c2273a75fd68f22057ffa90e7c13b6930db7093203b2fc429f06c8155486f9ed2c83856f12d9fd5c46a2596644cfa3558d5e75472212d97100e48c786974f9679f63c2a397e4377f3356193dd1a67632b2a43e7d75d45945292a3e0eb123b4e1ea87d24d668e9963160998a6be2c91239a506c43da84ae10cdd19d8dfb14ea4036505ec87c9404dfa51cd0666db5bc91bcf31ec8fb4bc804b37432883460c8746a116c12556c36d7a6cda044b495878bf35d7f89230f2b361167b3b"

e = "10001"
d = "67774a4a186f82e39?e9ba?99?82dead4febf???e8?50745b2d7bde6?4e5c1f?1a42e52c4e2673??a478d1abc0?b75d16?3?08?8?e6067eb?0?f69?5ac444b213b3f09?914adcf1?7feb3409ef249bde22df75a3443133187c?e92c4429df3d2?1?b9b1??fb05cedd6f6d63?6e364?3f19260f6e?15???518607?261?b7fe02?8f92a3f?f5f9d47dd774?5a1c8??a81?7?e968777?04760d193dd3a968?8726a6?f?2ef769516f7?37b1?a?a2408bb337?5d827?4b477736ecc0ce7?fb3261f8?7fd479db7aab5050d6d8ffa?ce6b2eb3b0e88?79?b0d?8a9635?5272?a9b63?6?139d5690?cc?275?a2a50?9?2200430d333711ffcf65ff54?cfd4ffc?afb2?"

p = "??f7?06006f6a1f33acc519??e?5?52?7501320d6a4df22abce07f12499?7d3ec7f8c992ff34b9d978?1569d589c?84c633679??1df0b0eefa?ddaa37fa788?acd33a252d7?02f1996390168d87b82af822edc8dd02550637012?25b85e?5f7a??e48?c52cb0?f3ac42??e81d19063670e?ae06e89d32efa????babf3b73ce3?17"
q = "??c2?a1fad?6f763619486?e335f4?11?9e?4b7f7ca53c9?737bb7?7??ac2c9b?6c3f24a46?6f2866edf?0e7?d5ce30aa18d65bbe1?b1ef6e1347a4448?db776??f9a527bedf632a3ad?47971877c8b9ce895?88?731752ee?85108e0ce?8?998a9?9660e?c4aad1??a0709?ae2e?7c??545828821b7?9f0?0?01e29d5?06f7?7d"

# backup of P and Q, used to recover a certain state of P and Q if a wrong choice is made !
pp = "??f7?06006f6a1f33acc519??e?5?52?7501320d6a4df22abce07f12499?7d3ec7f8c992ff34b9d978?1569d589c?84c633679??1df0b0eefa?ddaa37fa788?acd33a252d7?02f1996390168d87b82af822edc8dd02550637012?25b85e?5f7a??e48?c52cb0?f3ac42??e81d19063670e?ae06e89d32efa????babf3b73ce3?17"
qq = "??c2?a1fad?6f763619486?e335f4?11?9e?4b7f7ca53c9?737bb7?7??ac2c9b?6c3f24a46?6f2866edf?0e7?d5ce30aa18d65bbe1?b1ef6e1347a4448?db776??f9a527bedf632a3ad?47971877c8b9ce895?88?731752ee?85108e0ce?8?998a9?9660e?c4aad1??a0709?ae2e?7c??545828821b7?9f0?0?01e29d5?06f7?7d"

hexadecimals = string.hexdigits[:-6]
black_list = []

# generate a possible byte for a missing one
def possibilities(pq) :
    if pq[:2] == "??"  :                                                        # if the whole byte is missing, we go from 00 to ff
        pq_list = [ "{:02x}{}".format(ij, pq[2:]) for ij in range(256) ]
    elif pq[0] == "?" :                                                         # if the left nibble is missing, we go from 0X to fX
        pq_list = [ "{}{}".format(i, pq[1:]) for i in hexadecimals ]        
    elif pq[1] == "?" :                                                         # if the right nibble is missing, we go from X0 to XF
        pq_list = [ "{}{}{}".format(pq[0], j, pq[2:]) for j in hexadecimals ]
    else :
        pq_list =  [pq]

    return pq_list

# checks if a certain Pi multiplied by Qi equals Ni; i represents the position of a missing byte 
def satisfy_mul(pi, qi):
    global N

    mul_p_q = "{:0x}".format( int(pi,16) * int(qi,16) )
    l = len(pi)
    
    if N[-l:] == mul_p_q[-l:] :
       return True
    
    return False

# iterates P and Q from least significant byte and return the first missing byte
def find_empty(p,q):
    for i in range(-2, -260, -2):
        if p[i] == "?" or p[i+1] == "?" or q[i] == "?" or q[i+1] == "?" :
            return i
    
    return 0
        
def solve(p, q):

    # find the first missing least significant byte in P or Q 
    i = find_empty(p,q)

    # if no more missing bytes, then we recovered P and Q
    if i == 0 :
        print("[*] Found p: ", p)
        print("[*] Found q: ", q)
        print("[!] N == p * q: ", int(N,16) == int(p,16) * int(q, 16) )
        return True
    
    # generate a list of the possible Ps and Qs going from the missing byte to the last byte
    p_list = possibilities(p[i:])
    q_list = possibilities(q[i:])

                                                                    
    for pi in p_list :                                              # iterate through each possible P
        for qi in q_list :                                          # iterate through each possible Q
            if (pi,qi) not in black_list and satisfy_mul(pi, qi) :  # check if we have a valid Pi and Qi that satisfies Pi x Qi = Ni and isn't black listed
                p = p[:i] + pi                                      # we fill the missing byte in P using Pi
                q = q[:i] + qi                                      # we fill the missing byte in Q using Qi
                if solve(p, q) :                                    # we recurse in order to find the next missing byte  
                    return True
                
                black_list.append((pi,qi))                          # if we didn't reach True, it means the last Pi and Qi choosen aren't good for the next steps
                p = p[:i] + pp[i:]                                  # we remove the added Pi and Qi using a backup P called pp and a backup Q called qq
                q = q[:i] + qq[i:]                                  # we black list the last Pi and Qi

    return False

if __name__ == '__main__' :
    solve(p, q)