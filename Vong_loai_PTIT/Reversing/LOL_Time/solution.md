**LOL Time**
---
Reverse Engineering

Description:
---
> Did you play LOL? Do you know Yasuo? Author: Shin

Solution:
---

Lại load vào IDA, ngay từ hàm main đã thấy dòng chữ thông báo flag và trước đó là 1 hàm check. Phân tích hàm này được:
```C
int __cdecl sub_4018B6(char *a1) // a1 là key mình nhập vào
{
  const char *v2; // ebx
  BYTE *v3; // eax
  const char *v4; // eax
  int v5; // [esp+1Bh] [ebp-5Dh]
  char v6; // [esp+1Fh] [ebp-59h]
  int v7; // [esp+58h] [ebp-20h]
  int i; // [esp+5Ch] [ebp-1Ch]

  if ( strlen(a1) != 16 )
    return 0;
  v5 = *(_DWORD *)"b7b5266167a6d34c266162bf266163a19df331d3ec32501b849b18d562bf62bf";
  strcpy((char *)&v7, "2bf");
  qmemcpy(
    (void *)((unsigned int)&v6 & 0xFFFFFFFC),
    (const void *)("b7b5266167a6d34c266162bf266163a19df331d3ec32501b849b18d562bf62bf"
                 - ((char *)&v5
                  - ((unsigned int)&v6 & 0xFFFFFFFC))),
    4 * (((unsigned int)((char *)&v5 - ((unsigned int)&v6 & 0xFFFFFFFC) + 65) & 0xFFFFFFFC) >> 2));
  for ( i = 0; i <= 15; ++i )
  {
    v2 = (const char *)sub_401843(&v5, i);
    v3 = (BYTE *)sub_4017BD(a1[i]);
    v4 = (const char *)sub_401500(v3);
    if ( strcmpi(v4, v2) != 0 )
      return 0;
    free(dword_405020);
  }
  return 1;
}
```
Ban đầu nhìn cũng khá hoảng, nhưng mấu chốt chỉ nằm ở vòng lặp `for ( i = 0; i <= 15; ++i )`. Lưu ý key nhập vào có 16 ký tự nhé.

Hàm `sub_401843`lấy ra 4 ký tự lần lượt trong chuỗi v5 thôi:
```C
void *__cdecl sub_401843(int a1, int a2)
{
  void *v3; // [esp+18h] [ebp-10h]
  signed int i; // [esp+1Ch] [ebp-Ch]

  v3 = malloc(5u);
  memset(v3, 0, 5u);
  for ( i = 0; i <= 3; ++i )
    *((_BYTE *)v3 + i) = *(_BYTE *)(4 * a2 + i + a1);
  dword_405020 = v3;
  return v3;
}
```

Hàm `sub_4017BD` thì lần lượt lấy ra 1 ký tự trong key nhập vào:
```C
BYTE *__cdecl sub_4017BD(char a1)
{
  _BYTE *v1; // ST2C_4

  v1 = malloc(2u);
  memset(v1, 0, 2u);
  *v1 = a1;
  return v1;
}
```

Hàm `sub_401500` thì hash MD5 ký tự v3 vừa lấy ra ở key, và trả lại 4 ký tự cuối của chuỗi hash:
```C
...
  if ( CryptAcquireContextA(&phProv, 0, "Microsoft Base Cryptographic Provider v1.0", 1u, 0xF0000000) == 0 )
    return 0;
  if ( CryptCreateHash(phProv, 0x8003u, 0, 0, &phHash) == 0 ) // <--- 0x8003u là flag ứng với CALG_MD5
  {
    CryptReleaseContext(phProv, 0);
    result = 0;
  }
  else
  {
    v2 = strlen((const char *)pbData);
    if ( CryptHashData(phHash, pbData, v2, 0) == 0 )
    {
      CryptReleaseContext(phProv, 0);
      CryptDestroyHash(phHash);
      result = 0;
    }
    else if ( CryptGetHashParam(phHash, 2u, v5, &pdwDataLen, 0) == 0 )
    {
      CryptReleaseContext(phProv, 0);
      CryptDestroyHash(phHash);
      result = 0;
    }
    else
    {
      for ( i = 0; i < pdwDataLen; ++i )
      {
        v10[2 * i] = v11[(signed int)v5[i] >> 4];
        v10[2 * i + 1] = v11[v5[i] & 0xF];
      }
      CryptReleaseContext(phProv, 0);
      CryptDestroyHash(phHash);
      v9 = malloc(5u);
      memset(v9, 0, 5u);
      for ( j = 0; j <= 3; ++j )  // <--- Lấy 4 ký tự cuối
      {
        v3 = (char *)v9 + j;
        v4 = strlen(v10);
        *v3 = v10[v4 - 4 + j];
      }
      result = v9;
    }
  }
  return result;
}
```

OK đã đủ thông tin. Mình sẽ hash MD5 tất cả các ký tự in được từ 32 đến 127 và tìm ra ký tự nào nằm trong key:
```python
import hashlib

table = []
for i in range (32, 127):
	table.append(hashlib.md5(chr(i)).hexdigest()[28:])

s = 'b7b5266167a6d34c266162bf266163a19df331d3ec32501b849b18d562bf62bf'
ans = []
index = 0
while (index < (len(s))):
	ans.append(s[index:index+4])
	index += 4

final = ''
for i in ans:
	if i in table:
		final += chr(table.index(i) + 32)

#Done
print final
```

Key: `DaxuaGankTem15GG` :sunglasses:

Nhập vào chương trình và nhận flag: `PTITCTF{y0u_4r3_b3zt_d4xua}`
