**Active Me**
---
Reverse Engineering

Description:
---
> My product key has expired. Please help me active. Author: BreakerBK

*Nhận định của riêng mình*:
Mình thấy bài này dễ hơn bài LOL Time mà sao ít người làm, trong khi đó LOL Time thì đông thế :disappointed_relieved:

Solution:
---


Load vào `IDA`, mở tab `Strings window` và trace theo dòng chữ `Congratulation! Flag is Serial key` ta sẽ thấy có 1 hàm kiểm tra trước khi 
gọi ra MessageBox này. Hàm này sau khi phân tích thì được giả mã như sau:
```C
int __thiscall sub_401070(HWND hDlg)
{
  HWND v1; // esi
  int i; // esi
  int j; // edi
  int v4; // eax
  int result; // eax
  char v6; // [esp+4h] [ebp-20Ch]
  CHAR String; // [esp+108h] [ebp-108h]

  v1 = hDlg;
  srand(0x3039u);
  if ( !GetDlgItemTextA(v1, 1001, &String, 260) )
    goto LABEL_13;
  for ( i = rand(); i < 357913941; i = rand() + 4 * i )
    ;
  for ( j = rand(); j < 715827882; j = rand() + 4 * j )
    ;
  sub_401010(&v6, "%08X-%08X", i);  // <--- Chỗ này là key
  v4 = strcmp(&v6, &String);
  if ( v4 )
    v4 = -(v4 < 0) | 1;
  if ( v4 )
LABEL_13:
    result = 0;
  else
    result = 1;
  return result;
}
```
Bài này tạo key ngay trong chương trình mà lại chả mã hoá gì. Bây giờ có 2 cách, `khổ trước sướng sau` hoặc `sướng trước khổ sau`.
Mình chọn cách 1 :satisfied: 

Nói là khổ thôi chứ chỉ việc copy đoạn code này vào và chạy ra key:
```C
#include <stdio.h>
#include <stdlib.h>

int main()
{
	int i; // esi
	int j; // edi
	int v4; // eax
	int result; // eax
	char v6[500]; // [esp+4h] [ebp-20Ch]
	char String[500]; // [esp+108h] [ebp-108h]

	srand(12345u);
	for (i = rand(); i < 357913941; i = rand() + 4 * i)
		;
	for (j = rand(); j < 715827882; j = rand() + 4 * j)
		;
	printf("%08X-%08X\n", i, j);
}
```
Được key là: `3831FEB4-6F474E60`. Submit flag thôi: `PTITCTF{3831FEB4-6F474E60}`
