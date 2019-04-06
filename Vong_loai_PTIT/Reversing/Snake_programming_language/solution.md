**Snake programming language**
---
Reverse Engineering

Description:
---
> Do you know Reverse Engineering Snake programming language? If you don't, try another way? Author: Shin

Solution:
---

Từ cái mô tả đã thấy bài này nó khác thường rồi. Load IDA lên xem thì không thấy bóng dáng flag ở đâu. Mình nghĩ nó bị pack nên thử detect 
xem là packer nào:

<img src = "/Vong_loai_PTIT/Reversing/Snake_programming_language/1.PNG" class="center">

Không phát hiện packer mà lại còn báo không phải file PE hợp lệ. Quay lại IDA xem kỹ hơn Strings window thì thấy rất nhiều chuỗi `Py_xxxx`, 
`Python DLL` các kiểu. Mình đoán app này viết bằng python rồi dùng tool để convert sang PE File.

Google 1 lúc thì tìm được [tool chuyển ngược lại](https://github.com/countercept/python-exe-unpacker):

```bash
root@kali:~/python-exe-unpacker# python python_exe_unpack.py -i Snake.exe
[*] On Python 2.7
[*] Processing Snake.exe
[*] Pyinstaller version: 2.1+
[*] This exe is packed using pyinstaller
[*] Unpacking the binary now
[*] Python version: 37
[*] Length of package: 4879108 bytes
[*] Found 22 files in CArchive
[*] Beginning extraction...please standby
[!] Warning: The script is running in a different python version than the one used to build the executable
    Run this script in Python37 to prevent extraction errors(if any) during unmarshalling
[!] Unmarshalling FAILED. Cannot extract PYZ-00.pyz. Extracting remaining files.
[*] Successfully extracted pyinstaller exe.
root@kali:~/python-exe-unpacker# cd unpacked/
root@kali:~/python-exe-unpacker/unpacked# cd Snake.exe/
root@kali:~/python-exe-unpacker/unpacked/Snake.exe# ls
 base_library.zip                                   python37.dll
 _bz2.pyd                                           PYZ-00.pyz
 _hashlib.pyd                                       PYZ-00.pyz_extracted
 libcrypto-1_1-x64.dll                              select.pyd
 libssl-1_1-x64.dll                                 _socket.pyd
 _lzma.pyd                                          _ssl.pyd
 pyexpat.pyd                                        struct
 pyiboot01_bootstrap                                Test
 pyimod01_os_path                                   Test.exe.manifest
 pyimod02_archive                                   unicodedata.pyd
 pyimod03_importers                                 VCRUNTIME140.dll
'pyi-windows-manifest-filename Test.exe.manifest'
```
Sau khi xem xét mấy file trong này thì file Test có 1 điều thú zị :grin:
```bash
root@kali:~/python-exe-unpacker/unpacked/Snake.exe# cat Test
�@svddlZed�Ze�e�dZdZxBedee��D]0e	e�e�
dd�ddZ
      ee
        e
e�dS)   �NzInput username: z!PTITCTF{Y0u_kn0w_sn@k3_d3c0mp!l3}��d���azThis is  # <--- Cái gì đây ??
your password: )�random�inputusername�seed�flagpassword�range�len�i�
ord�randint�a�chr�print�rrzTest.py<module>s
```

Submit thôi :joy:
