# 山河SHCTF 2024-Crypto-Week 1


## EzAES

* 反向解密AES，编写脚本

```
from Crypto.Cipher import AES

c = b'Y\xfe\xcf#3\xd0\xe5\xd2\x1c\x88P\x8e\x97]g\x1c\xda7\xe0?\xf0\xedx\xd7\xca\xbf\xcei\xf5\x92\xb9W\xb0\t\xedG\x98\x9a\x14^\x0e\xa6\n\x11F\x96el'
iv = b':\xc4\x89\xb0\x1d\x85u\xe5GT\xe7\xeav\x9b\x0e&'
key = b'\x97\xe5c\xd5\xcd\xf0\xbaL\x974y\xf9\x1d@\x96G'
aes = AES.new(key, AES.MODE_CBC, iv)
m = aes.decrypt(c)
print(m)
```

* 手动去除结尾占位符得到SHCTF{ce64e000-9df0-425f-890c-9117bfc55bf1}

## Hello Crypto

* 字节转长整型，解密长整型转字节编写脚本

```
from Crypto.Util.number import *

m = 215055650564999508008595955251115217121853124218655965176771533623153065935246300580860285105594255592545838379107175445373
print(long_to_bytes(m))
```

* 得到SHCTF{hEllO_ctF3r_W3LC0ME_7o_CryP70_wOR1D_6b74aC13}
