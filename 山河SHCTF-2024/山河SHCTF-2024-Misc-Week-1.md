# 山河SHCTF 2024-Misc-Week 1


## 真真假假?遮遮掩掩!

* zip伪加密010editor修改后解压
* winRAR打开发现提示密码为SHCTF??????FTCHS
* 尝试APCHPR纯数字掩码爆破得到密码SHCTF202410FTCHS
* SHCTF{C0ngr@tu1at1ons_On_Mast3r1ng_mAsk_aTT@ck5!}

## Rasterizing Traffic

* 追踪http流，发现有三个flag.txt，将里面内容拼接后得到 `SHCTF{Congratul@te_on_Y0U_F1nd_th3_wr0ng_answer}`
* 继续追踪http流，发现png存在，用foremost分离出图片
* 注意到（惊人的注意力，，，
* 这是光栅加密或者栅格加密？（其实我也不知道叫啥
* 经过ps手动加上栅格后，经过一定编辑，可以得到如下

![](https://seandictionary.top/wp-content/uploads/2024/10/flag.png)

* SHCTF{1111z_tr@ff1c_aNaLys13}

## 拜师之旅①

* 下载附件发现缺少文件头，补充完整
* 发现kali中无法打开，猜测高宽被修改
* 用脚本爆破

```
#coding=utf-8
import zlib
import struct
#读文件
file = input("输入图片路径：")  #例：C:/example/a.png 没有引号
fr = open(file,'rb').read()
data = bytearray(fr[12:29])
crc32key = eval(str(fr[29:33]).replace('\\x','').replace("b'",'0x').replace("'",''))
#crc32key = 0xCBD6DF8A #补上0x，copy hex value
#data = bytearray(b'\x49\x48\x44\x52\x00\x00\x01\xF4\x00\x00\x01\xF1\x08\x06\x00\x00\x00')  #hex下copy grep hex
n = 4095 #理论上0xffffffff,但考虑到屏幕实际，0x0fff就差不多了
for w in range(n):#高和宽一起爆破
    width = bytearray(struct.pack('>i', w))#q为8字节，i为4字节，h为2字节
    for h in range(n):
        height = bytearray(struct.pack('>i', h))
        for x in range(4):
            data[x+4] = width[x]
            data[x+8] = height[x]
            #print(data)
        crc32result = zlib.crc32(data)
        if crc32result == crc32key:
            print(width,height)
            #写文件
            newpic = bytearray(fr)
            for x in range(4):
                newpic[x+16] = width[x]
                newpic[x+20] = height[x]
            fw = open(file+'.png','wb')#保存副本
            fw.write(newpic)
            fw.close
```

* 得到修复过的图片
* SHCTF{ohhh_rooooxy!}

## 有Wifi干嘛不用呢

* cap是数据包文件，在kali中用wireshark打开发现没有什么有用信息
* 查询搜索引擎关于抓包获取密码的有关操作
* 发现几乎是使用指令对数据包进行字典爆破
* 注意到（惊人的注意力）may文件夹存在，里面文件打开格式几乎一致（除了像是乱码
* 用脚本提取文件中内容，作为字典

```
import os
folder_path = b'C:\Users\XXX\Desktop\desktop\may'  # 替换为实际文件夹路径
output_file = 'output.txt'
with open(output_file, 'w', encoding='utf-8') as outfile:
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        if os.path.isfile(file_path):
            with open(file_path, 'r', encoding='utf-8') as infile:
                content = infile.read()
                outfile.write(content[1:-2] + '\n')

print(f'所有文件的内容已写入 {output_file}')
```

* 在kali中用字典爆破
* sudo aircrack-ng -w 字典 XXX.cap
* 输出 `KEY FOUND! [ 0TUMVxz0JrUSDxHG ]`
* SHCTF{0TUMVxz0JrUSDxHG}

## Quarantine

* 提示说了文件被隔离，所以需要扔到杀软的隔离区里，重新恢复
* [github类似题目wp](https://github.com/OpenDocCN/flygon-ctf-wiki/blob/a8566684f010cf7f1eb9d579b0af26d97b2e3942/docs/BugkuCTF-%E9%83%A8%E5%88%86%E9%A2%98%E8%A7%A3(%E4%B8%80)_z.volcano%E7%9A%84%E5%8D%9A%E5%AE%A2-CSDN%E5%8D%9A%E5%AE%A2_bugkuctf.md?plain=1#L1610)
* 遗憾我电脑始终有权限问题无法复现，但大致操作应该是一样的
