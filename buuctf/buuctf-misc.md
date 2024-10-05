# [BUUCTF-Misc](https://seandictionary.top/buuctf-misc/)

## 1.签到

## 2.金三胖

* 下载下来一个压缩包
* 解压得到aaa.gif
* 查看，能发现一闪而过的flag
* 拖入kali,执行 `convert aaa.gif a.png`
* 发现三张flag图片，合并得到
* flag{he11ohongke},注意he11o中，不是L。

![](https://seandictionary.top/wp-content/uploads/2024/09/image.png)

## 3.你竟然赶走我

* 同样解压
* 得到一张biubiu.jpg
* 打开无异常
* 拽入010editor
* 发现在文件结尾有flag
* flag{stego_is_s0_bor1ing}

![](https://seandictionary.top/wp-content/uploads/2024/09/image-1-1024x467.png)

## 4.二维码

* 同样解压缩，得到QR_code.png
* 扫描得到secret is here（不死心尝试，果真不是flag）
* 然后扔到010editor发现有多余的内容，能看到有4number.txt存在
* 并且注意到zip格式文件头 `50 4B 03 04`

![](https://seandictionary.top/wp-content/uploads/2024/09/image-2-1024x514.png)

* 用 `binwalk QR_code.png`拆解
* 得到加密的压缩包1D7.zip
* 尝试secret is here作为密码，无果
* 密码没有头绪，用ARCHPR爆破，得到密码

![](https://seandictionary.top/wp-content/uploads/2024/09/image-3.png)

* 解压得到flag{vjpw_wnoei}

## 5.大白

* 解压得到dabai.png
* 拖入kali发现无法打开报错 `IHDR：CRC error`，而win10中正常打开
* 判断出宽高有误
* 原大小为679*256
* 将高改为679（02 A7），即可正常打开
* flag{He1l0_d4_ba1}

![](https://seandictionary.top/wp-content/uploads/2024/09/image-4.png)

## 6.鸟巢峰会种图

* 直接获得jpg图片
* 010editor打开发现结尾存在flag{97314e7864a8f62627b26f3f998c37f1}
* 或者kali中执行 `strings`同样能得到

## 7.wireshark

* 得到pcap流量包
* 扔进kali里用wireshark分析
* 有题目得到是发送给服务器的请求，过滤器用 `http.request.method==POST`
* 得到"password" = "ffb7567a1d4f4abdffdb54e022f8facd"

![](https://seandictionary.top/wp-content/uploads/2024/09/image-6-1024x498.png)

## 8.N种解决方法

* 得到无法打开的exe文件
* 丢到010editor，提示这是个jpg格式的image，以及由base64编码
* 把密文丢到CyberChef，点击魔法棒或者选择base64解码再转化为图片
* 得到一个二维码，扫描
* 结果是KEY{dca57f966e4e4e31fd5b15417da63269}

## 9.基础破解

* 由提示得到是个四位数字密码
* 直接ARCHPR暴力破解，得到密码2563
* 解压得到txt中的内容明显是base64加密
* 解密得到flag
* flag{70354300a5100ba78068805661b93a5c}

## 10.文件中的秘密

* 图片在kali中执行 `exiftool`查看详细信息
* 得到flag{870c5a72806115cb5439345d8b014396}

## 11.LSB

* 得到图片
* 对于 `exiftool`没有结果
* 010editor中IDAT块时有时无
* 由题目提醒得到采用LSB隐写
* 使用StegSlove打开对三通道最低位提取，可以观察到如下

![](https://seandictionary.top/wp-content/uploads/2024/09/image-5-1024x752.png)

* 显然为png图片文件，保存发现是一张二维码
* 扫描的到flag{1sb_i4_s0_Ea4y}

## 12.zip伪加密

* 得到加密zip压缩包
* 用010editor打开，注意到加密位是 `09 00`

![](https://seandictionary.top/wp-content/uploads/2024/09/image-7-1024x321.png)

* 尝试改为 `00 00`
* 成功打开
* 得到flag{Adm1N-B2G-kU-SZIP}

## 13.被嗅探的流量

* 首先的到流量包
* 有题目知道发生了文件传输
* wireshark执行 `http.request.method == "POST"`
* 发现传输了一张flag.jpg文件
* 根据文件头 `FF D8 FF`将传输内容截取，还原为flag.png
* 用010editor打开，发现在文件尾有一串多余字符
* 仔细分辨发现类似flag，尝试，成功
* flag{da73d88936010da1eeeb36e945ec4b97}

![](https://seandictionary.top/wp-content/uploads/2024/09/image-8-1024x423.png)

## 14.rar

* 加密rar文件
* APCHPR爆破四位数字，得到密码 `8795`
* flag{1773c5da790bd3caff38e3decd180eb7}

## 15.qr

* 得到一个二维码，扫描得到
* 欢迎参加本次比赛，密码为 Flag{878865ce73370a4ce607d21ca01b5e59}

## 16.镜子里面的世界

* 一张图片，010editor打开发现文件中IDAT块时有时无
* 果断用StegSlove取最低位，发现flag

## 17.ningen

* 对图片strings
* 发现有文件名存在
* binwalk分离
* 得到加密zip压缩包
* 用ARCHPR爆破得到密码8368
* flag{b025fc9ca797a67d2103bfbc407a6d5f}

## 18.爱因斯坦

* 对图片strings，发现文件名
* binwalk分离
* 压缩包有密码，暴力无法解决
* exiftool查看图片详细内容

![](https://seandictionary.top/wp-content/uploads/2024/09/image-9-1024x674.png)

* 得到密码，成功解压
* flag{dd22a92bf2cceb6c0cd0d6b83ff51606}

## 19.小明的保险箱

* 和17一样
* 分离，爆破
* flag{75a3d68bf071ee188c418ea6cf0bb043}

## 20.easycup

* 追踪TCP流，得到16进制码，转码
* flag{385b87afc8671dee07550290d16a8071}

## 21.隐藏的钥匙

* strings显示字符串，太多不好查找
* strings -n 8显示长度超过8的。得到base64加密的flag，转码
* flag{377cbadda1eca2f2f73d36277781f00a}

![](https://seandictionary.top/wp-content/uploads/2024/09/image-10-1024x557.png)

## 22.另一个世界

* binwalk查看没有隐藏文件
* strings查看得到一串二进制，并且恰好长度为56，8*7，一个字符对应一个字节
* 尝试转码，结果作为flag，成功
* flag{koekj3s}

![](https://seandictionary.top/wp-content/uploads/2024/09/image-11-1024x211.png)

## 23.数据包中的线索

* 对数据包中的HTTP流追踪
* 得到如下

![](https://seandictionary.top/wp-content/uploads/2024/09/image-12-1024x616.png)

* 显然是base64编码，解码，用CyberChef魔法棒，转化得到图片

![](https://seandictionary.top/wp-content/uploads/2024/09/image-13-1024x747.png)

* 此时就能看到flag{209acebf6324a09671abc31c869de72c}

## 24.神秘龙卷风

* ARCHPR爆破得到5463
* 文本中能发现只有 `+.>`，其中+很多，可以猜测与数量有关，那么用脚本计数+，将数量通过ASCII码转化为字符。

```
with open(file_path,'r') as file:
    content = file.read()
    content = "".join(content.split())
ans = ""
counts = 0
for i in content:
    if i == "+":
        counts += 1
    elif i == ".":
        ans += chr(counts)
        counts = 0
    else:
        continue
print(ans)
```

* 结果正确，为flag{e4bbef8bdf9743f8bf5b727a9f6332a8}

之后发现这是一种名为brainfuck的语言。

## 25.FLAG

* 010editor发现很像LSB隐写
* 用StegSlove处理发现有zip压缩文件的影子

![](https://seandictionary.top/wp-content/uploads/2024/09/image-14-1024x752.png)

* 保存为zip打开，显示文件损坏，修复
* 对文件strings得到flag{dd0gf4c3tok3yb0ard4g41n~~~}
* 或者 `chmod +x ./文件名` `./文件名` 打开ELF文件，命令行窗口显示flag{dd0gf4c3tok3yb0ard4g41n~~~}

## 26.假如给我三天光明

* 先对照盲文表得到kmdonowg
* 然后解压发现是摩斯电码，用音频处理软件（我用的是FL Studio）打开

![](https://seandictionary.top/wp-content/uploads/2024/09/image-15-1024x546.png)

* 对照长短，抄收到CTFWPEI08732?23DZ
* 最后删去CTF，改为小写，flag{wpei08732?23dz}

## 27.后门查杀

* 解压到桌面，火绒自动查杀删除 `include/include.php`
* 打开 `include.php`，按照题目提示搜索md5
* 追踪到pass，继续搜索pass
* 得到6ac45fb83b3bc355c024f5034b947dd3
* flag{6ac45fb83b3bc355c024f5034b947dd3}

## 28.webshell后门

* 和27一样，火绒自动查杀，锁定文件位置
* 搜索pass得到flag
* flag{ba8e6c6f35a53933b871480bb9a9545c}

## 29.来首歌吧

* 和26有点像
* 将音频文件放入FL Studio中，能注意到音乐是右声道的
* 在1：11处发现，左声道存在莫斯码

![](https://seandictionary.top/wp-content/uploads/2024/09/image-16-1024x546.png)

* 抄收并转码
* flag{5BC925649CB0188F52E617D70929191C}

## 30.面具下的Flag

* strings发现flag字眼，疑似文件名
* binwalk查看确认含有zip，并分离
* 加密，尝试伪加密直接更改。成功
* 得到flag.vmdk，这是一个虚拟机磁盘映像文件
* 对vmdk文件用7z解压
* 在part1文件夹和part2文件夹中分别发现两个特殊文件NUL和where_is_flag_part_two.txt:flag_part_two_is_here.txt
* 对这两个文件分别进行BrainFuck和Ook！[解码](https://www.splitbrain.org/services/ook)
* 得到两部分flag
* 第一部分 flag{N7F5_AD5
* 第二部分 _i5_funny!}

❓ **疑问：**

为什么我把vmdk文件在VMware软件中直接映射磁盘到电脑后，打开磁盘里面的文件内容对于直接7z解压来说是缺失的，尤其是关键的两个文件都没有

一个part1文件夹中只有文件名为NUL的空文件，一个part2文件夹中只有名为where_is_flag_part_two.txt的文件，打开是Oops,flag_part_two_isn't_here!

为什么会在文件内容上有区别？

**大佬的解释：**

VMware自身的问题 ，修改设置触发了 “未知因素” 使得虚拟机实际的磁盘文件（.vmdk）和配置文件(.vmx)中的参数不匹配造成的，把配置文件中的这项参数修改得和文件夹中真正的快照文件一致，即可恢复正常。

## 31.荷兰宽带数据泄露

* 新工具 RouterPassView
* 用工具打开conf.bin文件，直接查找flag，username，password的值
* 提交后发现答案为username flag{053700357621}

## 32.九连环

* 图片strings分析，发现隐藏文件
* binwalk分离得到加密zip压缩包，没有密码线索
* 010editor尝试伪加密修改，成功
* 对图片执行 `steghide extract -sf`提取隐写文本，密码跳过
* 得到压缩包密码bV1g6t5wZDJif^J7
* flag{1RTo8w@&4nK@z*XL}

## 33.被劫持的神秘礼物

* wireshark打开，过滤HTTP包
* 发现疑似登陆的包，追踪
* 疑似账号密码

![](https://seandictionary.top/wp-content/uploads/2024/09/image-17-1024x638.png)

* CyberChef里对adminaadminb进行MD5转化
* 得到flag{1d240aafe21a86afc11f38a45b541a49}

## 34.[BJDCTF2020]认真你就输了

* 得到一个xls表格文件，excel打开失败
* 放到010editor中，一眼看出zip压缩包格式，更改后缀
* 在该目录下 `10.zip\xl\charts`发现flag.txt文件
* 打开得到flag{M9eVfi2Pcs#}

## 35.被偷走的文件

* 流量包用010editor打开，搜索flag

![](https://seandictionary.top/wp-content/uploads/2024/09/image-18-1024x535.png)

* 发现一个flag.rar
* WireShark过滤关键字flag.rar，在FTP的包下面追踪发现
* 一段典型的 **FTP** 文件传输会话日志

![](https://seandictionary.top/wp-content/uploads/2024/09/image-19.png)

* 截获数据包类型为 `FTP-DATA` 的数据流，另存为rar文件，解压有密码
* 猜测常用四位数字，ARCHPR爆破，密码5790
* flag{6fe99a5d03fb01f833ec3caa80358fa3}

## 36.[BJDCTF2020]藏藏藏

* 图片扔010editor查成分。
* 注意到docx的存在

![](https://seandictionary.top/wp-content/uploads/2024/09/image-20-1024x258.png)

* 注意到DOCX文件是一个压缩的 ZIP 文件，包含多个 XML 文件和资源
* 文件头和文件尾和ZIP一样分别是 `50 4B 03 04`和 `50 4B 05 06`
* 手动分离文件另存为docx，无法打开
* 保存为zip解压发现损坏，用WinRAR修复
* 解压得到一个docx文件，打开是二维码
* 扫描得到flag{you are the best!}

## 37.[GXYCTF2019]佛系青年

* zip伪加密

![](https://seandictionary.top/wp-content/uploads/2024/09/image-21-1024x456.png)

* 打开txt，经过与佛论禅解密，得到
* flag{w0_fo_ci_Be1}
* ps.属于是见多识广了

## 38.[BJDCTF2020]你猜我是个啥

* zip打开有误
* 010editor打开，发现文件结尾有flag{i_am_fl@g}

## 39.刷新过的图片

* 题目提醒F5
* 对图片F5解密
* 查看输出发现符合zip格式
* 解压发现有密码，尝试伪加密更改，成功
* flag{96efd0a2037d06f34199e921079778ee}

## 40.秘密文件

* 流量包追踪ftp
* 发现rar文件
* 用binwalk分离
* 用ARCHPR爆破，得到密码1903
* flag{d72e5a671aa50fa5f400e5d10eedeaa5}

## 41.[BJDCTF2020]鸡你太美

* 对副本加上gif文件头
* flag{zhi-yin-you-are-beautiful}
* 呸，tm答案不是短横线，是下划线
* flag{zhi_yin_you_are_beautiful}

![](https://seandictionary.top/wp-content/uploads/2024/09/image-24.png)

* 这题我开始方向就错了，首先对副本binwalk检查
* 发现有.gz文件存在，就分离了文件
* 结果就是gz文件死活打不开，后续就断了
* 这题我开始方向就错了，首先对副本binwalk检查
* 发现有.gz文件存在，就分离了文件
* 结果就是gz文件死活打不开，后续就断了
* 淦

## 42.snake

* 010editor一眼看出结尾有zip压缩包
* binwalk提取
* key文件中一眼base64编码，解码得到
* What is Nicki Minaj's favorite song that refers to snakes?
* 百度查到是anaconda
* 对cipher文件用[Serpent解密](http://serpent.online-domain-tools.com/)，key是anaconda
* 得到flag{who_knew_serpent_cipher_existed}

好多奇奇怪怪的加密啊

## 43.[BJDCTF2020]just_a_rar

* ARCHPR爆破，密码2160
* exiftool查看详细内容得到flag
* flag{Wadf_123}

## 44.菜刀666

* 直接binwalk拆解流量包
* 得到含有flag.txt的加密zip

![](https://seandictionary.top/wp-content/uploads/2024/09/image-25-1024x491.png)

* 010editor打开发现确实需要密码，不是伪加密
* 在第七个流中发现FF D8 FF开头的十六进制文件
* 保存为图片，得到密码Th1s_1s_p4sswd_!!!

![](https://seandictionary.top/wp-content/uploads/2024/09/a.jpg)

* flag{3OpWdJ-JP6FzK-koCMAK-VkfWBq-75Un2z}

## 45.[BJDCTF2020]一叶障目

* kali中无法打开显示IHDR：CRC error
* 显然是人为更改宽高
* 爆破宽高
* 得到flag{66666}
* 附上大佬的爆破脚本，有修改

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

## 46.[SWPU2019]神奇的二维码

* 扫描得到swpuctf{flag_is_not_here}，不信邪尝试，错误
* strings -n 8能发现txt，doc等各种文件名后缀
* 果断binwalk分离
* 对于 `encode.txt` Base 64解码得到asdfghjkl1234567890
* 这个密码用于打开 `看看flag在不在里面^_^.rar`，没有效果
* 对于 `flag.doc` Base 64解码20次得到comEON_YOuAreSOSoS0great（👊，20次加密，无语）
* 这个密码打开 `18394.rar`得到 `good.mp3`
* 抄录莫斯密码，转码，改为小写
* flag{morseisveryveryeasy}

## 47.[BJDCTF2020]纳尼

* gif文件无法打开，扔010editor查成分
* 文件头看不出来
* 看文件结尾是 `00 3B`，是GIF文件尾
* 开头添上GIF的文件头 `47 49 46 38`
* 得到一串Base 64密文，先用convert截取每一帧
* 转码得到CTF{wang_bao_qiang_is_sad}
* flag{wang_bao_qiang_is_sad}

## 48.[HBNIS2018]excel破解

* 表格加密，先扔010editor看看有没有线索
* 搜索flag有很多结果，寻找最像答案的
* flag{office_easy_cracked}

![](https://seandictionary.top/wp-content/uploads/2024/09/image-26-1024x310.png)

## 49.[HBNIS2018]来题中等的吧

* 莫斯密码解码
* flag{alphalab}

## 50.梅花香之苦寒来

* 010editor中发现文件尾有一长串
* 尝试对结尾字符统计，按顺序和逆序提交，均错误
* 对字符进行16进制转化得到坐标，保存
* 用python编写脚本转化为散点图
* 得到flag{40fc0a979f759c8892f4dc045e28b820}

```
import matplotlib.pyplot as plt

# 读取txt文件并解析坐标数据
def read_coordinates(file_path):
    coordinates = []
    with open(file_path, 'r') as file:
        for line in file:
            # 去除行首行尾空白符，并去掉括号，用逗号分隔获取坐标
            line = line.strip().replace("(", "").replace(")", "")
            x, y = map(int, line.split(','))
            coordinates.append((x, y))
    return coordinates

# 绘制坐标点
def plot_coordinates(coordinates):
    x_vals = [x for x, y in coordinates]
    y_vals = [y for x, y in coordinates]

    plt.scatter(x_vals, y_vals, color='black')  # 使用scatter函数绘制散点图
    plt.xlabel('X')
    plt.ylabel('Y')
    plt.title('Scatter plot')
    plt.grid(False)
    plt.show()

# 文件路径
file_path = input("输入文件路径：")
coordinates = read_coordinates(file_path)
plot_coordinates(coordinates)
```

## 51.[ACTF新生赛2020]outguess

* zip伪加密
* exiftool查看图片信息

![](https://seandictionary.top/wp-content/uploads/2024/09/image-27-1024x620.png)

* 一眼核心价值观编码，解码得到abc
* Outguess隐写解码 `outguess -k <密钥> -r <输入路径> <输出路径>`
* flag{gue33_Gu3Ss!2020}

## 52.谁赢了比赛？

* strings看见文件名
* binwalk分离，得到rar压缩包，其中gif加密
* 用ARCHPR爆破爆破得到密码1020
* 解压gif得到复盘全况
* convert截取每一帧图片，得到

![](http://seandictionary.top/wp-content/uploads/2024/09/image-29.png)

* 对这张图片用StegSlove打开
* 在Red 0通道处发现

![](http://seandictionary.top/wp-content/uploads/2024/09/image-30-840x1024.png)

* 扫描得到flag{shanxiajingwu_won_the_game}

## 53.穿越时空的思念

* 左声道原曲，右声道莫斯码
* FL Studio打开编辑波形图，后半截没用

![](http://seandictionary.top/wp-content/uploads/2024/09/image-32-1024x114.png)

* 解码得到flag{f029bd6f551139eedeb8e45a175b0786}

## 54.[WUSTCTF2020]find_me

* exiftool查看图片，发现盲文
* ⡇⡓⡄⡖⠂⠀⠂⠀⡋⡉⠔⠀⠔⡅⡯⡖⠔⠁⠔⡞⠔⡔⠔⡯⡽⠔⡕⠔⡕⠔⡕⠔⡕⠔⡕⡍=
* 此处运用[盲文解密](https://www.qqxiuzi.cn/bianma/wenbenjiami.php?s=mangwen)，而非翻译
* 得到flag{y$0$u_f$1$n$d$_M$e$e$e$e$e}

## 55.[SWPU2019]我有一只马里奥

* 运行，显示

```
ntfs
flag.txt
```

* ntfs提示，这题要用到NTFS（详细解释见下，算是了解新知识了）
* notepad 1.txt:flag.txt

### 1. 什么是NTFS和备用数据流（ADS）

**NTFS（New Technology File System）** 是Windows操作系统使用的一种文件系统。它支持多种特性，包括：

* **文件权限和安全性** ：允许对文件设置不同的访问权限。
* **文件压缩** ：可以在文件系统级别上压缩文件以节省空间。
* **加密** ：支持文件加密以保护数据。
* **备用数据流（ADS）** ：允许在一个文件中存储多个数据流。

#### 备用数据流（ADS）

备用数据流是一种可以在文件中附加额外数据的方式。每个NTFS文件可以有多个流，其中一个是主数据流，其他的就是备用数据流。通过这种方式，你可以在不影响主文件的情况下存储额外的信息。

例如，除了主文件 `1.txt` 之外，你还可以有一个名为 `flag.txt` 的备用数据流。

### 2. 如何创建和查看备用数据流

#### 创建备用数据流

你可以使用命令行创建一个包含备用数据流的文件。比如：

```
echo "这是一个隐藏的flag" > 1.txt:flag.txt
```

这个命令会在 `1.txt` 文件中创建一个名为 `flag.txt` 的备用数据流，内容是 "这是一个隐藏的flag"。

#### 查看备用数据流

要查看备用数据流的内容，你可以使用记事本：

```
notepad 1.txt:flag.txt
```

## 56.[GUET-CTF2019]KO

* 确定Ook！编码
* [解码](https://www.splitbrain.org/services/ook)
* flag{welcome to CTF}

## 57.[ACTF新生赛2020]base64隐写

* 二维码没用，微信公众号引流
* 对txt进行base64解码，发现有错误
* 结合题目得出是base64隐写
* 运用大佬脚本，进行了细微修改
* 得到flag{6aseb4_f33!}

```
# base64隐写
import base64
def get_diff(s1, s2):
    base64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    res = 0
    for i in range(len(s2)):
        if s1[i] != s2[i]:
            return abs(base64chars.index(s1[i]) - base64chars.index(s2[i]))
    return res


def b64_stego_decode():
    path = input("输入文件路径:")
    file = open(path,"rb")
    x = ''                                      # x即bin_str
    lines =  file.readlines()
    for line in lines:
        l = str(line, encoding = "utf-8")
        stego = l.replace('\n','')
        #print(stego)
        realtext = base64.b64decode(l)
        #print(realtext)
        realtext = str(base64.b64encode(realtext),encoding = "utf-8")
        #print(realtext)
        diff = get_diff(stego, realtext)        # diff为隐写字串与实际字串的二进制差值
        n = stego.count('=')
        if diff:
            x += bin(diff)[2:].zfill(n*2)
        else:
            x += '0' * n*2
        
    i = 0
    flag = ''
    while i < len(x):
        if int(x[i:i+8],2):
            flag += chr(int(x[i:i+8],2))
        i += 8
    print(flag)

if __name__ == '__main__':
    b64_stego_decode()
```

## 58.[MRCTF2020]ezmisc

* kali中打不开，win可以，锁定宽高修改，同45
* 原文件500*319，猜测高为500（01 F4）

![](http://seandictionary.top/wp-content/uploads/2024/09/image-36.png)

* 成功得到flag{1ts_vEryyyyyy_ez!}

## 59.[GXYCTF2019]gakki

* 图片binwalk发现有隐写文件，分离得到加密rar
* 用ARCHPR爆破爆破得到密码8864
* 得到flag.txt，里面一串乱码，联想频数分析
* 用010editor打开查看频数直方图

![](http://seandictionary.top/wp-content/uploads/2024/09/image-45.png)

* flag{gaki_IsMyw1fe}

## 60.[HBNIS2018]caesar

* 凯撒加密，偏移位为1
* flag{flagiscaesar}

## 61.[SUCTF2018]single dog

* binwalk分离得到压缩包，里面是txt文件
* 文件内是一堆颜文字，[解码网址](http://hi.pcmoe.net/kaomoji.html)
* 得到

```
function a()
{
var a="SUCTF{happy double eleven}";
alert("双十一快乐");
}
a();
```

## 62.[HBNIS2018]低个头

* EWAZX RTY TGB IJN IO KL
* 没有头绪可以考虑键盘坐标
* 每个字母对应到键盘上就可以连线出CTF

![](http://seandictionary.top/wp-content/uploads/2024/09/image-47-1024x312.png)

* flag{CTF}

## 63.黑客帝国

* 转为十六进制文件保存为rar压缩文件
* APCHPR爆破得到密码3690
* 解压得到图片，win下无法打开
* 010editor查看发现JFIF说明是JPG文件，但文件头却是PNG的
* 手动修改前四个字节为 `FF D8 FF E0`

![](http://seandictionary.top/wp-content/uploads/2024/09/image-48-1024x140.png)

* 图片可以打开

![](http://seandictionary.top/wp-content/uploads/2024/09/image-49-1024x114.png)

* flag{57cd4cfd4e07505b98048ca106132125}

## 64.[SWPU2019]伟大的侦探

* txt种乱码是EBDIC信息交换码，用010editor处理

![](http://seandictionary.top/wp-content/uploads/2024/09/image-50.png)

![](http://seandictionary.top/wp-content/uploads/2024/09/image-51.png)

* 得到密码解压成功
* 文件中是跳舞的小人加密[[对照表]](https://blog.csdn.net/weixin_47869330/article/details/111396033)
* 解密得到flag{iloveholmesandwllm}

## 65.[MRCTF2020]你能看懂音符吗

* rar文件打开失败，010editor打开发现文件头61 52倒置，改为52 61
* 解压得到word文件，打开发现没有有用内容
* 已知docx是类zip文件的压缩包，改为zip后解压
* 打开 `/word/document.xml`能看到文件隐藏内容

![](http://seandictionary.top/wp-content/uploads/2024/09/image-52-1024x356.png)

* 用[解密工具](https://www.qqxiuzi.cn/bianma/wenbenjiami.php?s=yinyue#:~:text=%E6%96%87%E6%9C%AC%E5%8A%A0%E5%AF%86%E4%B8%BA%E9%9F%B3%E4%B9%90%E7%AC%A6%E5%8F%B7,)解密
* flag{thEse_n0tes_ArE_am@zing~}

## 66.我吃三明治

* 图片strings发现比较特殊的字符串

![](http://seandictionary.top/wp-content/uploads/2024/09/image-53-1024x441.png)

* 查看十六进制文件能发现藏了一个jpg文件
* 用binwalk分离出来（然而并没有用）
* 对密文Base32解密得到
* flag{6f1797d4080b29b64da5897780463e30}

## 67.[SWPU2019]你有没有好好看网课?

* 根据flag3.zip的提示，爆破密码得到183792
* 根据docx的提示，盯帧
* 在5.20和7.11发现

![](https://seandictionary.top/wp-content/uploads/2024/09/image-54.png)

* 第一个敲击码   ..... ../ ... ./ ... ./ ... ../   得到wllm
* 第二个Base64  dXBfdXBfdXA=        得到up_up_up

![](https://seandictionary.top/wp-content/uploads/2024/09/image-55.png)

* flag2.zip解压密码是wllmup_up_up
* strings得到flag{A2e_Y0u_Ok?}

## 68.[ACTF新生赛2020]NTFS数据流

* 打开找到唯一一个大小不一样的文件263.txt解压
* 关于备用数据流（ADS）可以查看第55题
* 控制台输入notepad 293.txt:flag.txt
* 得到flag{AAAds_nntfs_ffunn?}

## 69.sqltest

* 分析http流，发现请求url十分奇怪
* 结合题目可以判断是sql注入
* 截取最后的flag爆破流另存为output.txt（过滤器筛选http.request，截取从6274往后的所有http流）
* 用脚本转化为flag

```
path = r"C:\Users\XXX\Desktop\output.txt"
a = []
with open(path,'r') as file:
    a = file.read().split('\n')
for i in range(len(a)):
    a[i] = a[i][139:-10].split(',%201))>')
test = 0
ans = []
for m,n in a:
    if m != test:
        ans += [n]
        test = m
    elif m == test:
        ans[-1] = n
print(''.join(chr(int(x)) for x in ans))
```

* flag{47edb8300ed5f9b28fc54b0d09ecdef7}

## 70.john-in-the-middle

* 追踪http流，在流4，5中发现png的影子
* 导出http
* StegSlove打开logo.png
* 在Red，Green，Blue的0，1通道均能模糊辨识出flag
* 或者注意到scanlines.png在很多通道中都有一条线（惊人的注意力
* 在打开scanlines.png的情况下选择 `Analyse > Imagine Combiner`选择logo.png比较（**顺序绝对不能调换，不然会看不到**
* 在SUB下能发现flag

![](https://seandictionary.top/wp-content/uploads/2024/09/image-63-1024x552.png)

* flag{J0hn_th3_Sn1ff3r}
