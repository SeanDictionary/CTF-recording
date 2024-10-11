# MoeCTF 2024-Misc


## 罗小黑战记

* 用convert截取每一帧画面

## 杂项入门指北

* 海报最右侧的装饰线是摩斯密码

## ez_Forensics

* 这是道内存取证
* 先将文件拖入kali，用Volatility分析
* `vol.py -f flag.raw imageinfo` 分析内存镜像的基本信息，获得内存镜像文件的类型*Image Type*
* `volatility -f flag.raw --profile=Win7SP1x64 consoles` 获取控制台执行历史，得到

```
C:\Users\npm>echo moectf{WWBGY-TLVC5-XKYBZ} > flag.txt
C:\Users\npm>echo SJW7O^%gt8 > flag.txt
C:\Users\npm>del flag.txt 
```

* moectf{WWBGY-TLVC5-XKYBZ}

## so many 'm'

* 打开txt发现一堆乱码，初步判断不出是什么编码，同时发现字符数几百，猜测是频数分析
* 用010editor打开，查看直方图

![](https://seandictionary.top/wp-content/uploads/2024/09/image-46.png)
注意p和M的频数相同，所以先后顺序要尝试

* moectf{C0MpuTaskingD4rE}

## Abnormal lag

* 此题明显听出音频有缺陷
* Audacity打开查看频谱图

![](https://seandictionary.top/wp-content/uploads/2024/09/image-31-1024x277.png)

* 然而答案显而易见，我却填不出来（我试了好长时间，b6不分，2z不分）
* moectf{09e3f7f8-c970-4c71-92b0-6f03a677421a}

## ez_F5

* 此题先用exiftool得到详细信息，将密文Base64解码
* 然后用F5解密，密码用上述解出来的
* output中得到flag
* moectf{F5_15_s0_lntere5t1n9}

## moejail_lv1

* 是python jail题，其本质是一个暗箱的主机，需要我们在有限的命令行下，绕过限制，找到flag
* 更多相似可以上NSSCTF寻找[[HNCTF 2022 Week1]calc_jail_beginner(JAIL)](https://zhuanlan.zhihu.com/p/578986988)。附上[大佬的解析](https://zhuanlan.zhihu.com/p/578986988)。

```
Give me your payload:__import__('os').system('sh')  #进入shell

cd /  #进入根目录

ls  #查看目录下文件
bin
dev
etc
home
lib
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var

cd /tmp

ls  #查看目录下文件，没有

ls -a #查看目录下文件，包括隐藏文件(.example)
.
..
.therealflag_2de0080eb1e85f9f2e7cb81a8475d2ba155dce0cf38a3231b7d0e4039779305ace58ccd8e8539dc7117fe6dc0970e72cda437161adc952ba7b63796199d0a26c  -

cat .thereal* #读取.thereal*文件，*是通配符
moectf{AH_h@_noW_yOu_kn0w_h0W_tO_ESC@Pe-sIMp1E-Str1NG_fIlter0}
```

## ctfer2077①

* 扫描二维码得到[链接](https://www.bilibili.com/video/BV1hThreMEyT)
* 用strings查看，得到提示

![](https://seandictionary.top/wp-content/uploads/2024/09/image-23.png)

* 在StegSlove中，注意到Red 0通道最上方有黑点
* 只取Red 0 的最低限位，得到答案
* flag is moectf{84d7f247-3cba-4077-ba25-079f3ac7bb8a}

## 捂住一只耳

* 音频结尾听到一串数字 `63 31 43 31 41 52 31 51 71 101`
* 对应键盘坐标 `(m,n)`，即键盘26字母中的从上至下第n行，从左至右第m个
* 得到moectf{NEVERGETUP}

## 每人至少300份

* 得到9张二维码碎片
* 9张不算多吧？不用脚本合并了，动手！拼图！
* 扫描得到一串乱码以及key
* 乱码提示用Base58加密
* 将key解码
* 得到moectf{we1rd_qrc0d3}

## the_secret_of_snowball

* 文件无法打开，010editor查成分
* 发现JFIF说明是JPG文件，修改文件头为 `FF D8 FF`，可以正常打开

![](https://seandictionary.top/wp-content/uploads/2024/09/image-33.png)

* 得到flag前半段
* 继续看010editor
* 在文件结尾发现了Base64密文
* 解码得到后半段
* moectf{Welc0me_t0_the_secret_life_0f_Misc!}

## Find It

* 这是一道社工题，类似图寻等，网络迷踪
* 首先图片寻找文字，能发现 `雄锋集团`
* 借助地图软件，在先搜索地点
* 与全景地图进行比较

![](https://seandictionary.top/wp-content/uploads/2024/09/image-34-1024x470.png)

* 该楼位于 `陕西省西安市未央区容桂大道中148号b座`
* 再通过图片判断拍摄地点，大致是在高楼面朝的方向
* 同时可以注意到图片中红框处是个比较矮的平房

![](https://seandictionary.top/wp-content/uploads/2024/09/image-35-1024x249.png)

* 因此可以判断出拍摄地点是在大楼的西面
* 可以判断小区就是 `旭景崇盛园`
* 两个幼儿园分别是 `吉的堡旭景崇盛幼儿园`，`吉的堡英佳幼儿园`
* moectf{ji_di_bao_you_er_yuan}

## 我的图层在你之上

* 得到pdf没有任何头绪
* 扔到010editor查成分，发现结尾有一串[在线ps的网址](https://ps.gaoding.com/)（其实是出题人用此网站，制作的图片，然而可以作为解题线索之一）
* 在此网站中打开pdf，能发现有五个图层（其实看题目也能想到分离图层）
* 将黑色Bitmap导出为PNG
* 将PNG文件用StegSlove打卡，查看不同通道的图片
* 最终发现在Gray Bits通道里发现密码p_w_d
* 解压zip
* 打开txt得到zbrpgs{q751894o-rr0n-47qq-85q4-r92q0443921s}
* 能发现符合flag格式，但数量一致，字符对不上
* 猜测凯撒加密
* 得到moectf{d751894b-ee0a-47dd-85d4-e92d0443921f}

## 时光穿梭机

* 文中提到了 `1946年4月20日知名古墓被开`
* 尝试以这个关键词搜索，发现得到的是 `清河县武植祠`
* 然而结合地图并没有找到对门的中医院，此方法不对
* 继续查看原文，提及到 `伦敦`和 `当地知名的画报`
* 可以找到是 `伦敦新闻画报 <em>Illustrated London News</em>`
* 在 `英国新闻档案 <em>British Newspaper Archive</em>`中能找到对应的期刊影印
* 查看 `<a href="https://www.britishnewspaperarchive.co.uk/viewer/BL/0001578/19460420/094/0003?browse=true#" data-type="link" data-id="https://www.britishnewspaperarchive.co.uk/viewer/BL/0001578/19460420/094/0003?browse=true#" target="_blank" rel="noreferrer noopener nofollow">伦敦新闻画报 <em>Illustrated London News</em> 第三页</a>`
* 在页面最低下发现

```
A covery of immense importance in chinese archaeology and art:
Thetomb of Wang Chien,the only imperial tomb of its kind to be scientifically excavated.
The story and other pictures of this discovery are given on pages 429,430 and 431.
```

![](https://seandictionary.top/wp-content/uploads/2024/09/image-37-1024x80.png)

* 第二段文字提示墓主人是王建
* 百度地图搜索王建墓，定位到 `成都市金牛区永陵路9号`

![](https://seandictionary.top/wp-content/uploads/2024/09/image-38.png)

* 答案moectf{han_fang_tang}

## 解不完的压缩包

* 010editor打开
* 搜索发现存在1004个 `50 4B 03 04`
* 1000个 `50 4B 05 06`
* 取倒数第五个文件头，和第一个文件尾组合成新zip
* 根据上一级压缩包名的提示
* 要用到CRC32碰撞发来获取密码
* [大佬的脚本](https://github.com/AabyssZG/CRC32-Tools) 命令行窗口中运行 ` python CRC32-Tools.py -2 <example.zip>`
* 输出即为密码，解压得到flag
* moectf{af9c688e-e0b9-4900-879c-672b44c550ea}

## ctfer2077②

* 先对核心价值观解密得到p@55w0rd
* 用VeraCrypt将文件挂载到电脑，密钥同上
* 查看新磁盘发现flag?.txt内容是Where is the flag?
* （走不下去了）

## ctfer2077③

* 打开流量包，追踪http流
* 截获压缩包，binwalk分离
* 对gif拆解，得到key：C5EZFsC6

![](https://seandictionary.top/wp-content/uploads/2024/09/image-40-1024x313.png)

* MP3隐写，用MP3Stego解码，密码如上
* 得到

```
+++++ +++[- >++++ ++++< ]>+++ +++++ .<+++ +[->- ---<] >---. <++++ +++[-
>++++ +++<] >+.<+ ++++[ ->--- --<]> ----- -.<++ +[->+ ++<]> +++++ +.<++
+[->- --<]> -.<++ ++[-> ----< ]>--- -.<++ ++++[ ->+++ +++<] >++++ +.<
```

* BrainFuck解码得到H5gHWM9b
* 附上[BrainFuck解码脚本](https://github.com/SeanDictionary/brainfuck-tool)

```
# BrainFuck 解释器
def brainfuck(code):
    # 创建数据内存带
    tape = [0] * 30000  # 使用 30,000 个单元格作为内存
    pointer = 0  # 指针初始位置
    code_pointer = 0  # 代码的指针
    bracket_map = {}  # 用于处理 [] 的跳转
    output = []  # 用来保存输出结果

    # 预处理：生成括号匹配的映射
    open_bracket_stack = []
    for i, command in enumerate(code):
        if command == '[':
            open_bracket_stack.append(i)
        elif command == ']':
            start = open_bracket_stack.pop()
            bracket_map[start] = i
            bracket_map[i] = start

    while code_pointer < len(code):
        command = code[code_pointer]

        if command == '>':
            pointer += 1
        elif command == '<':
            pointer -= 1
        elif command == '+':
            tape[pointer] = (tape[pointer] + 1) % 256  # 确保在 0-255 之间循环
        elif command == '-':
            tape[pointer] = (tape[pointer] - 1) % 256  # 确保在 0-255 之间循环
        elif command == '.':
            output.append(chr(tape[pointer]))  # 输出当前指针值对应的字符
        elif command == ',':
            tape[pointer] = ord(input('Input a character: ')[0])  # 接受一个字符输入
        elif command == '[':
            if tape[pointer] == 0:
                code_pointer = bracket_map[code_pointer]  # 跳转到相应的 ]
        elif command == ']':
            if tape[pointer] != 0:
                code_pointer = bracket_map[code_pointer]  # 跳回到相应的 [

        code_pointer += 1

    return ''.join(output)  # 返回输出结果

file_path = input("文件路径：")

with open(file_path,'r') as file:
    content = file.read()
    content = "".join(content.split())
print(brainfuck(content))
```

* 解压加密zip，得到三个txt
* 能发现是 `跳舞小人`加密

![](https://seandictionary.top/wp-content/uploads/2024/09/image-41-1024x379.png)
1.txt

![](https://seandictionary.top/wp-content/uploads/2024/09/image-42-1024x289.png)
2.txt

![](https://seandictionary.top/wp-content/uploads/2024/09/image-43-1024x315.png)
3.txt

![](https://seandictionary.top/wp-content/uploads/2024/09/image-44.png)
跳舞小人对照表，注意的是n和k一样，f和y一样（不知道是不是表错了）

* moectf{people_dancing_happily}
* moectf{PEOPLE_DANCING_HAPPILY}
* 实测两个都算对

## 拼图羔手

* 先拼二维码（其实是有技巧的 `位置探测图形`肯定位于三个角，再确定 `矫正图形`）

![](https://seandictionary.top/wp-content/uploads/2024/09/image-39.png)

* 扫描得到
* `balabalbalablbalblablbalabala//nihaopintugaoshou//encoded_flag{71517ysd%ryxsc!usv@ucy<em>wqosy</em>qxl&sxl*sbys^wb$syqwp$ysyw!qpw@hs}`
* 查看py文件，在末尾提示key的输出是一串Base64密文
* 解码得到 `xixsdxnlUmXixunbGsardftaUixavtitsJxzmtiaU`
* 观察加密逻辑，发现两次加密可以得到原文
* 原文为 `StrangeCharacterStaywithNumberOnSomewhere`
* 单独对71517逆向得到52367
* 结合密文解密得到
* `hs@dkj!dfhf$kdjfh$ud^hfuh*oeh&oejfhljdfvb@chb!vhefi%whf52367`
* `hs40dkj21dfhf24kdjfh24ud5ehfuh2aoeh26oejfhljdfvb40chb21vhefi25whf52367`
* （做不下去了）
