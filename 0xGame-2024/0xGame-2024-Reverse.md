# 0xGame 2024-Reverses-Week 1

## [Week 1] BabyBase

* IDA打开查看主函数发现没有线索
* 看见check_flag函数进去后发现一串编码
* MHhHYW1le04wd195MHVfa24wd19CNHNlNjRfRW5jMGQxbmdfdzNsbCF9
* 注意到（惊人的注意力）这是Base64编码，解密得到flag
* 0xGame{N0w_y0u_kn0w_B4se64_Enc0d1ng_w3ll!}
* 或者注意不到可以继续查看encode函数
* 能注意到他是Base64加密的脚本，从而得到flag

## [Week 1] BinaryMaster

* IDA打开查看主函数发现flag
* 0xGame{114514cc-a3a7-4e36-8db1-5f224b776271}

## [Week 1] SignSign

* IDA打开查看主函数得到后半段flag
* 视图查看字符串或者shift+F12
* 可以找到前半个字符串
* 0xGame{S1gn1n_h3r3_4nd_b3g1n_Reversing_n0w}

## [Week 1] Xor-Beginning

* IDA查看原函数
* 分析函数了解到是输入v4
* 通过遍历与78-v7异或（XOR）
* 结果要与v5一直
* 编写脚本

```
v5 = [0]*30
v4 = [0]*30
for n,i in enumerate("~5\v*',3"):
    v5[n] = ord(i)
v5[7] = 31  ;v5[8] = 118; v5[9] = 55  ;v5[10] = 27  ;v5[11] = 114 ;v5[12] = 49 ;v5[13] = 30 ;v5[14] = 54 ;v5[15] = 12
v5[16] = 76 ;v5[17] = 68; v5[18] = 99 ;v5[19] = 114 ;v5[20] = 87  ;v5[21] = 73 ;v5[22] = 8  ;v5[23] = 69 ;v5[24] = 66
v5[25] = 1  ;v5[26] = 90; v5[27] = 4  ;v5[28] = 19  ;v5[29] = 76
print(v5)
for i in range(30):
    v4[i] = (78-i) ^ v5[i]
print(v4)
print(''.join(chr(i) for i in v4))
```

* 输出0xGame{X0r_1s_v3ry_Imp0rt4n7!}

## [Week 1] Xor-Endian

* 分析main函数发现有encrypt函数用来加密
* 分析可知加密算法是对输入的每个字符用密钥循环去异或值
* 在main函数中与已给变量进行比较，最后输出right
* 所以可以根据异或的性质编写代码

```
v6 = "{\x1D>Q\x15\"\x1A\x0FV\nQV\0(]T\aKt\x05@QT\bT\x19rV\x1D\x04UvV\vTW\a\vUs\x01O\b\x05"
key = 'Key0xGame2024'
ans = ''
print(len(v6))
for i in range(len(v6)):
    ans += chr(ord(v6[i]) ^ ord(key[i%13]))
print(ans)
```

* 输出0xGame{b38ad4c8-733d-4f8f-93d4-17f1e79a8d68}

## [Week 2] BabyUPX

* EXE Info查看发现有UPX套壳，用[工具](https://github.com/upx/upx/releases)脱壳
* 脱壳后再次检查发现干净了
* IDA打开，查看是输入加密后与密文比对
* 加密本质为将一个字节的高4位与低4位互换
* 提取密文，编写解密脚本

```
encdata = [
    0x03, 0x87, 0x74, 0x16, 0xD6, 0x56, 0xB7, 0x63,
	0x83, 0x46, 0x66, 0x66, 0x43, 0x53, 0x83, 0xD2,
	0x23, 0x93, 0x56, 0x53, 0xD2, 0x43, 0x36, 0x36,
	0x03, 0xD2, 0x16, 0x93, 0x36, 0x26, 0xD2, 0x93,
	0x73, 0x13, 0x66, 0x56, 0x36, 0x33, 0x33, 0x83,
	0x56, 0x23, 0x66, 0xD7
]

def decode(encoded_data):
    decoded_str = ""
    for encoded_val in encoded_data:
        original_val = ((encoded_val & 0xF) << 4) | (encoded_val >> 4)
        decoded_str += chr(original_val)
    return decoded_str
decoded = decode(encdata)
print("decode:", decoded)
```

* 0xGame{68dff458-29e5-4cc0-a9cb-971fec338e2f}

## [Week 2] FirstSight-Jar

* 文件是已经打包好的jar文件，用工具或者网站反编译，我使用的是[网站](https://jdec.app/)
* 分析文件是对在字母表中的字符索引进行处理
* `var3 = (var3 * 5 + 3) % 16`
* 由于取膜后不好还原，所以直接写脚本将全部字母表都进行处理，产生明文与密文对照的字典
* 编写脚本

```
Alphabat = "0123456789abcdef"
ans = {}
c = "ab50e920-4a97-70d1-b646-cdac5c873376"
result = ''
for n,i in enumerate(Alphabat):
    m = (n*5+3)%16
    ans[Alphabat[m]]=i
for i in c:
	if i in Alphabat:
		result += ans[i]
	else:
		result += i
print("0xGame{",result,"}",sep="")
```

* 0xGame{b8a9fe39-dbe4-4926-87d7-52b5a5140047}

## [Week 2] FisrtSight-Pyc

* pyc是py文件在被import调用时候生成的类似缓存文件，可以加速下次调用
* 使用工具或者网站反编译，我使用的[网站](https://tool.lu/pyc/)
* 得到反编译后的python文件，并手动修改不当语句
* 由于本身是作为库调用的，这里将return删去，然后就可以直接运行了
* 分析源码发现当输入为Ciallo~时继续下一步操作
* 最终得到0xGame{2f0ef0217bf3a7c598d381b077672e09}

## [Week 2] Xor::Ramdom

* IDA打开分析
* 能发现是随机数与flag加密
* 注意到有init_random(void)函数，用来定义随机数种子
* `srand(0x77u);`
* 同时注意密文是小端序，要重排
* 据此手搓脚本
* 还要注意，这里生成的随机数使用c++生成，不存在范围限制
* 而python生成的随机数有范围限制，因此只能用c++编写脚本

```
#include <iostream>
#include <string>
#include <array>
#include <cstdlib>

const std::array<unsigned char, 30> expected_values = {
    0x0C, 0x4F, 0x10, 0x1F, 0x4E, 0x16, 0x21, 0x12,
    0x4B, 0x24, 0x10, 0x4B, 0x0A, 0x24, 0x1F, 0x17,
    0x09, 0x4F, 0x07, 0x08, 0x21, 0x5C, 0x2C, 0x1A,
    0x10, 0x1F, 0x11, 0x16, 0x59, 0x5A
};

void generate_flag(std::string& flag) {
    flag = "0xGame{";
    int random_value = rand();

    for (size_t i = 0; i < 30; ++i) {
        char ch;
        if (i % 2 != 0) {
            ch = random_value;
        }
        else {
            ch = random_value + 3;
        }
        ch ^= expected_values[i];
        flag += ch;
    }

    flag += '}';
}

int main() {
    std::string flag;
    srand(0x77u);
    rand();
    generate_flag(flag);
    std::cout << "Generated flag: " << flag << std::endl;
    return 0;
}
```

* （第一次写c++脚本，要废了呜呜呜
* 得到0xGame{r4nd0m_i5_n0t_alw4ys_'Random'!}

## [Week 2] ZzZ

* 函数很多啊，根本找不到
* 尝试运行下发现输出Please enter your flag，然后去搜索查找这段字符所在函数
* 或者Shift+F12也能看见
* 主函数sub_140011AA0()
* 分析逻辑发现是当满足如下方程的时候输出正确
* `11 * v11 + 14 * v10 - v12 == 0x48FB41DDD`
* `9 * v10 - 3 * v11 + 4 * v12 == 0x2BA692AD7`
* `((v12 - v11) >> 1) + (v10 ^ 0x87654321) == 0xCDBDFAAC`
* 其中v10，v11，v12是从flag中划分出来的字符转长整型，flag结构如下
* 0xGame{v13-v10-v11-v12-v14}，其中v13和v14已知，分别为E544267D和D085A85201A4
* 用z3编写脚本，Sage中比较难处理右移位以及异或运算

```
from z3 import *
from Crypto.Util.number import *

# 创建 Z3 变量
v10 = BitVec('v10',32)
v11 = BitVec('v11',32)
v12 = BitVec('v12',32)

# 创建 Z3 求解器
solver = Solver()

# 添加方程
solver.add(11 * v11 + 14 * v10 - v12 == 0x48FB41DDD)
solver.add(9 * v10 - 3 * v11 + 4 * v12 == 0x2BA692AD7)
solver.add(((v12 - v11) >> 1) + (v10 ^ 0x87654321) == 0xCDBDFAAC)

# 求解
if solver.check() == sat:
    model = solver.model()
    def bit_to_str(val):
        return long_to_bytes(model[val].as_long()).decode('ascii')[::-1]
    v10,v11,v12 = map(bit_to_str,[v10,v11,v12])
    print("0xGame"+f"{{E544267D-{v10}-{v11}-{v12}-D085A85201A4}}".lower())
else:
    print("无解")
```

* 其中注意最终算出的结果是小端序，要倒序下
* 得到0xGame{e544267d-7812-44b3-a35d-d085a85201a4}

## [Week 3] FirstSight-Android

* 下载安装JEB
* 用JEB打开apk文件，然后找到函数入口

![](https://seandictionary.top/wp-content/uploads/2024/10/image-24.png)

* 进入后右键解析就能显示反汇编java代码
* 然后根据判断语句找到secret字符串，双击后就能看见字符串内容
* 结合判断语句对输入进行了Base62加密
* 最后用CyberChef还原得到
* 0xGame{caff454e-2238-42aa-a75a-75e9f5f1f769}

## [Week 3] BabyASM

* 一段汇编语言，翻译一下得到如下
* 在 `.data` 段中，定义了一个包含 44 个字节的数组，数据以字节为单位存储
* 对前22个字节，值+28
* 对后22个字节，与前22个字节一一对应并异或
* 手搓

```
data = [
    20, 92, 43, 69, 81, 73, 95, 23, 72, 22,
    24, 69, 25, 27, 22, 17, 23, 29, 24, 73,
    17, 24, 85, 27,112, 76, 15, 92, 24,  1,
    73, 84, 13, 81, 12,  0, 84, 73, 82,  8,
    82, 81, 76, 125
]
for i in range(22):
    data[i] = data[i] + 28
for i in range(22, 43):
    data[i] ^= data[i - 22]
print(bytes("".join(chr(x) for x in data).encode("utf-8")))
```

* 0xGame{3d24a572-394e-4ec7-b9c2-f9097fda1f4a}

## [Week 3] LittlePuzzle

* 众所不周知，jar是压缩包，解压缩，把class文件用vscode打开，自动反编译
* 发现就是做个数度题目
* 手解数独（bushi
* 怎么可能，肯定是写脚本求解

```
def print_filled_numbers(board):
    for row in board:
        print(" ".join(str(num) if num != 0 else '.' for num in row))

def is_valid(board, row, col, num):
    for j in range(9):
        if board[row][j] == num:
            return False
    for i in range(9):
        if board[i][col] == num:
            return False
    box_row = row - row % 3
    box_col = col - col % 3
    for i in range(3):
        for j in range(3):
            if board[box_row + i][box_col + j] == num:
                return False
    return True

def solve_sudoku(board, filled_positions):
    for row in range(9):
        for col in range(9):
            if board[row][col] == 0:  # 找到一个空格
                for num in range(1, 10):  # 尝试填入1-9
                    if is_valid(board, row, col, num):
                        board[row][col] = num  # 填入数字
                        filled_positions.append(num)  # 记录填入的数字
                        if solve_sudoku(board, filled_positions):  # 递归调用
                            return True
                        board[row][col] = 0  # 回溯
                        filled_positions.pop()  # 移除最后填入的数字
                return False  # 无法填入任何数字，返回False
    return True  # 所有格子已填入

if __name__ == "__main__":
    board = [
        [5, 7, 0, 9, 4, 0, 8, 0, 0],
        [0, 0, 8, 0, 3, 0, 0, 0, 5],
        [0, 1, 0, 2, 0, 0, 0, 3, 7],
        [0, 0, 9, 7, 2, 0, 0, 0, 0],
        [7, 3, 4, 0, 0, 8, 0, 0, 0],
        [0, 0, 0, 0, 0, 0, 7, 5, 1],
        [3, 0, 0, 0, 1, 4, 2, 0, 0],
        [0, 6, 0, 0, 0, 2, 0, 4, 0],
        [0, 2, 7, 0, 0, 9, 5, 0, 0]
    ]

    filled_positions = []  # 用于记录填入的数字
    if solve_sudoku(board, filled_positions):
        print("填入的数字:")
        print("".join(map(str, filled_positions)))
    else:
        print("无解的数独。")
```

* 求解得到填入的数字316224671996854156384156296824939587681579343618
* 然后运行附件输入结果
* 得到0xGame{4d340a40fcd088c5dc9c48778e5643a666b53e42}

## [Week 4] MineSweeper

* 首先先用ILSpy反编译 `MineSweeper\Minesweeper_Data\Managed\Assembly-CSharp.dll`
* 得到的是程序的主代码
* 注意到update是主要的运行逻辑函数（又一次惊人的注意力
* 当游戏win之后会运行crypt函数
* 这个函数通过 `Array.<strong>Copy</strong>(Resources.<strong>Load</strong><TextAsset>("enc").bytes, array, 44);`加载enc
* 用AssetStudio反编译资源（过程中会有弹窗全选确定就行，时间有点慢
* 然后另存enc，记录十六进制值

![](https://seandictionary.top/wp-content/uploads/2024/11/image-5-1024x514.png)

* crypt内部使用key字符串用作key
* 返回update看crypt函数的传参，使用了haha字符串用作Key
* 最后手搓解密脚本

```
def crypt(key: str, Key: bytes, enc: bytes) -> str:
    num = 0
    array = bytearray(44)
    array[:] = enc
    Key = bytearray(Key)

    key_chars = [ord(c) for c in key]
    key_length = len(key_chars)
    for i in range(44):
        num = (num + key_chars[i % key_length]) % 44
        Key[num], Key[i] = Key[i], Key[num]

    for num2 in range(43, -1, -1):
        array[num2] ^= Key[num2]
    return array.decode()

enc = b'\x45\x21\x3E\x08\x57\x31\x09\x4D\x42\x45\x42\x44\x5D\x5A\x4B\x4B\x52\x56\x16\x44\x66\x45\x6C\x40\x57\x44\x33\x35\x51\x75\x0D\x58\x15\x71\x11\x1B\x0B\x08\x76\x04\x4F\x5C\x68\x3c'
key = "0xoX0XOxOXoxGAME"
Key = b"This is: True_KEY!for #0xgAmE_Unity~Cryption"
decrypted_text = crypt(key, Key, enc)
print(decrypted_text)
```

* 0xGame{36ecd059-b3e7-73c8-fa80-0a2abef3c757}

## [Week 4] PyPro

* 一眼pyinstaller打包，执行 `python pyinstxtractor.py PyPro.exe`
* 然而 `uncompyle6`支持3.8以下，尝试发现源码是3.12的，显然不能用
* 这里偷个懒直接用[网页](https://tool.lu/pyc/)了，用工具也是可以的[pycdc](https://github.com/zrax/pycdc)（附上[使用教程](https://www.52pojie.cn/thread-1854345-1-1.html)，`pycdc.exe PyPro.pyc`编码问题可以输入 `chcp 65001`
* 发现反编译有问题，最终还是用回工具了pycdas `pycdas.exe PyPro.pyc`
* 汇编是不可能看懂的，扔给GPT

```
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

key = bytes.fromhex('0554B134A029DE539438BD18604BF114')     # 这里开头要手动补0

target_data = '2e8Ugcv8lKVhL3gkv3grJGNE3UqkjlvKqCgJSGRNHHEk98Kd0wv6s60GpAUsU+8Q'

encrypted_data = base64.b64decode(target_data)

cipher = AES.new(key, AES.MODE_ECB)
decrypted_data = cipher.decrypt(encrypted_data)

try:
    flag = unpad(decrypted_data, AES.block_size).decode('utf-8')
    print(f"flag: {flag}")
except ValueError:
    print("解密失败，填充不正确。")
```

* 注意下给出的key是31位，会报错，开头补个0就行
* 0xGame{1cb76d38-4900-476f-bf1b-9d59f74d7b2e}
* p.s.其实吧汇编感觉还是能看懂点的（但只有一点点
