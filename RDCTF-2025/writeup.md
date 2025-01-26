# RDCTF 2025 Crypto&图寻② Official WriteUp

欸嘿，这次我是出题人，Crypto全是我出的，都是些板子题，佬们狠狠批评我

## Crypto

### Hello_Crypto

**题目**

出题人：SeanDictionary

难度：签到

题目描述：希望你喜欢密码之旅

题目：

AES.CBC

c = 0x26a8191576aa59308f9ff3469bebbd0c8d27820531130dfe1a860e1e7b02bd7495f56b3d3d5e9a12c01c4f853693e16c

key = IV = 0x1234567890abcdef1234567890abcdef

静态flag，格式flag{}

**exp**

base64+AES

flag{W3lc0m3_T0_TH3_CrypT0_W0rld}

```
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.number import *
from Crypto.Util.Padding import unpad

key = IV = long_to_bytes(0x1234567890abcdef1234567890abcdef)
c = long_to_bytes(0x26a8191576aa59308f9ff3469bebbd0c8d27820531130dfe1a860e1e7b02bd7495f56b3d3d5e9a12c01c4f853693e16c)

print(b64decode(unpad(AES.new(key, AES.MODE_CBC, IV).decrypt(c),AES.block_size)))
# flag{W3lc0m3_T0_TH3_CrypT0_W0rld}
```

这道题后来临时出的，感觉后面的有点难度，补了个简单的。结果还是看见好多人把base64交上去了🤣

### Login

**题目**

出题人：SeanDictionary

难度：简单

题目描述：真的是签到

静态flag，格式flag{}

```
from Crypto.Util.number import *
flag = ?
key = ?

alpha1 = 'abcdefghijklmnopqrstuvwxyz'
alpha2 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

def encrypt(flag,key):
    key_nums = []
    pointer = 0
    ans = ''
    for i in key:
        if i in alpha1:
            key_nums += [alpha1.find(i)]
        elif i in alpha2:
            key_nums += [alpha2.find(i)]
    for i in flag:
        if i in alpha1:
            new_index = (alpha1.find(i) + key_nums[pointer]) % 26
            ans += alpha1[new_index^pointer]
            pointer = (pointer + 1) % len(key_nums)
        elif i in alpha2:
            new_index = (alpha2.find(i) + key_nums[pointer]) % 26
            ans += alpha2[new_index^pointer]
            pointer = (pointer + 1) % len(key_nums)
        else:
            ans += i
    return ans

print(f"c = {encrypt(flag,key)}")
print(f"fake_key = {hex(bytes_to_long(key.encode()))[2:][::-1]}")

"""
c = byqo{A31k0kl_m0_YODPS}
fake_key = 76e6f6c69616e6968637f677
"""
```

**exp**

简单维吉尼亚魔改了一下，所以别想用工具一把梭哦（doge

虽然后来看好多人都是ai解出来的（忘掉还有ai这一回事了

```
from Crypto.Util.number import long_to_bytes

c = "byqo{A31k0kl_m0_YODPS}"
fake_key =  "76e6f6c69616e6968637f677" 

key = long_to_bytes(int(fake_key[::-1],16)).decode()

alpha1 = 'abcdefghijklmnopqrstuvwxyz'
alpha2 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

def decrypt(flag,key):
    key_nums = []
    pointer = 0
    ans = ''
    for i in key:
        if i in alpha1:
            key_nums += [alpha1.find(i)]
        elif i in alpha2:
            key_nums += [alpha2.find(i)]
    for i in flag:
        if i in alpha1:
            new_index = ((alpha1.find(i)^pointer) - key_nums[pointer]) % 26
            ans += alpha1[new_index]
            pointer = (pointer + 1) % len(key_nums)
        elif i in alpha2:
            new_index = ((alpha2.find(i)^pointer) - key_nums[pointer]) % 26
            ans += alpha2[new_index]
            pointer = (pointer + 1) % len(key_nums)
        else:
            ans += i
    return ans

print(decrypt(c,key))

# flag{W31c0me_t0_DRCTF}
```

### LFSR

**题目**

出题人：SeanDictionary

难度：中等

题目描述：奶龙听说你学了线性代数？

静态flag，格式flag{MD5}

```
from random import getrandbits
from hashlib import md5

def MD5(m):return md5(str(m).encode()).hexdigest()

class LFSR:
	def __init__(self, Mask_seed, Length):
		self.Length = Length
		assert Mask_seed.bit_length() < self.Length + 1
		self.seed  = getrandbits(self.Length)
		self.state = self.init_state(self.seed)
		self.mask  = self.init_state(Mask_seed)

	def init_state(self, seed):
		result = [int(i) for i in bin(seed)[2:]]
		PadLenth = self.Length - len(result)
		result += [ 0 ] * PadLenth
		assert len(result) == self.Length
		return result

	def next(self):
		output = 0
		for i in range(self.Length):
			output ^= self.state[i] & self.mask[i] 
		self.state  =  self.state[1:] + [output]
		return output

	def getrandbits(self,Length):
		result = []
		for _ in range(Length):
			result.append(str(self.next()))
		return int(''.join(result),2)

mask = ?
assert mask.bit_length() == 126
flag = 'flag{' + MD5(mask) + '}'

lfsr = LFSR(mask,128)
print(lfsr.getrandbits(128))
print(lfsr.getrandbits(128))

"""
41028035156847898222512503803584638260
86632308540621071257962048347493177990
"""
```

**exp**

在模2域下可以把异或运算看作加法，与运算看作乘法，然后就能根据LFSR原理可以写出AX=B的非齐次线性方程组，用sage求在模2域下的解

```
# sage
from hashlib import md5

def MD5(m):return md5(str(m).encode()).hexdigest()

def init(seed):
    result = [int(i) for i in bin(seed)[2:]]
    PadLenth = 128 - len(result)
    result = [ 0 ] * PadLenth + result
    assert len(result) == 128
    return result

random1 = init(41028035156847898222512503803584638260)
random2 = init(86632308540621071257962048347493177990)

stream = random1+random2

def solution(stream):
    F = GF(2)
    A = Matrix(F, [stream[i:i+128] for i in range(128)])
    B = vector(F, random2)

    x = A.solve_right(B)
    return int("".join(str(i) for i in x),2)

mask = solution(stream)//4
print(mask)
print('flag{' + MD5(mask) + '}')

# 83452003889525778062615500708190350511
# flag{13116b0935c06720514e7c3b9d5f010f}
```

### EZ_RSA

**题目**

出题人：SeanDictionary

难度：简单

题目描述：奶龙对RSA动了一点点手脚，不知道小七能不能解出来呢。

静态flag，格式flag{uuid}

```
from Crypto.Util.number import *
flag = b"flag{uuid}"
p = getPrime(1024)
q = getPrime(1024)
n = p*q
e = 0x10001
hint = pow(p+2,n,n)
c = pow(bytes_to_long(flag),e,n)

print(f"c = {c}")
print(f"hint = {hint}")
print(f"n = {n}")

"""
c = 8010415678766495559206888104308220461000137190504006792719473726344733619441141193462632115436953071133591418480457170724671799432518092660776309476406070558451285172355261125033267340649376421801091685798286314106142855053515428470474693625489377898001862186681685082360598622408094264333299738655461877207390809495955984957338296805424644630493393029139944919536399174215810604102444550172759845344395864486440754752041405094877450680140850037755156965823345868285966939695682195399775462308951218301326547363911121730948439732333381005743591960455287452246675824174748812338877227345103716723376979538380032002880
hint = 4954477722794007679259787705071851835680630074373589614154901212439091693825106875479842554606153058190995214347117184687613051142282846871128812252250637326896296788563890362185505010773931888829285558128596857093099418604694919454819343842312843108124919481178288207784060364226550053354580189857537158580943897179549277643338951797705412207045370229744214727707911966864066911560213737637233870360113799892826929003703273846381898853719476623176860704557650283662945755147547068370364286870324024577488484455358602429710219447526127782448349463942117410190437938834954390911495483413355957621606751450577074102729
n = 10784287819385415353621875218563143302159768325704928073867416808040916996479341048063223714643174249461097295535297542385475849470046760369978768211220988313304188367229395180043407712292398872921220233051142848776456790641708863113887722318345601554351621305567539237641096651148337525250970956775311944016141879494664318933091284315673333318969018209756116226492696486038744619977928991239409925382390262035475423869395568601956013364403631988387757474363593218046567386448482628006367012358287524440361632608335934523058793771435203563217660703267386600175482629638068995270497505139491768944189370651947532096313
"""
```

**exp**

```
from Crypto.Util.number import *
c = 8010415678766495559206888104308220461000137190504006792719473726344733619441141193462632115436953071133591418480457170724671799432518092660776309476406070558451285172355261125033267340649376421801091685798286314106142855053515428470474693625489377898001862186681685082360598622408094264333299738655461877207390809495955984957338296805424644630493393029139944919536399174215810604102444550172759845344395864486440754752041405094877450680140850037755156965823345868285966939695682195399775462308951218301326547363911121730948439732333381005743591960455287452246675824174748812338877227345103716723376979538380032002880
hint = 4954477722794007679259787705071851835680630074373589614154901212439091693825106875479842554606153058190995214347117184687613051142282846871128812252250637326896296788563890362185505010773931888829285558128596857093099418604694919454819343842312843108124919481178288207784060364226550053354580189857537158580943897179549277643338951797705412207045370229744214727707911966864066911560213737637233870360113799892826929003703273846381898853719476623176860704557650283662945755147547068370364286870324024577488484455358602429710219447526127782448349463942117410190437938834954390911495483413355957621606751450577074102729
n = 10784287819385415353621875218563143302159768325704928073867416808040916996479341048063223714643174249461097295535297542385475849470046760369978768211220988313304188367229395180043407712292398872921220233051142848776456790641708863113887722318345601554351621305567539237641096651148337525250970956775311944016141879494664318933091284315673333318969018209756116226492696486038744619977928991239409925382390262035475423869395568601956013364403631988387757474363593218046567386448482628006367012358287524440361632608335934523058793771435203563217660703267386600175482629638068995270497505139491768944189370651947532096313

e = 0x10001

p = GCD(hint-pow(2,n,n),n)
q = n//p
d = inverse(e,(p-1)*(q-1))
print(long_to_bytes(pow(c,d,n)))
# flag{8d3fcc6d-1ea4-4b31-90ae-fc911a127059}
```

### EZ_RSA2

**题目**

出题人：SeanDictionary

难度：中等

题目描述：奶龙竟然先计算私钥再输出的公钥，小七感觉这样有点不太妥当

静态flag，格式flag{uuid}

```
from Crypto.Util.number import *
flag = b"flag{uuid}"

p = getPrime(1024)
q = getPrime(1024)
n = p*q
phi = (p-1)*(q-1)
while True:
    d = getRandomNBitInteger(530)
    if GCD(d,phi) == 1:
        break
e = inverse(d,phi)
c = pow(bytes_to_long(flag),e,n)

print(f"c = {c}")
print(f"n = {n}")
print(f"e = {e}")
'''
c = 7604590913397004198963689400358802120334625316301111112576886513655107430495751968941301515797861955002951207375478521459811264470942298766088374550675466903738516416244757442099063102988037782219973697304563362512368154513305930639693679988291071020713046533919668788348441464101295258155091624702431371922987498153144768352796512144661515761036886506951085217618722096752361644269310855940222737123637473411009002629293214503812144543988961901514327199004251951383064874573493721463001553726609537700853804264152779596347547365622363127042216195888205262834357028553426852001895634392853557568345813531537434672292
n = 16145163005933810407752261390690458192000069934308800024793251111968297506978117680236631519134867456575599695051667859912486947325264983719050757010183264697879891337878352798559722307748191755884685168019750761992350866988144145508350759530849991025771815475490203524655715315406455490957031437606278684238684357961687750515481282458824342733221757328761803977347968239166300156697100824105916874354045078956289531442842186668325781737778325666035240164210867972975845514644865573894980966648127102115771282611672127276763261636922198587850125676847952570005820048642886137010843289815486863693662806191261840920411
e = 9413840062586532516010523846263448906176903339366168394620351383285203947784786691952534789875266051104991259694538552192226487375828641132781200775057320309298063487771973945854529521500040457563489147143649268428244922519913499151774826637646647277986297748039444242699406522861854432612700464070029031566474884803644131248088552581978906584088582170799199341999768616640639555746799089601035552285981690558357540924827239689083275440582504390522264302671874408125583806343189980990565854951321732991659947134880309636077682130661181437635505073400803788606635750774788853039972661648725169986554624217364019814143
'''
```

**exp**

很显然d过小，联想到维纳攻击。

然而维纳攻击有约束条件是$d<\frac{1}{3}N^{\frac{1}{4}}$，尝试维纳攻击会发现不满足

进一步有*Boneh Durfee*攻击，其约束条件$d$是能满足的

[GitHub仓库](https://github.com/mimoo/RSA-and-LLL-attacks/blob/master/boneh_durfee.sage)，在此基础上修改。

```
#sage
import time
from Crypto.Util.number import *
 
"""
Setting debug to true will display more informations
about the lattice, the bounds, the vectors...
"""
debug = True
 
"""
Setting strict to true will stop the algorithm (and
return (-1, -1)) if we don't have a correct 
upperbound on the determinant. Note that this 
doesn't necesseraly mean that no solutions 
will be found since the theoretical upperbound is
usualy far away from actual results. That is why
you should probably use `strict = False`
"""
strict = False
 
"""
This is experimental, but has provided remarkable results
so far. It tries to reduce the lattice as much as it can
while keeping its efficiency. I see no reason not to use
this option, but if things don't work, you should try
disabling it
"""
helpful_only = True
dimension_min = 7 # stop removing if lattice reaches that dimension
 
############################################
# Functions
##########################################
 
# display stats on helpful vectors
def helpful_vectors(BB, modulus):
    nothelpful = 0
    for ii in range(BB.dimensions()[0]):
        if BB[ii,ii] >= modulus:
            nothelpful += 1
 
    print (nothelpful, "/", BB.dimensions()[0], " vectors are not helpful")
 
# display matrix picture with 0 and X
def matrix_overview(BB, bound):
    for ii in range(BB.dimensions()[0]):
        a = ('%02d ' % ii)
        for jj in range(BB.dimensions()[1]):
            a += '0' if BB[ii,jj] == 0 else 'X'
            if BB.dimensions()[0] < 60:
                a += ' '
        if BB[ii, ii] >= bound:
            a += '~'
        print (a)
 
# tries to remove unhelpful vectors
# we start at current = n-1 (last vector)
def remove_unhelpful(BB, monomials, bound, current):
    # end of our recursive function
    if current == -1 or BB.dimensions()[0] <= dimension_min:
        return BB
 
    # we start by checking from the end
    for ii in range(current, -1, -1):
        # if it is unhelpful:
        if BB[ii, ii] >= bound:
            affected_vectors = 0
            affected_vector_index = 0
            # let's check if it affects other vectors
            for jj in range(ii + 1, BB.dimensions()[0]):
                # if another vector is affected:
                # we increase the count
                if BB[jj, ii] != 0:
                    affected_vectors += 1
                    affected_vector_index = jj
 
            # level:0
            # if no other vectors end up affected
            # we remove it
            if affected_vectors == 0:
                print ("* removing unhelpful vector", ii)
                BB = BB.delete_columns([ii])
                BB = BB.delete_rows([ii])
                monomials.pop(ii)
                BB = remove_unhelpful(BB, monomials, bound, ii-1)
                return BB
 
            # level:1
            # if just one was affected we check
            # if it is affecting someone else
            elif affected_vectors == 1:
                affected_deeper = True
                for kk in range(affected_vector_index + 1, BB.dimensions()[0]):
                    # if it is affecting even one vector
                    # we give up on this one
                    if BB[kk, affected_vector_index] != 0:
                        affected_deeper = False
                # remove both it if no other vector was affected and
                # this helpful vector is not helpful enough
                # compared to our unhelpful one
                if affected_deeper and abs(bound - BB[affected_vector_index, affected_vector_index]) < abs(bound - BB[ii, ii]):
                    print ("* removing unhelpful vectors", ii, "and", affected_vector_index)
                    BB = BB.delete_columns([affected_vector_index, ii])
                    BB = BB.delete_rows([affected_vector_index, ii])
                    monomials.pop(affected_vector_index)
                    monomials.pop(ii)
                    BB = remove_unhelpful(BB, monomials, bound, ii-1)
                    return BB
    # nothing happened
    return BB
 
""" 
Returns:
* 0,0   if it fails
* -1,-1 if `strict=true`, and determinant doesn't bound
* x0,y0 the solutions of `pol`
"""
def boneh_durfee(pol, modulus, mm, tt, XX, YY):
    """
    Boneh and Durfee revisited by Herrmann and May
  
    finds a solution if:
    * d < N^delta
    * |x| < e^delta
    * |y| < e^0.5
    whenever delta < 1 - sqrt(2)/2 ~ 0.292
    """
 
    # substitution (Herrman and May)
    PR.<u, x, y> = PolynomialRing(ZZ)
    Q = PR.quotient(x*y + 1 - u) # u = xy + 1
    polZ = Q(pol).lift()
 
    UU = XX*YY + 1
 
    # x-shifts
    gg = []
    for kk in range(mm + 1):
        for ii in range(mm - kk + 1):
            xshift = x^ii * modulus^(mm - kk) * polZ(u, x, y)^kk
            gg.append(xshift)
    gg.sort()
 
    # x-shifts list of monomials
    monomials = []
    for polynomial in gg:
        for monomial in polynomial.monomials():
            if monomial not in monomials:
                monomials.append(monomial)
    monomials.sort()
  
    # y-shifts (selected by Herrman and May)
    for jj in range(1, tt + 1):
        for kk in range(floor(mm/tt) * jj, mm + 1):
            yshift = y^jj * polZ(u, x, y)^kk * modulus^(mm - kk)
            yshift = Q(yshift).lift()
            gg.append(yshift) # substitution
  
    # y-shifts list of monomials
    for jj in range(1, tt + 1):
        for kk in range(floor(mm/tt) * jj, mm + 1):
            monomials.append(u^kk * y^jj)
 
    # construct lattice B
    nn = len(monomials)
    BB = Matrix(ZZ, nn)
    for ii in range(nn):
        BB[ii, 0] = gg[ii](0, 0, 0)
        for jj in range(1, ii + 1):
            if monomials[jj] in gg[ii].monomials():
                BB[ii, jj] = gg[ii].monomial_coefficient(monomials[jj]) * monomials[jj](UU,XX,YY)
 
    # Prototype to reduce the lattice
    if helpful_only:
        # automatically remove
        BB = remove_unhelpful(BB, monomials, modulus^mm, nn-1)
        # reset dimension
        nn = BB.dimensions()[0]
        if nn == 0:
            print ("failure")
            return 0,0
 
    # check if vectors are helpful
    if debug:
        helpful_vectors(BB, modulus^mm)
  
    # check if determinant is correctly bounded
    det = BB.det()
    bound = modulus^(mm*nn)
    if det >= bound:
        print ("We do not have det < bound. Solutions might not be found.")
        print ("Try with highers m and t.")
        if debug:
            diff = (log(det) - log(bound)) / log(2)
            print ("size det(L) - size e^(m*n) = ", floor(diff))
        if strict:
            return -1, -1
    else:
        print ("det(L) < e^(m*n) (good! If a solution exists < N^delta, it will be found)")
 
    # display the lattice basis
    if debug:
        matrix_overview(BB, modulus^mm)
 
    # LLL
    if debug:
        print ("optimizing basis of the lattice via LLL, this can take a long time")
 
    BB = BB.LLL()
 
    if debug:
        print ("LLL is done!")
 
    # transform vector i & j -> polynomials 1 & 2
    if debug:
        print ("looking for independent vectors in the lattice")
    found_polynomials = False
  
    for pol1_idx in range(nn - 1):
        for pol2_idx in range(pol1_idx + 1, nn):
            # for i and j, create the two polynomials
            PR.<w,z> = PolynomialRing(ZZ)
            pol1 = pol2 = 0
            for jj in range(nn):
                pol1 += monomials[jj](w*z+1,w,z) * BB[pol1_idx, jj] / monomials[jj](UU,XX,YY)
                pol2 += monomials[jj](w*z+1,w,z) * BB[pol2_idx, jj] / monomials[jj](UU,XX,YY)
 
            # resultant
            PR.<q> = PolynomialRing(ZZ)
            rr = pol1.resultant(pol2)
 
            # are these good polynomials?
            if rr.is_zero() or rr.monomials() == [1]:
                continue
            else:
                print ("found them, using vectors", pol1_idx, "and", pol2_idx)
                found_polynomials = True
                break
        if found_polynomials:
            break
 
    if not found_polynomials:
        print ("no independant vectors could be found. This should very rarely happen...")
        return 0, 0
  
    rr = rr(q, q)
 
    # solutions
    soly = rr.roots()
 
    if len(soly) == 0:
        print ("Your prediction (delta) is too small")
        return 0, 0
 
    soly = soly[0][0]
    ss = pol1(q, soly)
    solx = ss.roots()[0][0]
 
    #
    return solx, soly
 
def example(N,e,delta):
    ############################################
    # How To Use This Script
    ##########################################
 
    #
    # Lattice (tweak those values)
    #
 
    # you should tweak this (after a first run), (e.g. increment it until a solution is found)
    m = 4 # size of the lattice (bigger the better/slower)
 
    # you need to be a lattice master to tweak these
    t = int((1-2*delta) * m)  # optimization from Herrmann and May
    X = 2*floor(N^delta)  # this _might_ be too much
    Y = floor(N^(1/2))    # correct if p, q are ~ same size
 
    #
    # Don't touch anything below
    #
 
    # Problem put in equation
    P.<x,y> = PolynomialRing(ZZ)
    A = int((N+1)/2)
    pol = 1 + x * (A + y)
 
    #
    # Find the solutions!
    #
 
    # Checking bounds
    if debug:
        print ("=== checking values ===")
        print ("* delta:", delta)
        print ("* delta < 0.292", delta < 0.292)
        print ("* size of e:", int(log(e)/log(2)))
        print ("* size of N:", int(log(N)/log(2)))
        print ("* m:", m, ", t:", t)
 
    # boneh_durfee
    if debug:
        print ("=== running algorithm ===")
        start_time = time.time()
 
    solx, soly = boneh_durfee(pol, e, m, t, X, Y)
 
    # found a solution?
    if solx > 0:
        print ("=== solution found ===")
        if False:
            print ("x:", solx)
            print ("y:", soly)
 
        d = int(pol(solx, soly) / e)
        print ("private key found:", d)
    else:
        print ("=== no solution was found ===")
 
    if debug:
        print("=== %s seconds ===" % (time.time() - start_time))
    return d
 
if __name__ == "__main__":
    c = 7604590913397004198963689400358802120334625316301111112576886513655107430495751968941301515797861955002951207375478521459811264470942298766088374550675466903738516416244757442099063102988037782219973697304563362512368154513305930639693679988291071020713046533919668788348441464101295258155091624702431371922987498153144768352796512144661515761036886506951085217618722096752361644269310855940222737123637473411009002629293214503812144543988961901514327199004251951383064874573493721463001553726609537700853804264152779596347547365622363127042216195888205262834357028553426852001895634392853557568345813531537434672292
    n = 16145163005933810407752261390690458192000069934308800024793251111968297506978117680236631519134867456575599695051667859912486947325264983719050757010183264697879891337878352798559722307748191755884685168019750761992350866988144145508350759530849991025771815475490203524655715315406455490957031437606278684238684357961687750515481282458824342733221757328761803977347968239166300156697100824105916874354045078956289531442842186668325781737778325666035240164210867972975845514644865573894980966648127102115771282611672127276763261636922198587850125676847952570005820048642886137010843289815486863693662806191261840920411
    e = 9413840062586532516010523846263448906176903339366168394620351383285203947784786691952534789875266051104991259694538552192226487375828641132781200775057320309298063487771973945854529521500040457563489147143649268428244922519913499151774826637646647277986297748039444242699406522861854432612700464070029031566474884803644131248088552581978906584088582170799199341999768616640639555746799089601035552285981690558357540924827239689083275440582504390522264302671874408125583806343189980990565854951321732991659947134880309636077682130661181437635505073400803788606635750774788853039972661648725169986554624217364019814143

    # the hypothesis on the private exponent (the theoretical maximum is 0.292)
    delta = 0.26 # this means that d < N^delta
    d = example(n,e,delta)
    print(long_to_bytes(int(pow(c,d,n))))

# flag{effca6f2-1bb5-44f7-9403-1f907f66a83e}
```

### EZ_RSA3

**题目**

出题人：SeanDictionary

难度：困难

题目描述：奶龙小朋友随机生成e之后，好像解不开RSA了你能帮帮他吗？

静态flag，格式flag{uuid}

```
from Crypto.Util.number import *
flag = b"flag{uuid}"
e = bytes_to_long("我才是奶龙！".encode())
p = getPrime(1024)
q = getPrime(1024)
n = p*q
c = pow(bytes_to_long(flag),e,n)

print(f"n = {n}")
print(f"p = {p}")
print(f"q = {q}")
print(f"e = {e}")
print(f"c = {c}")

"""
n = 15053972587712326737984981095267960792339756622065073579111188525445868510590330659604223270721184072331493839265159470170355392171799351983071497034810534019098703586813178437220000299237564282685942973829256106470995577875224440900106659050273746948304690979611555091116990178959102554357379384064023182080666700106786150886642818482223897622665849350111428407215080384898306325112756469433773725135674797895617970989257055210731649722015842513058362567716844365541283978060810817157268638267744593919341826683904937473139716860255365258773315735723264469047254466729380062497129772537539992820940452374819883889699
p = 111461468683434975170530082386729308107721083330906321058829121868326203430516773024485160400892174495966198556599452146295591878375056413679531156926335281885967735274037488966954241985730655093765767422341322517922766939016379989407145412091848456414574239068924973099845847680344754993017711649519082586907
q = 135059880024258078020929974489544029792994133864551720912636124561116374784209453412300842283879224283596533450952894183516931875969274005736947998604565020290825188410459845975970263881482961767263235648934211129811591747510154846615233845871887644159755687581177174650685690858554979076239705934188310748057
e = 20082298101283703288320865436585567770885249
c = 14327804862664623364063959258427178907935384957710441654762368424900120280331345933628360240942622378528249399860274042388166444652264747772626182323631853384104248637306969357143688880736707775656162677920244822555418781064546615832984761008516662819058902729743553993810384792884287893556573015762231261295116313261495782463177386276342992071459495908705548654524926818736963302956262559366847765617107171213693590110396340998799738668493863993908256526309854145408616790448211605902340292953799051938220864866878238498670416409507471485181473643985920194302180643875443988264359015252402590566318567500376646205537
"""
```

**exp**

对不起，我没有完全搞明白，造成了对于当前数据下的特解。

当$m<p$的特殊情况，就会存在$(m^emod\ n)mod\ p = m^emod\ p$也就有$c^dmod\ p = m$

以下是常规解法

$e$和$\varphi$不互质，公约数为11。不能用常见的公约数为2的解法，即二次剩余＋CRT

所以用sage求解有限域下的开高次方

```
# sage
from Crypto.Util.number import *
from sympy.ntheory.modular import crt
 
n = 20842711442594791146374856214121582528327257891225290813530336280687700444434689528826816995021031731878337020258401354242247902015929771200705850569042575063795617552618902055067831789567091099682707220287123616930683072076125198513022885561623361437008244992306768865792693041197168062326383864967510475751670080723664951159890484684505519217732919961729224432272712104986045515824699280116868750810874231095537886084805403707543047980810388103430685071667316750766998309539614497252760370831770767227692489631102634032843034911386056868495655936115954516003022389212611668798342321052971040180450573611390564240021
p = 137781390851060340396968223998690526930435912056692358562614223664922510347445871704636502382766854547191606311425511476233518397873586607249761464364053041404247917286043534726364126793699440378966991010332458964646704685455081199158400370363458729804658285959400442768913766257574555795839402785563688439699
q = 151273777350131818975236703447272644767876460890607208016979326208820990855808091934144966725963648264584996000650605195266873337285464774944340935580617479049172715577337527033005662798874091736285791597528084125742948211645756710142532751685847912882931975890228047159361560810222983927284883336148459636279
e = 20082298101283703288320865436585567770885249
c = 9241547920314927447952803232776776260877370730408869407366523522609798809896216818520835302025186128592377814337727143978399362152104837864424176464366903470412439330034533731142010790653585188045815609733043431619492278166103988269688928050663121253423394791192519454420704101326550561851186291589547971245575555150284784444631972956734645544498725528665403393146845548125746870683521887000572317336812676877882090006898812117086705438177135447606660899859252487291517453435332652633734355534513786485803933409780307318989054401703365992453034914013359661478539068227468147196703523679398162094812807160553501996841

phi = (p-1)*(q-1)
gcd = GCD(e,phi)
d = inverse(e//gcd,phi)
 
 
R1.<x> = PolynomialRing(Zmod(p))
f = x^gcd - c
res1 = f.roots()
 
R2.<y> = PolynomialRing(Zmod(q))
f = y^gcd - c
res2 = f.roots()

for i in res1:
    for j in res2:
        m = crt([p,q],[int(i[0]),int(j[0])])
        if m is not None:
            try:
                print(long_to_bytes(int(pow(m[0],d,n))).decode())
            except Exception as e:
                continue

# flag{1d1f9bb2-e613-437a-849c-ec0db8ae7e42}
```

### LLL

**题目**

出题人：SeanDictionary

难度：简单/中等

题目描述：奶龙听说你学会了LLL？那奶龙可要考考你咯

静态flag，格式flag{MD5}

```
from Crypto.Util.number import *
from hashlib import md5
 
def MD5(m):return md5(m).hexdigest()

hint1 = b''
hint2 = b''

flag = f"flag{{{MD5(hint1 + hint2)}}}"
print(flag)

n = bytes_to_long(hint1)
a = bytes_to_long(hint2)

class LCG():
    def __init__(self, seed):
        self.state = seed
    def next(self):
        b = getRandomNBitInteger(32)
        state = (a*self.state + b)%n
        self.state = state
        return self.state

# part 1
p = getPrime(512)
print(f"p = {p}")
print(f"c = {inverse(n,p)*12345%p}")
"""
p = 12506595164013454866158631644558115305141237853551159687785506803551680177279765522514883247011673821044500450971811108588856569313384915952182118402644451
c = 6858382850871347338401485235522982663178997602186032993411965354243806778002934994521471797373267461374750351180326314850354343417874268012116097315994977
"""

# part 2
lcg = LCG(getRandomNBitInteger(128))
print([lcg.next() for _ in range(10)])
"""
[101394348304330664518612658966551284236, 12600749180053960167869224211924945881, 28111105835225564070023014409051018371, 35958569639368220256458103691515031526, 50706170894482995749385988503884957239, 90820015570145317779253781211515263478, 79622870965381801953499920525513019627, 24936182124493309888971127692766207826, 53512413277230147074476081664641503619, 91957135933128894950250248931906270651]
"""
```

**exp**

第一部分就是LLL入门题，用来锻炼（敲打）的。数据给多了，造成了非预期，实际上预期解12345用不上。

第二部分就是个LCG，只要构造出格就行，如下

已知$s_i=as_{i-1}+b_i+k_im$

$$
\begin{pmatrix}k_1&k_2&\dots&k_9&-a&1\end{pmatrix} \begin{pmatrix} n& & & & &0\\ &n& & & & \\ & &\ddots& & &\vdots\\ & & &n& & \\ s_0&s_1&\dots&s_8&1&0\\ s_1&s_2&\dots&s_9&0&1\\ \end{pmatrix}= \begin{pmatrix}b_1&b_2&\dots&b_9&-a&1\end{pmatrix}
$$

```
# sage
from Crypto.Util.number import *
from hashlib import md5
 
def MD5(m):return md5(m).hexdigest()

# Part 1
p = 12506595164013454866158631644558115305141237853551159687785506803551680177279765522514883247011673821044500450971811108588856569313384915952182118402644451
c = 6858382850871347338401485235522982663178997602186032993411965354243806778002934994521471797373267461374750351180326314850354343417874268012116097315994977

ge = [[1,c],[0,p]]
Ge = Matrix(ZZ,ge)
res = Ge.LLL()[0]
hint1 = long_to_bytes(int(abs(res[0])))
print(hint1)

# part 2
n = bytes_to_long(hint1)
s = [101394348304330664518612658966551284236, 12600749180053960167869224211924945881, 28111105835225564070023014409051018371, 35958569639368220256458103691515031526, 50706170894482995749385988503884957239, 90820015570145317779253781211515263478, 79622870965381801953499920525513019627, 24936182124493309888971127692766207826, 53512413277230147074476081664641503619, 91957135933128894950250248931906270651]
ge = [[0]*11 for _ in range(11)]
for i in range(9):
    ge[i][i] = n
ge[-2] = [s[i] for i in range(9)] + [1,0]
ge[-1] = [s[i+1] for i in range(9)] + [0,1]
Ge = Matrix(ZZ,ge)
res = Ge.LLL()[0]
hint2 = long_to_bytes(int(abs(res[-2])))
print(hint2)

flag = f"flag{{{MD5(hint1 + hint2)}}}"
print(flag)

# flag{896787a060cf738d896d9d7a1a270200}
```

### EC-LCG

**题目**

出题人：SeanDictionary

难度：困难

题目描述：诶诶你LLL都做出来了嘛？看来你一定对LCG很熟悉吧，那我奶龙可要往里面再加点佐料了。

静态flag，格式flag{MD5}

```
from hashlib import md5
from Crypto.Util.number import * 
from random import randint

class Point:
	def __init__(self,x,y,curve, isInfinity = False):
		self.x = x % curve.p
		self.y = y % curve.p
		self.curve = curve
		self.isInfinity = isInfinity
	def __add__(self,other):
		return self.curve.add(self,other)
	def __mul__(self,other):
		return self.curve.multiply(self,other)
	def __rmul__(self,other):
		return self.curve.multiply(self,other)
	def __str__(self):
		return f"({self.x},{self.y})"
	def __eq__(self, other):
		return self.x == other.x and self.y == other.y and self.curve == other.curve

class Curve:
	def __init__(self,a,b,p):
		self.a = a%p
		self.b = b%p
		self.p = p
	
	def multiply(self, P:Point, k:int) -> Point:
		Q = P
		R = Point(0,0,self,isInfinity=True)
		while k > 0 :
			if (k & 1) == 1:
				R = self.add(R,Q)
			Q = self.add(Q,Q)
			k >>= 1
		return R

	def find_y(self,x):
		x = x % self.p
		y_squared = (pow(x, 3, self.p) + self.a * x + self.b) % self.p
		assert pow(y_squared, (self.p - 1) // 2, self.p) == 1, "The x coordinate is not on the curve"
		y = pow(y_squared, (self.p + 1) // 4, self.p)
		assert pow(y,2,self.p) == (pow(x, 3, self.p) + self.a * x + self.b) % self.p
		return y

	def add(self,P: Point, Q : Point) -> Point:
		if P.isInfinity:
			return Q
		elif Q.isInfinity:
			return P
		elif P.x == Q.x and P.y == (-Q.y) % self.p:
			return Point(0,0,self,isInfinity=True)
		if P.x == Q.x and P.y == Q.y:
			param = ((3*pow(P.x,2,self.p)+self.a) * pow(2*P.y,-1,self.p))
		else:
			param = ((Q.y - P.y) * pow(Q.x-P.x,-1,self.p))
		Sx =  (pow(param,2,self.p)-P.x-Q.x)%self.p
		Sy = (param * ((P.x-Sx)%self.p) - P.y) % self.p
		return Point(Sx,Sy,self)

	def getrandpoint(self):
		while True:
			try:
				g = randint(1,self.p)
				G = Point(g, self.find_y(g), self)
				return G
			except:
				continue

class LCG():
    def __init__(self, seed: Point):
        self.state = seed
    def next(self):
        state = a*self.state + b
        self.state = state
        return state

flag1 = bytes_to_long(b"???")
p = getStrongPrime(1024)
q = getStrongPrime(1024)
e = 0x10001
n = p*q
c = pow(flag1,e,n)

while True:
    A = getRandomRange(p//2, p)
    B = getRandomRange(p//2, p)
    if (4*A**3+27*B**2)%p != 0:
        break

curve = Curve(A,B,p)
a = 1
b = curve.getrandpoint()
seed = curve.getrandpoint()
lcg = LCG(seed)

print(f"n = {n}")
print(f"c = {c}")
print(f"x = {[lcg.next().x for _ in range(7)]}")
flag = f"flag{{{md5(str(flag1+A+B).encode()).hexdigest()}}}"

"""
n = 20063834046803339010734658003051195926058980360352771999689605607630526133132709437443635728948194493378000453054594612019606018364170142821489063436615174507966641604457054729938970030825668574099411633352767113560994174904668528250330010403672367012235123491319990893295338126652169342947129952897103255421610611676218140533575176124779757098044204750351046938137029682233716532435712262076725928693345831687980022239186207541579727487055561763228421278516486530473677567116153973699050596077054192559466221749636983131259865361523395158653254663009172774003918269609592892356940916381199781312182290682707986541863
c = 11485262431666829221429328413707503063456015296829489341150255297505940688399716808961483156815143157305266117131180423677246094828984149176251230471111586667354279597454209596364389181173355522913933983588124441341665710392967462694488593117859962160338663562328636384730549078430168409232764076876912754880592004690624910195705067204232766913685644641365267349715934951662510683882969035414449683415362151508158254205270541800186927403042540671378869256579679214959641663092289706530040934973574766703331476619780262004856097589605106411700046656397803227659376975726367024185426906693074351638592127241941697189426
x = [123940278769819930556399347377619997590419209917515812977329095798416348541743108523463370292741159783762186256113649324358585540469865121845531735494722777922645965602508104938318567564849683209888197500870011207680282376863682063481785326722268467688329092271132282025100090978251724030801926856068665290551, 66121875834840701781315182052680281146180568070007572825818145475659070221201537343952531270942395108468637418918713629038162553649553392293796158251443767740622460186655092883126883400290059492883418498946415524936284205058506435294186976384481685109015167897791130563131421140532688628917115961232304520927, 2182693533357663831580479237697348461658279194496241938306969874988124696344580657073200393885989193913697901608659569588422293906780857228710230116114881109397674409436496101476523127467579403811321406958504201402719576273359145793529842869151649205566173315021714412842780385745503659284311906947957097953, 41925749629376746955048720205802018262770680829292406386751349693414414862688882614547146253599850178188879866326961925904386260100680508709468163659055019709559983082460827137281739474797067166502884057541771775614188031634779557588118927050058762439168798203602274937344215104455856643696964649907915653217, 1072008214030890531415051577275601146760864518785740416016116731117426061158028987145052745324946921870658674418987200960027821259025438875841297790268677410408378839106807736003264481798515693641954385655259769008759561902919406850771030592918393733060056266876691447397067408917683914663164817558044702563, 131622877797317940408661469675812156417619371713350831896620313739931875603625559254779319574819031642236115622746572489250297417252042080150528432362668238469566492744399679662206574547988710652437870317075246098134655585511168918685974460354734671485273582596872492027754664437269646799378713164637343000145, 132249104865208733672081867387965874608317454072933932187172149055629465066502705833543935891958474879551687986236245110220668480615535040355635889266574465566045240762793493315695298985038276680029966600618123481639408560245076968863803273992170199361617897074669018671828067226506615125843581251286573888826]
"""
```

**exp**

是道论文题，不过有被出过少量的题目

类似的题

[RCTF 2022 - IS_THIS_LCG?](https://github.com/pcw109550/write-up/blob/master/2022/RCTF/IS_THIS_LCG/README.md)

[Devcon 2024 Immunefi CTF - Curve Validator Plus](https://github.com/sahuang/sahuang.github.io/blob/98469bb4934da6252ddf7bac56284877d68d8627/writeups/devcon-2024/index.md)

论文

[PREDICTING THE ELLIPTIC CURVE CONGRUENTIAL GENERATOR](http://compalg.inf.elte.hu/~merai/pub/merai_predictingEC-LCG.pdf)

emmm……盲猜应该不会有太多人能解出来吧？

题解就不写太详细了，本蒟蒻也是照着上面的wp改的，下面贴代码

```
# sage
from Crypto.Util.number import * 
from hashlib import md5

n = 20063834046803339010734658003051195926058980360352771999689605607630526133132709437443635728948194493378000453054594612019606018364170142821489063436615174507966641604457054729938970030825668574099411633352767113560994174904668528250330010403672367012235123491319990893295338126652169342947129952897103255421610611676218140533575176124779757098044204750351046938137029682233716532435712262076725928693345831687980022239186207541579727487055561763228421278516486530473677567116153973699050596077054192559466221749636983131259865361523395158653254663009172774003918269609592892356940916381199781312182290682707986541863
c = 11485262431666829221429328413707503063456015296829489341150255297505940688399716808961483156815143157305266117131180423677246094828984149176251230471111586667354279597454209596364389181173355522913933983588124441341665710392967462694488593117859962160338663562328636384730549078430168409232764076876912754880592004690624910195705067204232766913685644641365267349715934951662510683882969035414449683415362151508158254205270541800186927403042540671378869256579679214959641663092289706530040934973574766703331476619780262004856097589605106411700046656397803227659376975726367024185426906693074351638592127241941697189426
x = [123940278769819930556399347377619997590419209917515812977329095798416348541743108523463370292741159783762186256113649324358585540469865121845531735494722777922645965602508104938318567564849683209888197500870011207680282376863682063481785326722268467688329092271132282025100090978251724030801926856068665290551, 66121875834840701781315182052680281146180568070007572825818145475659070221201537343952531270942395108468637418918713629038162553649553392293796158251443767740622460186655092883126883400290059492883418498946415524936284205058506435294186976384481685109015167897791130563131421140532688628917115961232304520927, 2182693533357663831580479237697348461658279194496241938306969874988124696344580657073200393885989193913697901608659569588422293906780857228710230116114881109397674409436496101476523127467579403811321406958504201402719576273359145793529842869151649205566173315021714412842780385745503659284311906947957097953, 41925749629376746955048720205802018262770680829292406386751349693414414862688882614547146253599850178188879866326961925904386260100680508709468163659055019709559983082460827137281739474797067166502884057541771775614188031634779557588118927050058762439168798203602274937344215104455856643696964649907915653217, 1072008214030890531415051577275601146760864518785740416016116731117426061158028987145052745324946921870658674418987200960027821259025438875841297790268677410408378839106807736003264481798515693641954385655259769008759561902919406850771030592918393733060056266876691447397067408917683914663164817558044702563, 131622877797317940408661469675812156417619371713350831896620313739931875603625559254779319574819031642236115622746572489250297417252042080150528432362668238469566492744399679662206574547988710652437870317075246098134655585511168918685974460354734671485273582596872492027754664437269646799378713164637343000145, 132249104865208733672081867387965874608317454072933932187172149055629465066502705833543935891958474879551687986236245110220668480615535040355635889266574465566045240762793493315695298985038276680029966600618123481639408560245076968863803273992170199361617897074669018671828067226506615125843581251286573888826]

T = Matrix(ZZ,[[2 * x[i] ** 2 + 2 * x[i] * (x[i - 1] + x[i + 1]), 2 * x[i] - (x[i - 1] + x[i + 1]), 2 * x[i], 2, (x[i - 1] + x[i + 1]) * x[i] ** 2] for i in range(1, 6)])
p = gcd(T.determinant(),n)
q = n//p
d = pow(0x10001, -1, (p-1)*(q-1))
flag1 = int(pow(c,d,n))
print(long_to_bytes(flag1))

C = matrix(GF(p),[[2 * x[i] ** 2 + 2 * x[i] * (x[i - 1] + x[i + 1]),2 * x[i] - (x[i - 1] + x[i + 1]),2 * x[i],2,2,-2] for i in range(1, 6)])

u = vector(GF(p),[(x[i - 1] + x[i + 1]) * x[i] ** 2 for i in range(1, 6)])

e = C.solve_right(u)
A = ZZ(e[2])
print(A)

F = GF(p)
R.<BB> = PolynomialRing(F)
equation = (C[0][0] * e[0] + C[0][1] * e[0]**2 + C[0][2] * A + C[0][3] * BB + C[0][4] * (e[0]**3 + A * e[0] + BB) + C[0][5] * e[0]**3) - u[0]
result = equation.subs(BB=0)
B = ZZ(- result * pow(4, -1, p) % p)
print(B)

flag = f"flag{{{md5(str(flag1+A+B).encode()).hexdigest()}}}"
print(flag)

# flag{4caf3aaee01ddec3ed51244fe5e99998}
```

Tips：上面计算的A和B是在有限域下的，所以别忘了转化到整数域上，不然后面的加法会自动取模

### hash_decrypt

**题目**

出题人：SeanDictionary

难度：困难

题目描述：hash函数是不可逆的，真的吗？

静态flag，格式flag{uuid}

```
flag = b"flag{uuid}"

def padding(byte, n):
    padding_length = n - (len(byte) % n)
    byte += bytes([padding_length] * padding_length)
    return byte

def nailong(byte):
	base = 0x6c62272e07bb014262b821756295c58d
	x = 0x0000000001000000000000000000013b
	MOD = 2**128
	for i in byte:
		base = (base * x) & (MOD - 1) 
		base ^= i
	return hex(base)

def encrypte(flag):
    flag = padding(flag,8)
    hash_encrypte = []
    for i in range(0,len(flag),8):
        hash_encrypte += [nailong(flag[i:i+8])[2:]]
    return "".join(hash_encrypte)

print(f"c = {encrypte(flag)}")

"""
c = c95cefdc9465995a309cd28f2664ede058d14499d865995b1290eca4d508d412d54abc786865995af58270805e2415a32eb961154365995af588c43d365d64f8912b01f73765995a3d053c465808efbae32287a69765995b0c46541a32d33811
"""
```

**exp**

出题灵感来自长城杯的fffffhash

这是FNV哈希算法，在用脚本生成目标哈希的碰撞对的时候，发现对于短文本的输入极有可能生成原文而非碰撞对，这或许可以作为一种攻击方式来逆向原文。

$$
h_1=xh_0+b_1\ mod\
$$

$$
h_{i+1}=xh_i+b_{i+1}\ mod\
$$

$$
h_n=x^nh_0+x^{n-1}b_0+x^{n-2}b_1+\dots +xb_{n-1}+b_n\ mod\
$$

构造格

$$
\begin{pmatrix}b_n&b_{n-1}&\dots&b_1&1&k\end{pmatrix} \begin{pmatrix} 1& & & & &x^0\\ &1& & & &x^1\\ & &\ddots& & &\vdots\\ & & &1& &x^{n-1}\\ & & & &1&x^nh_0-C\\ & & & & &M\\ \end{pmatrix}= \begin{pmatrix}b_n&b_{n-1}&\dots&b_1&1&0\end{pmatrix}
$$

用$K=2^{128}$配平，得到

$$
\begin{pmatrix}b_n&b_{n-1}&\dots&b_1&1&k\end{pmatrix} \begin{pmatrix} 1& & & & &x^0K\\ &1& & & &x^1K\\ & &\ddots& & &\vdots\\ & & &1& &x^{n-1}K\\ & & & &1&(x^nh_0-C)K\\ & & & & &MK\\ \end{pmatrix}= \begin{pmatrix}b_n&b_{n-1}&\dots&b_1&1&0\end{pmatrix}
$$

```
# sage
from Crypto.Util.number import *
base_num = 0x6c62272e07bb014262b821756295c58d
x = 0x0000000001000000000000000000013b
MOD = 2^128
c = "c95cefdc9465995a309cd28f2664ede058d14499d865995b1290eca4d508d412d54abc786865995af58270805e2415a32eb961154365995af588c43d365d64f8912b01f73765995a3d053c465808efbae32287a69765995b0c46541a32d33811"
x_ = inverse(x,MOD)

n = 8
output = bytes()

for l in range(0,len(c),32):
    target = int(c[l:l+32],16)
    ge = [[0]*(n+2) for _ in range(n+2)]
    for i in range(n+2):
        ge[i][i] = 1

    for i in range(n):
        ge[i][-1] = x^i

    ge[-2][-1] = (x^n)*base_num-target
    ge[-1][-1] = MOD

    bits = 128

    Ge = Matrix(ZZ,ge)
    Q = Matrix.diagonal([1] * (n+1) + [2^bits])
    Ge = Ge*Q
    res = Ge.LLL()
    res = res/Q

    for row in res:
        h = target
        ans = []
        if row[-1] == 0 and row[-2] == 1:
            for i in row[:-2]:
                h = (h-i)*x_%MOD
                ans += [int(h*x+i)^^int(h*x)]
        if ans != []:
            output += bytes(ans[::-1])
print(output)

# flag{2d813771-7287-4904-81ea-7c3c6d9dfd33}
```

## OSINT

### 图寻②

**题目**

难度：中等

出题人：SeanDictionary

题目描述：寻找出谷歌地图上最接近图片的位置（能完整显示路牌），经纬度取小数点后三位。例如:55.3647278,-11.3524167；取55.364,-11.352进行md5加密(32位小写)。flag{md5加密后的坐标}

![](https://seandictionary.top/wp-content/uploads/2025/01/image-17-1024x513.png)

**exp**

两种方式，一种找到原视频出处，原视频标题包含了路线信息。一种根据图片文字线索找到湖即可（有一座离得很远的港口名字相近，可能会因此找错）

有一说一根本用不上ai识图

**方法一**

用ai先把文字提取出来Breiðbalakvísl注意不要直接在谷歌地图搜，这样会搜到Breiðdalsvík，这不是路牌上的位置，是很远的一座港口，会找错。所以建议是直接谷歌搜索，能发现是条河

![](https://seandictionary.top/wp-content/uploads/2025/01/image-16-1024x555.png)

然后再去谷歌街景找

**方法二**

左下角水印能辨识出omadic，在油管搜索相关up会自动补全为nomadic，很容易就能找到这个up

![](https://seandictionary.top/wp-content/uploads/2025/01/image-15-1024x543.png)

搜索他的Iceland视频，播放量第一就是，找到Relaxing Rainy Drive in Iceland | Kirkjubæjarklaustur to Glacier Lagoon, Rain Sounds for Sleep ASMR，标题写明白了具体的行驶路线，在2：56找到图片出处。

直接按行驶路线走一遍就能找到。

url：[链接](https://www.google.com.hk/maps/@63.813462,-18.0119339,3a,75y,40.1h,74.42t/data=!3m7!1e1!3m5!1sXY6Bu-pZwGmwy5_jA-uAiw!2e0!6shttps:%2F%2Fstreetviewpixels-pa.googleapis.com%2Fv1%2Fthumbnail%3Fcb_client%3Dmaps_sv.tactile%26w%3D900%26h%3D600%26pitch%3D15.579321705065524%26panoid%3DXY6Bu-pZwGmwy5_jA-uAiw%26yaw%3D40.104795891408926!7i16384!8i8192!5m1!1e4?entry=ttu&g_ep=EgoyMDI0MTIxMS4wIKXMDSoASAFQAw%3D%3D)

ps：附件不是谷歌街景截图，选自[油管视频](https://www.youtube.com/watch?v=ObrzfkEqQac)

flag{80c7218d9f5e7c332d15bc94c794f9c9}
