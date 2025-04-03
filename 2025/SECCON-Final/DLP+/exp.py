from Crypto.Util.number import isPrime
from sage.all import factor, GF, discrete_log, PolynomialRing
from pwn import remote, process


p = 15716184699547462800461771601028927135348272154927459012381834606394607906735138215326765472045739095867667862791827281627279676331280673025582786492800565034681474589962543612181570816917654358007798115791387579073196284235251797321810838517520967959561184040912976519718458581462926905245885178079360322053716674233519451182638293301601
k = 1125
smooth_order = 81702288101897374130672874598561902721173468294968431566564038710852096398047085617569136205194590591076494888575280919059927276469484223384374847874938192122852470746278712759413600
max_pf = 40396092614384641
smooth_order //= max_pf
T = (p-1) // smooth_order

assert isPrime(p)
assert (2**k - 3) % p == 0
assert (p-1) % smooth_order == 0
g = p // 2
h = p // 3
assert g**k % p == h % p
import time 
st = time.time()
local = True
if local:
    io = process(["python3", "server.py"])
else:
    io = remote("xxxx", 0000)
    
io.sendlineafter(b"> ", hex(p).encode())
r = int(io.recvline().strip().split(b" = ")[1])
pr = PolynomialRing(GF(p), 'x')
Fp = GF(p)
v = pr.gen()
fx = v + v**k - r
rs = fx.roots()
for r_m in rs:
    root = r_m[0]
    try:
        print("Trying Discrete Log...")
        rx = discrete_log(Fp(root)**T, Fp(g)**T, ord=smooth_order)
    except:
        print("Discrete Log Failed")
        continue
    print(f"Discrete Log Success: {int(rx).bit_length()}")
    if int(rx).bit_length() <= 512:
        et = time.time()
        print(f"Time: {et - st}")
        io.sendlineafter(b"> ", str(rx).encode())
        print(io.recvline())
        io.interactive()
        exit()