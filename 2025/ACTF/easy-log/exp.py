from pwn import remote, process
from sage.all import GF, lcm, discrete_log, crt
from collections import namedtuple
import re
import subprocess

class Point(namedtuple("Point", "x y")):
    # re-implement Point for ease of use in discrete_log
    __slots__ = () 
    def is_zero(self):
        return self.x == 0 and self.y == 1

# this is actually the identity element in this group
O = Point(0, 1)
n = 0x231d5fa471913e79facfd95e9b874e2d499def420e0914fab5c9f87e71c2418d1194066bd8376aa8f02ef35c1926f73a46477cd4a88beae89ba575bb3e1b04271426c6706356dd8cd9aa742d7ad0343f8939bfd2110d45122929d29dc022da26551e1ed7000
G1 = Point(0xf22b9343408c5857048a19150c8fb9fd44c25d7f6decabc10bf46a2250a128f0df15adc7b82c70c0acaf855c0e898b141c9c94ba8aef8b67ea298c6d9fd870ea70e1c4f8a1b595d15373dc6db25a4ecddf626a64f47beba5538b7f733e4aa0c4f1fd4c291d, 0x8d3264514b7fdbce97fbaedb33120c7889a1af59691a1947c2c7061347c091b0950ca36efaa704514004a988b9b87b24f5cebf2d1c7bef44ff172519e1a62eb62cde234c94bd0ab39375d7ddb42e044090c8db46d3f965ef7e4753bc41dac3b8b3ae0cdb57)
G2 = Point(0x81919777837d3e5065c6f7f6801fe29544180be9db2137f075f53ebb3307f917183c6fc9cdfc5d75977f7, 0xd1a586d6848caa3a5436a86d903516d83808ce2fa49c5fb3f183ecb855e961c7e816a7ba8f588ef947f19)

def point_addition(P, Q, n):
	if P == O:
		return Q
	if Q == O:
		return P
	x = (P.x * Q.y + P.y * Q.x - P.x * Q.x) % n
	y = (P.x * Q.x + P.y * Q.y) % n
	return Point(x, y)
	
def double_and_add(k, P, n):
	Q = P
	R = O
	while(k > 0):
		if k & 1:
			R = point_addition(R, Q, n)
		k >>= 1
		Q = point_addition(Q, Q, n)
	return R

def inverse_point(P, n, o):
	return double_and_add(o - 1, P, n)

def solve_pow(io: remote):
    io.recvline().decode().strip()
    data = io.recvline().decode().strip()
    print("Received:", data)
    match = re.search(r"hashcash -mb26 (\w+)", data)
    if not match:
        print("Failed to parse challenge")
        return None
    
    token = subprocess.getoutput(f"hashcash -mb26 {match.group(1)}")
    token = token.strip().split("token: ")[-1].strip()
    print("Generated token:", token)
    io.sendline(token.encode())
    io.recvuntil(b"ok\n")
    
local = False
if local:
    io = process(["python3", "easy_log.py"])
else:
    io = remote("1.95.139.148", 9999)
    solve_pow(io)

# 544 bits
mods = [5**4, 15271784978279, 10714146599832792643, 222696442740376752383, 899889935029682511225429150065010811552017719005924136271659168643090431]
os = [5**3 * 20, 15271784978278, 114792937362708591729034885900234925448, 49593705609217901538575978041198096178688, 899889935029682511225429150065010811552017719005924136271659168643090430]
full_order = lcm(os)
print(f"Full order: {full_order} {full_order.bit_length()} bits")

Q = eval(io.recvline().decode().strip())
print(f"{Q = }")

gs = [Point(G1.x % mod, G1.y % mod) for mod in mods]
qs = [Point(Q.x % mod, Q.y % mod) for mod in mods]
rs = []

for idx in range(len(gs)):
    rx = discrete_log(qs[idx], gs[idx], os[idx], operation = "other", op = lambda x, y: point_addition(x, y, mods[idx]), 
                   identity=O, inverse= lambda x: inverse_point(x, mods[idx], os[idx]), algorithm="rho")
    rs.append(rx)

R = int(crt(rs, os))

# approximately 531 bits, we need to brute force a few bits to find flag1
flag1 = int(R)
while flag1 + full_order <= 2**544:
    flag1 += int(full_order)
    flag1_bytes = flag1.to_bytes(68, "big")
    if b"flag" in flag1_bytes or b"ACTF" in flag1_bytes:
        print(flag1_bytes)
        break

io.sendline(str(flag1).encode())
# smooth prime
p = 2219022262563817845601233887142124809519397622843764993025777505315744485194120997284413295120744840338461136718631385841
io.sendline(str(p).encode())
Q = eval(io.recvline().decode().strip())
G = Point(0x81919777837d3e5065c6f7f6801fe29544180be9db2137f075f53ebb3307f917183c6fc9cdfc5d75977f7 % p, 0xd1a586d6848caa3a5436a86d903516d83808ce2fa49c5fb3f183ecb855e961c7e816a7ba8f588ef947f19 % p)
# G's order in curve mod p
g_order = 221902226256381784560123388714212480951939762284376499302577750531574448519412099728441329512074484033846113671863138584
rx = discrete_log(Q, G, g_order, operation = "other", op = lambda x, y: point_addition(x, y, p), 
                   identity=O, inverse= lambda x: inverse_point(x, p, g_order), algorithm="rho")

# still need to brute force a few bits
flag2 = int(rx)
while flag2 + g_order <= 2**400:
    flag2 += g_order
    flag2_bytes = flag2.to_bytes(50, "big")
    if all(num < 128 for num in flag2_bytes[:10]):
        print(flag2_bytes)
        break