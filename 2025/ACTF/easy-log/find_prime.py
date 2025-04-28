from Crypto.Util.number import getPrime, isPrime
from random import getrandbits
from collections import namedtuple
from sage.all import factor

class Point(namedtuple("Point", "x y")):
    __slots__ = () 
    def is_zero(self):
        return self.x == 0 and self.y == 1

O = "Origin"
O = Point(0, 1)

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

def get_smooth_prime(bits, smoothness=16):
    assert bits - 2 * smoothness > 0
    p = 2
    while p.bit_length() < bits - 2 * smoothness:
        factor = getPrime(smoothness)
        p *= factor

    bitcnt = (bits - p.bit_length()) // 2
    while True:
        prime1 = getrandbits(bitcnt)
        prime2 = getrandbits(bitcnt)
        tmpp = p * prime1 * prime2
        if tmpp.bit_length() < bits:
            bitcnt += 1
            continue
        if tmpp.bit_length() > bits:
            bitcnt -= 1
            continue
        if isPrime(tmpp + 1):
            p = tmpp + 1
            break
    return p

def find_order(G, order, mod):
    order_facs = factor(order)
    for p, _ in order_facs:
        while order % p == 0 and double_and_add(order//p, G, mod) == O:
            order //= p
    return order

p = get_smooth_prime(400, 16)
print(f"p = {p} {p.bit_length()} bits")
G2 = Point(0x81919777837d3e5065c6f7f6801fe29544180be9db2137f075f53ebb3307f917183c6fc9cdfc5d75977f7 % p, 0xd1a586d6848caa3a5436a86d903516d83808ce2fa49c5fb3f183ecb855e961c7e816a7ba8f588ef947f19 % p)

if double_and_add(p, G2, p) == G2:
    print("Good prime")
    real_order = find_order(G2, p - 1, p)
    print(f"Order: {real_order} {real_order.bit_length()} bits")
