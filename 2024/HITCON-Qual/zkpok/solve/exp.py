from pwn import remote, process, log
import gmpy2
from Crypto.Util.number import getPrime, getRandomRange, GCD
from sage.all import PolynomialRing, Zmod
import json
import random

local = True
A = 2**1000
B = 2**80

if local:
    io = process(["python3", "server.py"])
else:
    io = remote("localhost", 1337)
    
n = int(io.recvline().decode().strip().split(" = ")[1])
    
def zkpof_verifier(io: remote, e: int):
    io.sendlineafter(b"e = ", str(e).encode())
    return io.recvline().decode()

def zkpof_prover(io:remote, n, z, phi):
    r = getRandomRange(0, A)
    x = pow(z, r, n)
    io.sendlineafter(b"x = ", str(x).encode())
    io.recvuntil(b"e = ")
    e = int(io.recvline().decode().strip())
    y = r + (n - phi) * e
    io.sendlineafter(b"y = ", str(y).encode())
    


# let c = n - phi = p + q - 1
# y = r +  c * e
lb = 1
ub = 2**513
bound_y = 10**4300
rand = random.Random(1337)

for i in range(0x137):
    z = rand.randrange(2, n)
    mid = (lb + ub) // 2
    estimated_e = -bound_y // mid
    response = zkpof_verifier(io, estimated_e)
    if "Exceeds" in response:
        # c*estimated_e > bound_y > mid * estimated_e
        # c > mid
        lb = mid
    else:
        ub = mid

log.info(f"lb = {lb}")
log.info(f"ub = {ub}")

# we have approximately 0x137 bits of p+q - 1 i.e. 0x137 bits of p+q
p_plus_q = (lb + ub) // 2
p_minus_q = int(gmpy2.isqrt(abs(p_plus_q**2 - 4 * n)))
p_h = (p_plus_q + p_minus_q) // 2
poly_ring = PolynomialRing(Zmod(n), 'x')
x = poly_ring.gen()
f = p_h + x
x0 = int(f.small_roots(beta=0.495, X=2**(512 - 0x137 + 3), epsilon=0.02)[0])

p = GCD(p_h + x0, n)
q = n // p
assert p * q == n
log.info("Successfully factored n")

phi = (p - 1) * (q - 1)

for i in range(13):
    z = rand.randrange(2, n)
    zkpof_prover(io, n, z, phi)
    
io.recvline().decode()
log.info(io.recvline().decode())

