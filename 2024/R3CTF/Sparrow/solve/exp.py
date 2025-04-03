from linearizaion import ABC_linearization
from sage.all import PolynomialRing, GF, matrix, vector, QQ, BooleanPolynomialRing, ZZ, Sequence, solve
from utils import Sparrow, fault, noise
import os
from pwn import remote, log, context
import json
from pwnlib.util.iters import mbruteforce
import string
import hashlib

spr = Sparrow(key=os.urandom(16))
# ctf2024-entry.r3kapig.com:32063
io = remote("ctf2024-entry.r3kapig.com", 32063)
# context.log_level = 'debug'

def solve_pow(io:remote):
    io.recvuntil(b"|    sha256(XXXX + ")
    suffix = io.recvuntil(b") == ").strip(b") == ")
    target = io.recvline().strip().decode()
    log.info(f"{suffix = }")
    log.info(f"{target = }")
    table = string.ascii_letters + string.digits
    sol = mbruteforce(lambda x: hashlib.sha256(x.encode() + suffix).hexdigest() == target, table, 4)
    io.sendlineafter(b"|    XXXX>", sol.encode())

def oracle(t: int) -> dict:
    io.sendlineafter(b'|  >', b'h')
    io.sendlineafter(b'|  chaos>', str(t).encode())
    data = io.recvline().strip().decode().replace("'", '"')
    return json.loads(data)
    
def recover_ct(t = 132):
    ys = PolynomialRing(ZZ, 128, 'y').gens()
    data = oracle(t)
    seed = bytes.fromhex(data['s'])
    cts = [bytes.fromhex(data['c'][i:i+32]) for i in range(0, len(data['c']), 32)]
    es = [bytes.fromhex(data['e'][i:i+32]) for i in range(0, len(data['e']), 32)]
    A, B, C = ABC_linearization(seed)
    eqs = []
    for e, ct in zip(es, cts):
        e_vec = spr.split(e)
        ct_vec = spr.split(ct)
        rh = sum(ct_vec)
        lh = 0
        cc = B * vector(GF(2), e_vec) + C
        cc = [int(i) for i in cc]
        for i in range(128):
            if cc[i] == 1:
                lh += (1 - ys[i])
            else:
                lh += ys[i]
        eqs.append(lh - rh)
    seq = Sequence(eqs)
    M, b = seq.coefficient_matrix()
    ker = M.right_kernel().basis()
    if len(ker) == 0:
        print("No solution")
        print("Check the equations")
    elif len(ker) > 1:
        print(f"Multiple solutions {len(ker) = }")
    sol = ker[0]
    # print(f"{sol = }")
    return A, B, C, sol

solve_pow(io)
A1, B1, C1, sol1 = recover_ct()
A2, B2, C2, sol2 = recover_ct()
A3, B3, C3, sol3 = recover_ct()


br = BooleanPolynomialRing(256, 'x')
xs = br.gens()
assert sol1[128] == 1 and sol2[128] == 1 and sol3[128] == 1
S1 = vector(br, [int(i) for i in sol1[:128]])
S2 = vector(br, [int(i) for i in sol2[:128]])
S3 = vector(br, [int(i) for i in sol3[:128]])

ms = list(xs[:128])
ks = list(xs[128:])
eqs = []
# A1 * x + B1 * m = S1
# A2 * x + B2 * m = S2
# A3 * x + B3 * m = S3

polys = A1 * vector(ms) + B1 * vector(ks) + S1
eqs.extend(list(polys))
polys = A2 * vector(ms) + B2 * vector(ks) + S2
eqs.extend(list(polys))
polys = A3 * vector(ms) + B3 * vector(ks) + S3
eqs.extend(list(polys))

seq = Sequence(eqs)
M, b = seq.coefficient_matrix()
ker = M.right_kernel().basis()
if len(ker) == 0:
    print("No solution")
    print("Check the equations")
assert len(ker) == 1, f"{len(ker) = } solutions found, try more samples"
log.info(f"{len(ker) = }")
sol = ker[0]

msg_bits = [int(i) for i in sol[:128]]
key_bits = [int(i) for i in sol[128:256]]
assert sol[256] == 1
recovered_msg = spr.unite(msg_bits)
recoverd_key = spr.unite(key_bits)

io.sendlineafter(b'|  >', b's')
io.sendlineafter(b'|  key>', recoverd_key.hex().encode())
io.sendlineafter(b'|  sec>', recovered_msg.hex().encode())
log.info(io.recvline().decode().strip())
log.info(io.recvline().decode().strip())