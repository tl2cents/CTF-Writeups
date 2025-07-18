from sage.all import EllipticCurve, GF, ZZ
# nc 91.107.252.0 17733
from pwn import remote, context, log, process
from sage.all import PolynomialRing, Zmod, Ideal
from sage.all import solve
from sage.rings.polynomial.msolve import variety
from sage.rings.polynomial import multi_polynomial_ideal


p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a, b = 0, 7
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
x = 0x4F22E22228BD75086D77AE65174C000F132BFD4EF3E28BEF20AC476997D4444F
y = 0x3456B224247A4F73BF187AC25864F8F694C078380E6BDDF51379AC33F18BD829
G = (x, y)


E = EllipticCurve(GF(p), [a, b])
G = E(G[0], G[1])
print("Curve:", E)
print("Generator:", G)
print(G.order())

def sign(sign_id, io: remote):
    io.sendlineafter(b"[Q]uit\n", b"s")
    io.sendlineafter(b"sign_id:\n", str(sign_id).encode())
    res = io.recvline().decode().strip().split("s = ")[1]
    return int(res)

def get_pubkey(io:remote):
    io.sendlineafter(b"[Q]uit\n", b"p")
    res = io.recvline().decode().strip().split("pubkey = ")[1]
    return eval(res)

# r0 = fG.x
# r1 = (f+1)G.x
# r2 = (f-1)G.x
# s * (si + f) = (hm + r*sk)
# s0*f = (hm + r0*sk0)
# s1*f = (hm + r0*sk1)
# (s1 - s0) f = r0(sk1 - sk0)
# (s2 - s0) f = r0(sk2 - sk0)

n_sample = 3
pr = PolynomialRing(GF(n), ["sk0", "sk1", "sk2", "f", "hm", "r0", "r1", "r2"])
sk0, sk1, sk2, f, hm, r0, r1, r2 = pr.gens()
variables = pr.gens()
sks = [sk0, sk1, sk2]
polys = []
for i in range(n_sample):
    # io = remote("91.107.252.0", 17733)
    io = process(["python3", "goliver_ii.py"])
    pk = get_pubkey(io)
    print("Public Key:", pk)
    s0 = sign(n + 0, io)
    s1 = sign(1, io)
    s2 = sign(n - 1, io)
    polys.extend(
        [s0 * f - (hm + r0 * sks[i]),
         s1 * (f + 1) - (hm + r1 * sks[i]),
         s2 * (f - 1) - (hm + r2 * sks[i])]
    )
    io.close()

I = Ideal(polys)
# solu = I.variety(proof=False)
# solu = solve(polys, *variables, algorithm="msolve")
# print(f"Solutions: {solu = }")

basis = I.groebner_basis()
print("Groebner Basis:")
for b in basis:
    print(b)
    
# then solve the system of equations, idk why I.variety() does not work in this case (maybe because there are too two solutions)