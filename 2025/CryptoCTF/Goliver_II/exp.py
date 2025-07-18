from sage.all import EllipticCurve, GF, ZZ
# nc 91.107.252.0 17733
from pwn import remote, context, log, process
from sage.all import PolynomialRing, Zmod, Ideal
from hashlib import sha256
from Crypto.Util.number import long_to_bytes

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

def get_clean_eqs():
    # r0 = fG.x
    # r1 = (f+1)G.x
    # r2 = (f-1)G.x
    # s * (si + f) = (hm + r*sk)
    # s0*f = (hm + r0*sk0)
    # s1*f = (hm + r0*sk1)
    # (s1 - s0) f = r0(sk1 - sk0)
    # (s2 - s0) f = r0(sk2 - sk0)
    # 未知量 r0, r1, r2, sk0, sk1, sk2， f, hm
    n_sample = 4
    pr = PolynomialRing(GF(n), ["sk0", "sk1", "sk2", "sk3", "f", "hm", "r0", "r1", "r2"])
    sk0, sk1, sk2, sk3, f, hm, r0, r1, r2 = pr.gens()
    sks = [sk0, sk1, sk2, sk3]
    polys = []
    for i in range(n_sample):
        io = remote("91.107.252.0", 17733)
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
    basis = I.groebner_basis()
    print(f"{basis = }")


io = remote("91.107.252.0", 17733)
pk = get_pubkey(io)
print("Public Key:", pk)
s0 = sign(n + 0, io)
# s0 * f = (hm + r0*sk0)
flag_half = b'CCTF{!_4m_A_9!an7_am0nG'
hm = int.from_bytes(sha256(flag_half).digest(), "big")
k = n + int.from_bytes(flag_half, "big")
r0 = (k * G)[0]
sk = int((s0 * k - hm) * pow(int(r0), -1, n) % n)

io.sendlineafter(b"[Q]uit\n", b"g")
io.sendlineafter(b"private key: \n", str(sk).encode())
io.interactive()