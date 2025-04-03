from sage.all import GF, PolynomialRing, ZZ, matrix, vector
from pwn import remote, process

P = PolynomialRing(GF(2), 'x')
x = P.gen()

def int_to_poly(h):
    return sum(((int(h) >> i) & 1) * x**i for i in range(int(h).bit_length()))

def poly_to_hex(f):
    num = int("".join([str(i) for i in f.list()[::-1]]), 2)
    return num.to_bytes((num.bit_length() + 7) // 8, "big").hex()

f = int_to_poly(0x1f3267f571be716d65f11ecb21b86d2e9)
F = GF(2**128, name='a', modulus=f)
a = F.gen()

def generate_special_message(target_len):
    assert 255 >= target_len >= 16
    prefix = bytes([target_len]) + b"\x00" * target_len
    pre_poly = F(int_to_poly(int.from_bytes(prefix, "big")))
    suffix16 = bytes.fromhex(poly_to_hex(-pre_poly))
    suffix = b"\x00" * (target_len - len(suffix16)) + suffix16
    return bytes([target_len]) +  suffix


def polynomial_to_circulant_matrix(poly, n, mod, F=GF(2)):
    x = poly.variables()[0]
    M = []
    for i in range(n):
        tmp_pol = poly * x**i % mod
        M.append(tmp_pol.list() + [0] * (n - 1 - tmp_pol.degree()))
    return matrix(F, M)

local = False
while True:
    if local:
        io = process(["python3", "vuln.py"], level='info')
    else:
        io = remote("78.46.142.212", "7777", level='info')
    eqs = []
    leaks = []
    for tlen in range(32, 32 + 10):
        io.sendline(b"query " + generate_special_message(tlen)[1:].hex().encode())
        mask_poly = P(F(int_to_poly(1 << (8*tlen + 8))) ** 1000000)
        M = polynomial_to_circulant_matrix(mask_poly, 128, f)
        # M_ = (F(int_to_poly(1 << (8*tlen + 8))) ** 1000000).matrix()
        # assert M == M_.T
        leak = ZZ(int(io.recvline().strip().decode(), 16))
        leak_bits = [(leak >> i) & 1 for i in range(64)]
        assert len(leak_bits) == 64 and leak < 2**64
        eqs += [M.column(i + 64) for i in range(64)]
        leaks += leak_bits
    mat = matrix(GF(2), eqs)
    vec = vector(GF(2), leaks)
    sol = mat.solve_right(vec)
    kpoly = F(sol.list())
    c = [poly_to_hex(i) for i in kpoly.nth_root(1000000, all=True)]
    print(f"submit {c[0]}")
    io.sendline(b"solve " + c[0].encode())
    res = io.recvline()
    print(res.decode().strip())
    if b"hxp" in res:
        break
    io.close()