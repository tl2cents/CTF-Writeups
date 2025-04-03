import os
import json
import signal
from sage.crypto.boolean_function import BooleanFunction
from itertools import combinations
from tqdm import tqdm
import secrets
from chall import Cipher, LFSR, Cipher256

MASK1 = int(0x6D6AC812F52A212D5A0B9F3117801FD5)
MASK2 = int(0xD736F40E0DED96B603F62CBE394FEF3D)
MASK3 = int(0xA55746EF3955B07595ABC13B9EBEED6B)
MASK4 = int(0xD670201BAC7515352A273372B2A95B23)

ct = "#"
enc_flag = "#"
ct = bytes.fromhex(ct)
enc_flag = bytes.fromhex(enc_flag)

    
class LFSRSymbolic:
    def __init__(self, n, key, mask):
        assert len(key) == n, "Error: the key must be of exactly 128 bits."
        self.state = key
        self.mask = mask
        self.n = n
        self.mask_bits = [int(b) for b in bin(self.mask)[2:].zfill(n)]
        
    def update(self):
        s = sum([self.state[i] * self.mask_bits[i] for i in range(self.n)])
        self.state = [s] + self.state[:-1]
        
    def __call__(self):
        b = self.state[-1]
        self.update()
        return b
    
class CipherSymbolic:
    def __init__(self, key: list):
        self.lfsr1 = LFSRSymbolic(128, key[-128:], MASK1)
        self.lfsr2 = LFSRSymbolic(128, key[-256:-128], MASK2)
        self.lfsr3 = LFSRSymbolic(128, key[-384:-256], MASK3)
        self.lfsr4 = LFSRSymbolic(128, key[-512:-384], MASK4)
        
    def filter_polynomial(self, x0, x1, x2, x3):
        # x0*x1*x2 + x0*x1*x3 + x0*x2*x3 + x1*x3 + x1 + x2
        return x0*x1*x2 + x0*x1*x3 + x0*x2*x3 + x1*x3 + x1 + x2

    def bit(self):
        x,y,z,w = self.get_xyzw()
        return self.filter_polynomial(x, y, z, w)
    
    def get_xyzw(self):
        x = self.lfsr1() + self.lfsr1() + self.lfsr1()
        y = self.lfsr2()
        z = self.lfsr3() + self.lfsr3() + self.lfsr3() + self.lfsr3()
        w = self.lfsr4() + self.lfsr4()
        return x,y,z,w
    
    def get_yz(self):
        y = self.lfsr2()
        z = self.lfsr3() + self.lfsr3() + self.lfsr3() + self.lfsr3()
        return y,z
    
    def stream(self, n):
        return [self.bit() for _ in range(n)]
            
    def xor(self, a, b):
        return [x + y for x, y in zip(a, b)]

    def encrypt(self, pt: bytes):
        pt_bits = [int(b) for b in bin(int.from_bytes(pt, 'big'))[2:].zfill(8 * len(pt))]
        key_stream = self.stream(8 * len(pt))
        return self.xor(pt_bits, key_stream)
    
key = secrets.randbits(512)
key_bits = [int(i) for i in bin(key)[2:].zfill(512)]
br512 = BooleanPolynomialRing(512, [f"x{i}" for i in range(512)])
key_sym = list(br512.gens())

cipher = Cipher(key)
cipher_sym = CipherSymbolic(key_sym)

pt = b"\x00" * 2**12
ct_bits = [int(b) for b in bin(int.from_bytes(ct, 'big'))[2:].zfill(8 * len(ct))]
print(ct_bits.count(1))

# check if yz_list.obj exists
if os.path.exists("./yz_list.obj.sobj"):
    yz_list = load("./yz_list.obj.sobj")
else:
    yz_list = []
    for i in tqdm(range(len(pt) * 8)):
        yz_list.append(cipher_sym.get_yz())
    save(yz_list, "./yz_list.obj")
    
def all_monomials(x1s, x2s):
    d1_monos = x1s[:] + x2s[:]
    d2_monos = []
    for xi in x1s:
        for xj in x2s:
            d2_monos.append(xi*xj)
    return [1] + d1_monos + d2_monos

def fast_coef_mat(monos, polys, br_ring):
    mono_to_index = {}
    for i, mono in enumerate(monos):
        mono_to_index[br_ring(mono)] = i
    # mat = matrix(GF(2), len(polys), len(monos))
    mat = [[0] * len(monos) for i in range(len(polys))]
    for i, f in tqdm(list(enumerate(polys))):
        for mono in f:
            # mat[i,mono_to_index[mono]] = 1
            mat[i][mono_to_index[mono]] = 1
    return mat

eqs = []
for i, bit in enumerate(ct_bits):
    if bit == 1:
        eqs.append(yz_list[i][0]*yz_list[i][1] + yz_list[i][0] + yz_list[i][1] + 1)
        

x2s = key_sym[256:384]
x1s = key_sym[128:256]
monos = all_monomials(list(x1s)[1:], list(x2s)[2:])
print(f"[+] total equations {len(eqs)}")
print(f"[+] total monomials {len(monos)}")
for v1 in [0]:
    for v2 in [0]:
        for v3 in [1]:
            new_eqs = []
            for eq in eqs:
                new_eqs.append(eq.subs({x1s[0]:v1, x2s[0]:v2, x2s[1]: v3}))
            mat = fast_coef_mat(monos, new_eqs, br512)
            mat = matrix(GF(2), mat)
            B = vector(GF(2),[mat[j,0] for j in range(len(eqs))])
            mat = mat[:, 1:]
            print(f"[+] {mat.dimensions() = }, {mat.rank() = }")
            try:
                sol = mat.solve_right(B)
                print(f"[+] solution found for x1[0] = {v1}, x2[0] = {v2}, x2[1] = {v3}")
                print(f"[+] solution: {sol}")
                ker = mat.right_kernel()
                for v in ker.basis():
                    print(f"[+] kernel vector: {v}")
                # break
            except:
                print(f"[+] no solution for x1[0] = {v1}, x2[0] = {v2}, x2[1] = {v3}")
                continue