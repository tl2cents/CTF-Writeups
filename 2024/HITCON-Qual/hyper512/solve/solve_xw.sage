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
pt = b"\x00" * 2**12

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
    
class CipherSymbolicHalf:
    def __init__(self, key: list, key2, key3):
        self.lfsr1 = LFSRSymbolic(128, key[-128:], MASK1)
        self.lfsr2 = LFSR(128, key2, MASK2)
        self.lfsr3 = LFSR(128, key3, MASK3)
        self.lfsr4 = LFSRSymbolic(128, key[-256:-128], MASK4)
        
    def filter_polynomial(self, x0, x1, x2, x3):
        # x0*x1*x2 + x0*x1*x3 + x0*x2*x3 + x1*x3 + x1 + x2
        return x0*x1*x2 + x0*x1*x3 + x0*x2*x3 + x1*x3 + x1 + x2

    def bit(self):
        x,y,z,w = self.get_xyzw()
        return self.filter_polynomial(x, y, z, w)
    
    def get_xyzw(self):
        x = self.lfsr1() + self.lfsr1() + self.lfsr1()
        y = self.lfsr2()
        z = (self.lfsr3() + self.lfsr3() + self.lfsr3() + self.lfsr3()) % 2
        w = self.lfsr4() + self.lfsr4()
        return x,y,z,w
    
    def get_yz(self):
        y = self.lfsr2()
        z = self.lfsr3() + self.lfsr3() + self.lfsr3() + self.lfsr3()
        return y,z        
    
    def stream(self, n):
        return [self.bit() for _ in tqdm(range(n))]
            
    def xor(self, a, b):
        return [x + y for x, y in zip(a, b)]

    def encrypt(self, pt: bytes):
        pt_bits = [int(b) for b in bin(int.from_bytes(pt, 'big'))[2:].zfill(8 * len(pt))]
        key_stream = self.stream(8 * len(pt))
        return self.xor(pt_bits, key_stream)
    
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
        

# x1[0] = 0, x2[0] = 0, x2[1] = 1
sol = (1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0)

x1 = [0] + list(sol[:127])
x2 = [0,1] + list(sol[127 : 127 + 126])
key1 = int(''.join(map(str, x1)), 2)
key2 = int(''.join(map(str, x2)), 2)

br256 = BooleanPolynomialRing(256, [f"x{i}" for i in range(256)])
key_sym = list(br256.gens())

cipher_sym = CipherSymbolicHalf(key_sym, key1, key2)
ct_bits = [int(b) for b in bin(int.from_bytes(ct, 'big'))[2:].zfill(8 * len(ct))]
# print(ct_bits.count(1))
out_list = cipher_sym.stream(len(pt) * 8)

eqs = []
for i, bit in tqdm(enumerate(ct_bits)):
    eqs.append(out_list[i] - ct_bits[i])
    
x0s = key_sym[0:128]
x3s = key_sym[128:256]
monos = all_monomials(list(x0s), list(x3s))
print(f"[+] total equations {len(eqs)}")
print(f"[+] total monomials {len(monos)}")

mat = fast_coef_mat(monos, eqs, br256)
mat = matrix(GF(2), mat)
B = vector(GF(2),[mat[j,0] for j in range(len(eqs))])
mat = mat[:, 1:]
sol = mat.solve_right(B)
print(f"[+] solution found {sol}")