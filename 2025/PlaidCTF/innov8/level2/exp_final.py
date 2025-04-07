from sage.all import BooleanPolynomialRing, PolynomialRing, GF, Integer, ZZ, Sequence, vector, save, load
from tqdm import trange, tqdm
import struct
from math import floor
import random
import itertools

class xorshift128:
    def __init__(self, seed0, seed1):
        self.state0 = seed0
        self.state1 = seed1
        self.mask = 2**64 - 1

    def next(self):
        s1 = self.state0
        s0 = self.state1
        self.state0 = s0
        s1 ^= (s1 << 23)
        s1 &= self.mask
        s1 ^= (s1 >> 17)
        s1 &= self.mask
        s1 ^= s0
        s1 ^= (s0 >> 26)
        s1 &= self.mask
        self.state1 = s1
    
    def next_double1(self):
        # used in nodejs
        # https://github.com/nodejs/node/blob/7e43337fdd73f3b4d5b49ca7eb7012b0bf6ed6b4/deps/v8/src/base/utils/random-number-generator.h#L111
        self.next()
        double_bits = (self.state0 >> 12) | 0x3FF0000000000000
        double = struct.unpack('d', struct.pack('<Q', double_bits))[0] - 1
        return double
    
    def next_double2(self):
        # used in v8
        # https://github.com/v8/v8/blob/2f2bcbae2ec348b0b9f293c74f622149fe60c248/src/base/utils/random-number-generator.h#L111
        self.next()
        double = float(self.state0 >> 11) * (1 / (0x1 << 53))
        # double = float(self.state0 & 0x1FFFFFFFFFFFFF) / (0x1 << 53)
        return double
    
boolean_poly_ring = BooleanPolynomialRing(128, 'x')
l_shift = lambda xs, n: xs[n:] + [boolean_poly_ring(0)] * n
r_shift = lambda xs, n: [boolean_poly_ring(0)] * n + xs[:-n]
xor = lambda xs, ys: [x + y for x, y in zip(xs, ys)]

def symbolic_xorshift128(se_state0, se_state1):
    assert len(se_state0) == 64 and len(se_state1) == 64
    se_s1 = se_state0
    se_s0 = se_state1
    se_state0 = se_s0
    se_s1 = xor(se_s1, l_shift(se_s1, 23))
    se_s1 = xor(se_s1, r_shift(se_s1, 17))
    se_s1 = xor(se_s1, se_s0)
    se_s1 = xor(se_s1, r_shift(se_s0, 26))
    se_state1 = se_s1
    return se_state0, se_state1


xs = boolean_poly_ring.gens()
se_state0 = list(xs[:64])
se_state1 = list(xs[64:])
polys = []

for i in range(128):
    se_state0, se_state1 = symbolic_xorshift128(se_state0, se_state1)
    # make the 12th bit of se_state0 be 1
    polys.append(se_state0[-12] + boolean_poly_ring(1))

# due to cache stack of size 64 used in node/v8 (first in, last out), the first 112 polys of outputs should be the following:
all_polys = polys[:64] + polys[64:128][::-1][:112 - 64]
# choose num_eq polys
assert len(all_polys) == 112

# we choose 110 out of 112 polys to be satisfied (meanwhile we force the other two being 0 to avoid duplicate checks)
# actually we have checked the case of 110, 111 and cannot find mismatches >= 104 (but many cases with 103 mismatches)
num_eqs = 110 # the number of 1s constrained 
# the polys constrained to 0
search_space = itertools.combinations(list(range(112)), 112 - num_eqs)
N = 2**52 - 1

for idxs in search_space:
    polys = all_polys[:]
    for idx in idxs:
        # make it constrained to 0
        polys[idx] += boolean_poly_ring(1)

    seq = Sequence(polys)
    mat, mono = seq.coefficients_monomials()
    b = mat[:, -1]
    mat = mat[:, :-1].dense_matrix()
    basis = mat.right_kernel().basis()
    sol0 = mat.solve_right(vector(b.list()))
    sols = []

    bf = 2**len(basis)
    max_mismathes = 0

    for i in trange(bf):
        sol = sol0 + sum([basis[j] * ((i >> j) & 1) for j in range(len(basis))])
        s0 = int(''.join([str(x) for x in sol[:64]]), 2)
        s1 = int(''.join([str(x) for x in sol[64:128]]), 2)
        prng1 = xorshift128(s0, s1)
        prng2 = xorshift128(s0, s1)
        outs1 = []
        outs2 = []
        for j in range(128):
            outs1.append(prng1.next_double1())
            outs2.append(prng2.next_double2())
        checked_outs1 = outs1[:64] + outs1[64:][::-1][:112 - 64]
        checked_outs2 = outs2[:64] + outs2[64:][::-1][:112 - 64]
        mismathes = 0
        for c1, c2 in zip(checked_outs1, checked_outs2):
            N1 = floor(c1 * N)
            N2 = floor(c2 * N)
            if N1 != N2:
                mismathes += 1
        if mismathes > max_mismathes:
            max_mismathes = mismathes
        if mismathes >= 104:
            print(f"{i = }, {s0 = }, {s1 = }, {mismathes = }")
            input("Found a case with 104 mismatches, press enter to continue")
# i = 19188, s0 = 16430066307599907648, s1 = 11328760440928705748, mismathes = 104