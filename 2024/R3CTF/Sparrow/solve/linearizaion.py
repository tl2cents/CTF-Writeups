from sage.all import GF, matrix, vector
from utils import Sparrow
import os


sec = os.urandom(16)
spr = Sparrow(key=os.urandom(16))
SEED= os.urandom(16)

def encrypt(msg, seed=SEED):
    spr.st(seed)
    ct = spr.encrypt(msg)
    spr.ed()
    return ct

def encrypt0(key, seed=SEED):
    spr.st(seed)
    spr.key = key
    msg = b"\x00" * 16
    ct = spr.encrypt(msg)
    spr.ed()
    return ct

def encrypt1(key, msg, seed=SEED):
    spr.st(seed)
    spr.key = key
    ct = spr.encrypt(msg)
    spr.ed()
    return ct

def getA(seed):
    base = b"\x00" * 16
    c0 = encrypt(base, seed)
    vecs = []
    for i in range(128):
        p = [0] * 128
        p[i] = 1
        p = spr.unite(p)
        row = spr.xor(encrypt(p, seed),c0)
        vecs.append(spr.split(row))
    A = matrix(GF(2), vecs).T
    return A

def getBC(seed):
    base_key0 = b"\x00" * 16
    c00 = encrypt0(base_key0, seed)

    vecs = []
    for i in range(128):
        k = [0] * 128
        k[i] = 1
        k = spr.unite(k)
        row = spr.xor(encrypt0(k, seed),c00)
        vecs.append(spr.split(row))

    B = matrix(GF(2), vecs).T
    C = vector(GF(2), spr.split(c00))
    return B, C

def ABC_linearization(seed):
    A = getA(seed)
    B, C = getBC(seed)
    return A, B, C

def test_impl():
    key = os.urandom(16)
    msg = os.urandom(16)
    seed = os.urandom(16)
    A, B, C = ABC_linearization(seed)
    k_vec = vector(GF(2), spr.split(key))
    m_vec = vector(GF(2), spr.split(msg))

    ct1 = encrypt1(key, msg, seed)
    ct2 = spr.unite(A*m_vec + B*k_vec + C)
    print(f"key = {key.hex()}")
    print(f"msg = {msg.hex()}")
    print(f"ct1 = {ct1.hex()}")
    print(f"ct2 = {ct2.hex()}")
    assert ct1 == ct2
    print("Test passed")
    
if __name__ == "__main__":
    test_impl()

# n = 128
# A = matrix(GF(2), n, n)
# B = matrix(GF(2), n, n)
# base = b"\x00" * 16
# c0 = encrypt(base)
# vecs = []

# for i in range(128):
#     p = [0] * 128
#     p[i] = 1
#     p = spr.unite(p)
#     row = spr.xor(encrypt(p),c0)
#     vecs.append(spr.split(row))

# A = matrix(GF(2), vecs).T
# b = vector(GF(2), spr.split(c0))

# p = os.urandom(16)
# p_vec = vector(GF(2), spr.split(p))
# c = spr.unite([int(bit) for bit in A * p_vec + b])
# s = encrypt(p)

# print(f"p = {p.hex()}")
# print(f"c = {c.hex()}")
# print(f"s = {s.hex()}")

# base_key0 = b"\x00" * 16
# c00 = encrypt0(base_key0)
# print(f"c00 = {c00.hex()}")

# vecs = []
# for i in range(128):
#     k = [0] * 128
#     k[i] = 1
#     k = spr.unite(k)
#     row = spr.xor(encrypt0(k),c00)
#     vecs.append(spr.split(row))

# B = matrix(GF(2), vecs).T
# C = vector(GF(2), spr.split(c00))

# key = os.urandom(16)
# key_vec = vector(GF(2), spr.split(key))
# c = spr.unite([int(bit) for bit in B * key_vec + C])
# s = encrypt0(key)
# print(f"p = {key.hex()}")
# print(f"c = {c.hex()}")
# print(f"s = {s.hex()}")

# key = os.urandom(16)
# msg = os.urandom(16)
# k_vec = vector(GF(2), spr.split(key))
# m_vec = vector(GF(2), spr.split(msg))

# ct1 = encrypt1(key, msg)
# ct2 = spr.unite(A*m_vec + B*k_vec + C)
# print(f"key = {key.hex()}")
# print(f"msg = {msg.hex()}")
# print(f"ct1 = {ct1.hex()}")
# print(f"ct2 = {ct2.hex()}")

