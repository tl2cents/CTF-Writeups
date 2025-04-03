#!/usr/bin/env sage

from sage.all import GF, PolynomialRing
import hashlib
import ecdsa
import random
from utils import *
import os


def separator():
    print("-" * 150)

def gen_kij_poly(ys_inv, us, x, mod):
    def k_ij_poly(i, j):
        coeff1 = (ys_inv[i] - ys_inv[j]) % mod
        coeff2 = (us[i] - us[j]) % mod
        poly = coeff1*x - coeff2
        return poly
    return k_ij_poly


def dpoly(k_ij_poly, n, i, j):
    if i == 0:
        return (k_ij_poly(j+1, j+2))*(k_ij_poly(j+1, j+2)) - (k_ij_poly(j+2, j+3))*(k_ij_poly(j+0, j+1))
    else:
        left = dpoly(k_ij_poly, n, i-1, j)
        for m in range(1, i+2):
            left = left*(k_ij_poly(j+m, j+i+2))
        right = dpoly(k_ij_poly, n, i-1, j+1)
        for m in range(1, i+2):
            right = right*(k_ij_poly(j, j+m))
        return (left - right)


def print_dpoly(n, i, j):
    if i == 0:
        print('(k', j+1, j+2, '*k', j+1, j+2, '-k', j+2,
              j+3, '*k', j+0, j+1, ')', sep='', end='')
    else:
        print('(', sep='', end='')
        print_dpoly(n, i-1, j)
        for m in range(1, i+2):
            print('*k', j+m, j+i+2, sep='', end='')
        print('-', sep='', end='')
        print_dpoly(n, i-1, j+1)
        for m in range(1, i+2):
            print('*k', j, j+m, sep='', end='')
        print(')', sep='', end='')
        
def recover_sk(us, ys, degree, mod):
    assert len(us) == len(ys)
    assert len(us) >= degree + 3
    Z = GF(mod)
    R = PolynomialRing(Z, names=('x',))
    (x,) = R._first_ngens(1)
    
    ys_inv = [int(pow(y, -1, mod)) for y in ys]
    k_ij_poly = gen_kij_poly(ys_inv, us, x, mod)
    poly_target = dpoly(k_ij_poly, degree - 1, degree - 1, 0)
    d_guesses = poly_target.roots(multiplicities=False)
    # separator()
    # print("Roots of the polynomial :")
    # print(d_guesses)
    # separator()
    return d_guesses
    
    
def test_recover():
    MOD = 0x10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000283
    SEED = b2i(os.urandom(128))

    N = 10
    x = randint(1, MOD)
    a = []
    for i in range(N-2):
        a.append(random.randint(1, MOD - 1))
        
    k = []
    k.append(randint(1, MOD))
    for i in range(N-1):
        new_k = 0
        for j in range(N-2):
            new_k += a[j]*(k[i]**j) % MOD
        k.append(new_k % MOD)

    us = [randint(1, MOD) for _ in range(N)]
    ys = []
    ys_inv = []

    for i in range(N):
        y = (x * pow(k[i] + us[i], -1, MOD)) % MOD
        ys.append(y)
        ys_inv.append(int(pow(y, -1, MOD)))
    
    sk = recover_sk(us, ys, N-2, MOD)
    print(f"Check : {x in sk}")

if __name__ == "__main__":
    test_recover()