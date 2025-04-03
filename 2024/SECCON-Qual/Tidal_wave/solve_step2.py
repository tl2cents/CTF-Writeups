
from sage.all import Zmod, matrix, block_matrix, identity_matrix, PolynomialRing, Sequence, ZZ, save, load, prod, vector
from output import dets, double_alphas, alpha_sum_rsa, p_encoded, key_encoded, N, encrypted_flag, alphas


k, n = 8, 36
Zn = Zmod(N)
G = matrix(ZZ, k, n, lambda i, j: pow(alphas[j], i, N))

# p_encoded = pvec*G + make_random_vector(R, n)
G = G.stack(vector(p_encoded))
In = identity_matrix(ZZ, n) * N
Ik = identity_matrix(ZZ, k + 1) * 2**(1000 - 64)
Ik[-1,-1] = 2**1000
M = block_matrix([
   [G, Ik],
   [In, 0]
])

L = M.LLL()
for row in L:
    row_bits = [int(x).bit_length() for x in row]
    if all(900 <= x <= 1000 for x in row_bits[:-(k+1)]):
        print(row[-(k+1):-1])
        p_vec = [abs(ZZ(num/2**(1000 - 64))) for num in row[-(k+1):-1]]
        print(f"{p_vec = }")
        ph = sum(p_vec[i] * pow(2, 64*i) for i in range(k))
        pr = PolynomialRing(Zmod(N), 'x')
        x = pr.gen()
        fx = ph + x 
        pl = fx.small_roots(X=2**64, beta=0.495)
        p = ZZ(pl[0]) + ph
        assert N % p == 0
        q = N // p
        print(f"{p = }")
        print(f"{q = }")
        break