
from sage.all import Zmod, matrix, PolynomialRing, Sequence, Ideal, save, load, prod
from output import dets, double_alphas, alpha_sum_rsa, p_encoded, key_encoded, N, encrypted_flag

k, n = 8, 36
Zn = Zmod(N)
Zx = PolynomialRing(Zn, [f"alpha_{i}" for i in range(1, n + 1)])
alphas = Zx.gens()
mod_polys = [alphas[i]**2 - double_alphas[i] for i in range(n)]
G = matrix(Zx, k, n, lambda i, j: (alphas[j]**(i%2) * pow(double_alphas[j], (i//2), N)) % N)

det_polys = []
for i in range(5):
    start_col = i * k - i
    submatrix = G.submatrix(0, start_col, 8, 8)
    det_polys.append(submatrix.det() - dets[i])

# try to use groebner basis to solve the equations
seq = Sequence(det_polys + mod_polys)
# seq += [sum(alphas)**65537 -  alpha_sum_rsa]
I = Ideal(seq)
groebner_basis = I.groebner_basis()
poly_rsa = sum(alphas)
eqs = []
for i, poly in enumerate(groebner_basis):
    print(f"{i = }, {poly = }")
    poly_rsa %= poly
    if i != 0:
        eqs.append(poly)
# solve the equations
print(f"{poly_rsa = }")
res = poly_rsa
for i in range(16):
    poly_rsa = poly_rsa ** 2
    poly_rsa %= mod_polys[-1]
    
poly_rsa = res * poly_rsa - alpha_sum_rsa
poly_rsa %= mod_polys[-1]

eqs.append(poly_rsa)
print(f"{poly_rsa = }")

seq = Sequence(eqs)
mat, monos = seq.coefficients_monomials()

b = -mat[:, -1]
mat = mat[:, :-1]
sol = mat.solve_right(b).list()
print(f"{sol = }")
for i, si in enumerate(sol):
    assert si**2 % N == double_alphas[i]
    
print(f"OK")