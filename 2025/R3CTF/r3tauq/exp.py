
from sage.all import QuaternionAlgebra, Zmod, matrix, vector, ZZ, is_prime, PolynomialRing
from math import gcd
from sage.all import var

data = [9179146701312781699176828536776206089522408831979885137804817119605132824670673896777591947510882312771183820299882701673215709151977703193903616420702637,
        188706257709485662889897107268939642280152413424908152855562194130538159229344166143895172825675717408926036013540426973122050052311570664470631060866326,
        2682712522093551545327045002884555242296600010649692520986985330242254238488174707977608269114146421801908861117953931511928486194314901772151783668459458,
        3450486865638869884029607240891787866556930082379406388731244160308196118526545881858756124529382085993846169512275853780392762817972043910244447967967496,
        3978613946907291563196945341686358146709099241100401211979238259502207240204268447607153317575767659025152104242438128290935255838611081957683034411586841,
        'fb459084099c44b75f2a1c256b604b187ab4877e78ea2b9fc5320471c319f9063428c72002310df82e1a424425189d0dabebe601031a']

n = data[0]
quater_elem = data[1:5]
ciphertext = data[5]

# def right_mul_matrix(a, b, c, d, u, v):
#     """
#     i**2 = u, j**2 = v, k**2 = -u*v, i*j = -j*i
#     """
#     return [
#         [a, b * u, c * v, d * -u * v],
#         [b, a, d*v, -c*v],
#         [c, -u*d, a, b * u],
#         [d, -c, b, a]
#     ]
# x, y = 1, 2
# qr = QuaternionAlgebra(Zmod(n), 1, 2)
# base = qr.random_element()
# base_mat = matrix(Zmod(n), right_mul_matrix(base[0], base[1], base[2], base[3], x, y))

# r = qr.random_element()
# res1 = base * r
# res2 = base_mat * vector(Zmod(n), list(r))
# print(res1)
# print(res2)
# for i in range(4):
#     assert res1[i] == res2[i], f"Mismatch at index {i}: {res1[i]} != {res2[i]}"
# x, y, p, q, r = var('x y p q r')
# base = [x+y, p+x, q+y, r]
# mat = matrix(right_mul_matrix(*base, x, y))
# for row in mat:
#     print(row)
# y = base
# print(f"Initial base: {y}")
# for i in range(1, 2):
#     y = mat * vector(y)
#     print(f"Iteration {i}: {y}")
    
a, b, c, d = quater_elem
mat = matrix(ZZ, [
    [b, c, d*2**128],
    [n, 0, 0],
    [0, n, 0],
    [0, 0, n*2**128]
    ])

L = mat.LLL()
# base = [x+y, p + x, q + y, r]
# 2**(256 + 128) = 2**384
for row in L:
    row_bits = [int(x).bit_length() for x in row]
    r0 = abs(row[-1]//2**128)
    if is_prime(r0):
        print(f"Found prime: r = {r0}")
        print(f"{row = }")
        d0 = r0
        b0 = abs(row[0])
        c0 = abs(row[1])
        print(f"{b0 = }")
        print(f"{c0 = }")
        print(f"{d0 = }")
        plsb128 = b0 % 2**128
        qlsb128 = c0 % 2**128
        assert plsb128 * qlsb128 % 2**128 == n % 2**128, "Mismatch in LSBs"
        print(f"find partial p leak {plsb128 = }")
        break

pr = PolynomialRing(Zmod(n), "x")
x = pr.gen()
# try lsb leak
for i in range(2**8):
    p_lsb_136 = (plsb128 + i * 2**128)
    f = x * 2**(136) + p_lsb_136
    f = f.monic()
    roots = f.small_roots(X=2**(256 - 136), beta = 0.499, epsilon=0.03)
    if len(roots) >= 1:
        ph = roots[0]
        p = int(ph) * 2**136 + p_lsb_136
        q = n // p
        assert p * q == n, "p * q does not equal n"
        print(f"Found {p = }, {q = }")
        x = b0 - p
        y = c0 - q
        assert is_prime(x >> 128) and is_prime(y >> 128), "x or y is not prime"
        print(f"Found {x = }, {y = }")
        break
    
qr_p = QuaternionAlgebra(Zmod(p), -x, -y)
qr_q = QuaternionAlgebra(Zmod(q), -x, -y)
order_p = qr_p.order()
order_q = qr_q.order()
g = [x+y, p + x, q + y, r0]
g_p = qr_p(g)
g_q = qr_q(g)
gp_order = g_p.multiplicative_order()
gq_order = g_q.multiplicative_order()
print(f"Order of gp in p: {gp_order}")
print(f"Order of gq in q: {gq_order}")