from sage.modules.free_module_integer import IntegerLattice
import numpy as np
from Crypto.Cipher import AES
from hashlib import sha256
from random import SystemRandom
import sys
from sage.all import GF, PolynomialRing, Zmod, matrix, QQ, ZZ, block_matrix, zero_matrix, vector
from copy import copy


# https://github.com/rkm0959/Inequality_Solving_with_CVP
def Babai_CVP(mat, target):
    M = mat.LLL()
    G = M.gram_schmidt()[0]
    diff = target
    for i in reversed(range(G.nrows())):
        diff -= M[i] * ((diff * G[i]) / (G[i] * G[i])).round()
    return target - diff


def solve(M, lbounds, ubounds, weight=None):
    mat, lb, ub = copy(M), copy(lbounds), copy(ubounds)
    num_var = mat.nrows()
    num_ineq = mat.ncols()

    max_element = 0
    for i in range(num_var):
        for j in range(num_ineq):
            max_element = max(max_element, abs(mat[i, j]))

    if weight == None:
        weight = num_ineq * max_element

    # sanity checker
    if len(lb) != num_ineq:
        print("Fail: len(lb) != num_ineq")
        return

    if len(ub) != num_ineq:
        print("Fail: len(ub) != num_ineq")
        return

    for i in range(num_ineq):
        if lb[i] > ub[i]:
            print("Fail: lb[i] > ub[i] at index", i)
            return

    # heuristic for number of solutions
    DET = 0

    if num_var == num_ineq:
        DET = abs(mat.det())
        num_sol = 1
        for i in range(num_ineq):
            num_sol *= (ub[i] - lb[i])
        if DET == 0:
            print("Zero Determinant")
        else:
            num_sol //= DET
            # + 1 added in for the sake of not making it zero...
            print("Expected Number of Solutions : ", num_sol + 1)

    # scaling process begins
    max_diff = max([ub[i] - lb[i] for i in range(num_ineq)])
    applied_weights = []

    for i in range(num_ineq):
        ineq_weight = weight if lb[i] == ub[i] else max_diff // (ub[i] - lb[i])
        applied_weights.append(ineq_weight)
        for j in range(num_var):
            mat[j, i] *= ineq_weight
        lb[i] *= ineq_weight
        ub[i] *= ineq_weight

    # Solve CVP
    target = vector([(lb[i] + ub[i]) // 2 for i in range(num_ineq)])
    result = Babai_CVP(mat, target)

    for i in range(num_ineq):
        if (lb[i] <= result[i] <= ub[i]) == False:
            print("Fail : inequality does not hold after solving")
            break

    # recover x
    fin = None

    if DET != 0:
        mat = mat.transpose()
        fin = mat.solve_right(result)

    # recover your result
    return result, applied_weights, fin

def recover(ct: bytes, poly: list, t: int):
    poly = np.array(poly)
    f = lambda x: int(np.polyval(poly, x) % p)
    ks = [f(x) for x in range(t)]
    key = sha256(repr(ks).encode()).digest()
    cipher = AES.new(key, AES.MODE_CTR, nonce=ct[:8])
    return cipher.decrypt(ct[8:])

n = 48
t = 24
ct = b'\xa4\x17#U\x9d[2Sg\xb9\x99B\xe8p\x8b\x0b\x14\xf0\x04\xde\x88\xb9\xf6\xceM/\xea\xbf\x15\x99\xd7\xaf\x8c\xa1t\xa4%~c%\xd2\x1dNl\xbaF\x92\xae(\xca\xf8$+\xebd;^\xb8\xb3`\xf0\xed\x8a\x9do'
shares = [(18565, 15475), (4050, 20443), (7053, 28908), (46320, 10236), (12604, 25691), (34890, 55908), (20396, 47463), (16840, 10456), (29951, 4074), (43326, 55872), (15136, 21784), (42111, 55432), (32311, 30534), (28577, 18600), (35425, 34192), (38838, 6433), (40776, 31807), (29826, 36077), (39458, 24811), (32328, 28111), (38079, 11245), (36995, 27991), (26261, 59236), (42176, 20756),
          (11071, 50313), (31327, 7724), (14212, 45911), (22884, 22299), (18878, 50951), (23510, 24001), (61462, 57669), (46222, 34450), (29, 5836), (50316, 15548), (24558, 15321), (9571, 19074), (11188, 44856), (36698, 40296), (6125, 33078), (42862, 49258), (22439, 56745), (37914, 56174), (53950, 16717), (17342, 59992), (48528, 39826), (59647, 57687), (30823, 36629), (65052, 7106)]


p = 65537
mod = 2**64
pinv = int(pow(p, -1, mod))
pinv_div_2 = ZZ(pinv) / ZZ(2)
n_point = len(shares)
degree = t
mat11 = matrix(ZZ, degree + 1, n_point)
bound = mod // p


for i in range(n_point):
    x, y = shares[i]
    for j in range(degree):
        mat11[j, i] = int(pow(x, j, mod) * pinv % mod)
    mat11[degree, i] = int(-(y) * pinv % mod)

mat12 = matrix.identity(ZZ, degree + 1)
mat13 = zero_matrix(ZZ, degree + 1, n_point)

mat21 = matrix.identity(ZZ, n_point) * mod
mat22 = zero_matrix(ZZ, n_point, degree + 1)
mat23 = zero_matrix(ZZ, n_point, n_point)

mat31 = matrix.identity(ZZ, n_point) * -pinv
mat32 = zero_matrix(ZZ, n_point, degree + 1)
mat33 = matrix.identity(ZZ, n_point, n_point)


M = block_matrix(ZZ, [[mat11, mat12, mat13],
                      [mat21, mat22, mat23],
                      [mat31, mat32, mat33]])

mod = 2**64
p = 65537
bound = mod // p
lb = [0] * n_point + [0] * degree + [1] + [0] * n_point
ub = [bound] * n_point + [p] * degree + [1] + [1] * n_point
# solve CVP
res, weights, fin = solve(M, lb, ub)
print(res)

rcoeffs =  [res[i]//weights[i] for i in range(n_point, n_point + degree)]
print(rcoeffs)
poly = rcoeffs[::-1]
print(recover(ct, poly, t))