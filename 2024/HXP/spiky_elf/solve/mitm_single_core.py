from sage.all import ZZ, binomial
from itertools import combinations
from tqdm import tqdm

n = 0x639d87bf6a02786607d67741ebde10aa39746dc8ed22b191ff2fefe9c210b3ee2ce68b185dc7f8069e78441bdec1d33e2b342c226b5cde8a49f567ac11a3bcb7ff88eeededdd0d50eb981635920d2380a6b878d327b261821355d65b2ef9f807035a70c77252d09787c2b3dfafdfa4f5c6b39a1c66c5b39fe9d1ee4b36d86d5
e = 0x10001
flag = 0x40208a7900b1575431a49690030e4eb8be6269edcd3c7b2d97ae94a6eb744e9c622d81b95ea45b23ee6e0d773e3dd48adc6bb2c7c6423d8fd52eddcc6c0710f607590d5fc57a45883a36ad0d851f84d4bee86ffaf65bc1773f97430080926550dce3666051befa87bacc01d44dd09baa6ae93a85cedde5933f7cbbe2cb56cdd
d = 0x1a54893799cd9805600cfaee1c8a408813525db268fbc29e7f2a81eb47b64d2dd20dc8be52b6332e375f92a120957042a92a4bd4f5e13ef14e9b398bec330602dc9dbbb63cf3dfe6d33bf95d08306a894b052e005a57cc41673fe866f4f8b2ffb0aa26fc4c51a8f5135e40df2107e0259ddf4c1d9c1eb41b1f702b135c941
d_real_msb = 4514088967547488951649479902515202812774123491743896551436762406242971627370506765191178449599877062466101307468179199203541042200279058948411943214043223303232663400817011215091948406144006044666676764127646300202138127044251756808659462372075867443194976482310771190867332273026020227834408536297872091

err_pos = [46, 102, 235, 252, 280, 394, 412, 434, 485]
unknown_nbit = 1024 - 520
d_msb = (d_real_msb >> unknown_nbit) << unknown_nbit
d_lsb = d & ((1 << unknown_nbit) - 1)

enc2 = pow(2, e, n)
inv_enc2 = pow(enc2, -1, n)
# enc2^(d_msb) * enc2^(d_l) = 2
# c:= enc2^(d_l) = 2 * pow(enc2, -d_msb, n) % n
# d_l := a*2**252 + b 
# c = enc2 ^ (a*2**252 + b) = (enc2^(2^252))^a * enc2 ^ b
# c *  * (enc2^-1) ^ b) = (enc2^(2^252))^a

c  = 2 * pow(enc2, - d_msb, n) % n
X = pow(enc2, 2**252, n)

enc2_basis = [pow(enc2, 2**i, n) for i in range(unknown_nbit // 2)]
enc2_inv_basis = [pow(inv_enc2, 2**i, n) for i in range(unknown_nbit // 2)]
X_basis = [pow(X, 2**i, n) for i in range(unknown_nbit // 2)]
X_inv_basis = [pow(pow(X, -1, n), 2**i, n) for i in range(unknown_nbit // 2)]

d_l_msb = d_lsb >> (unknown_nbit // 2)
d_l_lsb = d_lsb & ((1 << (unknown_nbit // 2)) - 1)
d_l_lsb_bits = [d_l_lsb >> i & 1 for i in range(unknown_nbit // 2)]
d_l_msb_bits = [d_l_msb >> i & 1 for i in range(unknown_nbit // 2)]

B_initial = pow(inv_enc2, d_l_lsb, n) * c % n
A_initial = pow(X, d_l_msb, n)

# build table
search_err1 = 3
search_err2 = 4
pos_size = 252 # unknown_nbit // 2
bf_space = combinations(range(pos_size), search_err1) 
total_size = binomial(pos_size, search_err1)
table = {}

for pos1 in tqdm(bf_space, total=total_size):
    lhs = A_initial
    for idx in pos1:
        if d_l_msb_bits[idx] == 1:
            lhs = lhs * X_inv_basis[idx] % n
        else:
            lhs = lhs * X_basis[idx] % n
    table[lhs] = pos1

bf_space = combinations(range(pos_size), search_err2) 
total_size = binomial(pos_size, search_err2)

for pos2 in tqdm(bf_space, total=total_size):
    rhs = B_initial
    for idx in pos2:
        if d_l_lsb_bits[idx] == 1:
            rhs = rhs * enc2_basis[idx] % n
        else:
            rhs = rhs * enc2_inv_basis[idx] % n
    if rhs in table:
        pos1 = table[rhs]
        print(f"{pos1 = }")
        print(f"{pos2 = }")
        break