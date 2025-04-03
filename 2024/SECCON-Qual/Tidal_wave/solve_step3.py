from sage.all import Zmod, matrix, block_matrix, identity_matrix, PolynomialRing, Sequence, ZZ, save, load, prod, vector, codes, GF, crt
from output import dets, double_alphas, alpha_sum_rsa, p_encoded, key_encoded, N, encrypted_flag, alphas

k, n = 8, 36
Zn = Zmod(N)
G = matrix(ZZ, k, n, lambda i, j: pow(alphas[j], i, N))

p = 12565690801374373168209122780100947393207836436607880099543667078825364019537227017599533210660179091620475025517583119411701260337964778535342984769252959
q = 13063745862781294589547896930952928867567164583215526040684813499782622799740291421111907000771263532192148557705806567586876208831387558514840698244078507

Fq = GF(q)
Fp = GF(p)
betas = [1 for i in range(n)]
alphas_p = [Fp(alpha) for alpha in alphas]
alphas_q = [Fq(alpha) for alpha in alphas]
Cp = codes.GeneralizedReedSolomonCode(alphas_p, k, betas)
print(Cp.decoders_available())
dp = Cp.minimum_distance() // 2
# r = c + e
rp = vector(Fp, key_encoded)
print(f"{dp = }")
# d = (n- k + 1) //2
mp = Cp.decode_to_message(rp, decoder_name='Gao')
print(mp)

Cq = codes.GeneralizedReedSolomonCode(alphas_q, k, betas)
print(Cq.decoders_available())
dq = Cq.minimum_distance() // 2
# r = c + e
rq = vector(Fq, key_encoded)
print(f"{dq = }")
# d = (n- k + 1) //2
mq = Cq.decode_to_message(rq, decoder_name='Gao')
print(mq)

key_list = [crt([ZZ(mp[i]), ZZ(mq[i])], [p, q]) for i in range(k)]
keyvec = vector(ZZ, key_list)

import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
key = hashlib.sha256(str(keyvec).encode()).digest()
cipher = AES.new(key, AES.MODE_ECB)
flag = cipher.decrypt(encrypted_flag)
print(f"{flag=}")