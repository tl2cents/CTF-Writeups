import numpy as np
import random

# 模拟数据
s = random.getrandbits(256)
r_list = [random.getrandbits(256) for _ in range(128)]
w_list = [bin(s ^ r).count('1') for r in r_list]  # popcount(s ^ r)

def get_bit(x, i):
    return (x >> i) & 1

def recover_s_bitwise(r_list, w_list):
    bit_scores = []
    for j in range(256):
        rj_bits = np.array([get_bit(r, j) for r in r_list])
        w_array = np.array(w_list)

        # 皮尔逊相关系数（越负说明 s_j = 1 的可能性越大）
        corr = np.corrcoef(rj_bits, w_array)[0, 1]
        bit_scores.append(corr)

    # 解释：
    # 负相关 ⇒ s_j = 1（因为 1 ⊕ r_j 翻转，导致 popcount 值变化方向相反）
    # 正相关 ⇒ s_j = 0（r_j 保持不变，对 popcount 增加起正贡献）
    s_recovered = 0
    for j, score in enumerate(bit_scores):
        if score < 0:
            s_recovered |= (1 << j)
    return s_recovered

s_recovered = recover_s_bitwise(r_list, w_list)

# 评估恢复效果
diff = s ^ s_recovered
error_bits = bin(diff).count('1')
print(f"Recovered s has {error_bits} bit errors out of 256")
