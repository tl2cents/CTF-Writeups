import numpy as np
import random
from Crypto.Util.number import getPrime

# 模拟生成数据
def nth_bit(x, n):
    return (x >> n) & 1

def popcount(x):
    return bin(x).count('1')

# ground truth
nbit = 248
s = getPrime(nbit)
r = [getPrime(nbit + 1) for _ in range(nbit//2)]
w = [popcount(s ^ r_i) for r_i in r]

# 恢复 s
correlations = []
for bit in range(nbit):
    r_bit_column = [nth_bit(r_i, bit) for r_i in r]  # 第bit位的取值序列
    corr = np.corrcoef(r_bit_column, w)[0, 1]  # 与 popcount 的 Pearson 相关系数
    correlations.append(corr)

print(f"Correlations: {correlations}")
# 根据相关性恢复每一位
recovered_s_bits = [0 if corr > 0 else 1 for corr in correlations]

# 构造 recovered s 整数
recovered_s = 0
for i, b in enumerate(recovered_s_bits):
    recovered_s |= (b << i)

# 计算准确率
diff = s ^ recovered_s
error_bits = popcount(diff)
print(f"Recovered s: {hex(recovered_s)}")
print(f"Actual     s: {hex(s)}")
print(f"Bit errors: {error_bits} / {nbit} ({100*error_bits/nbit:.2f}%)")
